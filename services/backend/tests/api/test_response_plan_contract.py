from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta
from time import monotonic, sleep
from types import SimpleNamespace

import pytest
from evidencesoc.api import sse
from evidencesoc.api.storage import ApiStore
from evidencesoc.api.tables import ApiInvestigationTable
from evidencesoc.persistence.tables import ResponsePlanTable
from sqlalchemy import func, select
from test_investigation_flow import (
    create_demo_session,
    create_investigation,
    decision_headers,
    wait_status,
)

pytest_plugins = ("test_investigation_flow",)


def test_generated_response_plan_exposes_persisted_review_details(api_environment):
    client, store, _workflow, _sessions, _app = api_environment
    created = create_investigation(client)
    incident = wait_status(client, created["incident_id"], "awaiting_approval")
    plan_id = incident["response_plan"]["response_plan_id"]

    detail_response = client.get(f"/api/v1/response-plans/{plan_id}")
    assert detail_response.status_code == 200, detail_response.text
    detail = detail_response.json()
    persisted = store.get_plan(plan_id)
    listed = client.get("/api/v1/response-plans").json()["items"][0]
    for view in (detail, listed, incident["response_plan"], persisted):
        assert view["execution_mode"] == "simulation"
        assert view["risk_level"] == "medium"
        assert "source IP" in view["risk_reason"]
        assert view["affected_assets"] == ["203.0.113.42"]
        assert "no real traffic changes" in view["business_impact"]
        assert datetime.fromisoformat(view["expires_at"]) > datetime.now(UTC)
        assert view["rollback_steps"][0]["step_id"].startswith("RB-")
        assert view["rollback_steps"][0]["target"] == "203.0.113.42"
        assert view["validation_checks"][0]["check_id"].startswith("VC-")
        assert view["validation_checks"][0]["query"]["filters"] == {
            "source_ip": "203.0.113.42"
        }
        assert view["validation_checks"][0]["evidence_ids"] == view["evidence_ids"]
        assert view["actions"][0]["evidence_ids"] == view["evidence_ids"]
    assert detail["simulation_execution"] is None
    assert incident["simulation_execution"] is None


def test_completed_simulation_read_model_is_persisted_and_version_bound(
    api_environment,
):
    client, store, _workflow, _sessions, _app = api_environment
    created = create_investigation(client)
    awaiting = wait_status(client, created["incident_id"], "awaiting_approval")
    plan_id = awaiting["response_plan"]["response_plan_id"]
    before = client.get(f"/api/v1/response-plans/{plan_id}").json()
    assert before["simulation_execution"] is None

    create_demo_session(client)
    accepted = client.post(
        f"/api/v1/response-plans/{plan_id}/approve",
        json={
            "reason": "Reviewed simulated response",
            "plan_version": before["plan_version"],
        },
        headers=decision_headers("simulation-execution-" + plan_id),
    )
    assert accepted.status_code == 202, accepted.text
    deadline = monotonic() + 5
    while monotonic() < deadline:
        incident = client.get(f"/api/v1/incidents/{created['incident_id']}").json()
        if incident["status"] in {"completed", "manual_review", "failed"}:
            break
        sleep(0.01)
    else:
        assert False, "simulation did not finish"
    detail = client.get(f"/api/v1/response-plans/{plan_id}").json()
    execution = detail["simulation_execution"]
    assert execution["response_plan_id"] == plan_id
    assert execution["plan_version"] == before["plan_version"]
    assert execution["status"] == "completed"
    assert execution["started_at"] <= execution["finished_at"]
    assert [item["action_id"] for item in execution["action_results"]] == [
        item["action_id"] for item in detail["actions"]
    ]
    assert all(item["outcome"] == "success" for item in execution["action_results"])
    assert incident["simulation_execution"] == execution
    assert store.get_response_plan_detail(plan_id)["simulation_execution"] == execution


def test_expired_response_plan_disables_approval_and_returns_410(api_environment):
    client, _store, _workflow, sessions, _app = api_environment
    created = create_investigation(client)
    awaiting = wait_status(client, created["incident_id"], "awaiting_approval")
    plan_id = awaiting["response_plan"]["response_plan_id"]
    with sessions.begin() as session:
        plan = session.get(ResponsePlanTable, plan_id)
        plan.expires_at = plan.created_at + timedelta(milliseconds=1)
    create_demo_session(client)
    detail = client.get(f"/api/v1/response-plans/{plan_id}").json()
    assert detail["available_actions"] == []
    response = client.post(
        f"/api/v1/response-plans/{plan_id}/approve",
        json={"reason": "Reviewed", "plan_version": detail["plan_version"]},
        headers=decision_headers("expired-plan"),
    )
    assert response.status_code == 410, response.text
    assert response.json()["error"]["code"] == "PLAN_EXPIRED"
    assert (
        client.get(f"/api/v1/response-plans/{plan_id}").json()["decision_state"]
        == "pending"
    )


@pytest.mark.parametrize("recover_pending", [False, True])
def test_expired_plan_can_generate_a_fresh_reviewable_plan_in_same_investigation(
    api_environment, monkeypatch, recover_pending
):
    client, store, _workflow, sessions, app = api_environment
    created = create_investigation(client)
    awaiting = wait_status(client, created["incident_id"], "awaiting_approval")
    old_id = awaiting["response_plan"]["response_plan_id"]
    old_cursor = store.get_investigation(created["investigation_id"])["last_event_id"]
    with sessions.begin() as session:
        old_plan = session.get(ResponsePlanTable, old_id)
        old_plan.expires_at = old_plan.created_at + timedelta(milliseconds=1)
    old_detail = client.get(f"/api/v1/response-plans/{old_id}").json()
    create_demo_session(client)

    with monkeypatch.context() as paused:
        if recover_pending:
            # Leave the accepted command durable before a worker starts it.
            paused.setattr(app.state.runner, "schedule", lambda _metadata: None)
        accepted = client.post(
            f"/api/v1/response-plans/{old_id}/renew",
            json={"plan_version": old_detail["plan_version"]},
            headers=decision_headers("renew-" + old_id),
        )
        if recover_pending:
            restored = ApiStore(sessions)
            pending = restored.get_investigation(created["investigation_id"])
            assert pending["state"]["pending_renewal"]["response_plan_id"] == old_id
            replay_pending = client.post(
                f"/api/v1/response-plans/{old_id}/renew",
                json={"plan_version": old_detail["plan_version"]},
                headers=decision_headers("renew-" + old_id),
            )
            assert replay_pending.status_code == 200, replay_pending.text
    assert accepted.status_code == 202, accepted.text
    assert accepted.json()["investigation_id"] == created["investigation_id"]
    if recover_pending:
        app.state.runner.store = restored
        client.portal.call(app.state.runner.recover)

    import time

    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        incident = client.get(f"/api/v1/incidents/{created['incident_id']}").json()
        if (
            incident.get("response_plan", {}).get("response_plan_id") != old_id
            and incident["status"] == "awaiting_approval"
        ):
            break
        time.sleep(0.01)
    else:
        assert False, "renewal did not create a new plan"

    new_id = incident["response_plan"]["response_plan_id"]
    new_detail = client.get(f"/api/v1/response-plans/{new_id}").json()
    previous = client.get(f"/api/v1/response-plans/{old_id}").json()
    assert incident["status"] == "awaiting_approval"
    assert new_detail["is_current"] is True
    assert new_detail["is_expired"] is False
    assert new_detail["available_actions"] == ["approve", "reject"]
    assert new_detail["approval"] is None
    assert new_detail["simulation"] == []
    assert new_detail["evidence_ids"] == previous["evidence_ids"]
    assert previous["plan_version"] == old_detail["plan_version"]
    assert previous["is_current"] is False
    assert previous["available_actions"] == []
    assert previous["is_expired"] is True
    persisted = store.list_events(created["investigation_id"], old_cursor)
    renewal_events = [
        item
        for item in persisted
        if item["event"] in {"plan.renewal_requested", "plan.renewed"}
    ]
    assert [item["event"] for item in renewal_events] == [
        "plan.renewal_requested",
        "plan.renewed",
    ]

    async def replay_until_new_approval():
        async def is_disconnected():
            return False

        request = SimpleNamespace(
            app=app, state=SimpleNamespace(), is_disconnected=is_disconnected
        )
        response = await sse.stream(
            created["investigation_id"], request, last_event_id=str(old_cursor)
        )
        frames = []
        try:
            async with asyncio.timeout(3):
                async for frame in response.body_iterator:
                    frames.append(frame)
                    if frame["event"] in {"stream.reset", "approval.required"}:
                        break
        finally:
            await response.body_iterator.aclose()
        return frames

    frames = client.portal.call(replay_until_new_approval)
    assert not any(frame["event"] == "stream.reset" for frame in frames)
    assert [int(frame["id"]) for frame in frames] == list(
        range(old_cursor + 1, old_cursor + len(frames) + 1)
    )
    by_id = {int(frame["id"]): frame for frame in frames}
    for item in renewal_events:
        frame = by_id[item["id"]]
        assert frame["event"] == "status"
        assert json.loads(frame["data"]) == {**item["data"], "status": "reconstructing"}
    assert frames[-1]["event"] == "approval.required"
    assert json.loads(frames[-1]["data"])["response_plan"]["response_plan_id"] == new_id
    assert (
        ApiStore(sessions).list_events(created["investigation_id"], old_cursor)
        == persisted
    )

    expired_approval = client.post(
        f"/api/v1/response-plans/{old_id}/approve",
        json={
            "reason": "Old plan must stay expired",
            "plan_version": old_detail["plan_version"],
        },
        headers=decision_headers("old-approve-" + old_id),
    )
    assert expired_approval.status_code == 410, expired_approval.text
    assert expired_approval.json()["error"]["code"] == "PLAN_EXPIRED"
    replay = client.post(
        f"/api/v1/response-plans/{old_id}/renew",
        json={"plan_version": old_detail["plan_version"]},
        headers=decision_headers("renew-" + old_id),
    )
    assert replay.status_code == 200, replay.text
    assert replay.json()["investigation_id"] == created["investigation_id"]
    assert store.list_events(created["investigation_id"], old_cursor) == persisted
    with sessions() as session:
        assert (
            session.scalar(select(func.count()).select_from(ApiInvestigationTable)) == 1
        )
        assert session.scalar(select(func.count()).select_from(ResponsePlanTable)) == 2


def test_legacy_response_plan_can_be_read_and_rejected_but_cannot_be_approved(
    api_environment,
):
    client, _store, _workflow, sessions, _app = api_environment
    created = create_investigation(client)
    awaiting = wait_status(client, created["incident_id"], "awaiting_approval")
    plan_id = awaiting["response_plan"]["response_plan_id"]
    with sessions.begin() as session:
        plan = session.get(ResponsePlanTable, plan_id)
        plan.risk_level = None
        plan.risk_reason = None
        plan.affected_assets = []
        plan.business_impact = None
        plan.expires_at = None
        plan.rollback_steps = []
        plan.validation_checks = []

    path = f"/api/v1/response-plans/{plan_id}"
    detail_response = client.get(path)
    assert detail_response.status_code == 200, detail_response.text
    detail = detail_response.json()
    assert detail["actions"]
    assert detail["risk_level"] is None
    assert detail["available_actions"] == ["reject"]
    assert (
        client.get("/api/v1/response-plans").json()["items"][0]["response_plan_id"]
        == plan_id
    )
    assert client.get(f"/api/v1/investigations/{created['investigation_id']}").json()[
        "available_actions"
    ] == ["reject"]

    approved = client.post(
        f"{path}/approve",
        json={"reason": "Reviewed", "plan_version": detail["plan_version"]},
        headers=decision_headers("legacy-plan-approve"),
    )
    assert approved.status_code == 409, approved.text
    assert approved.json()["error"]["code"] == "CONFLICT"
    assert client.get(path).json()["decision_state"] == "pending"

    rejected = client.post(
        f"{path}/reject",
        json={
            "reason": "Legacy plan lacks review details",
            "plan_version": detail["plan_version"],
        },
        headers=decision_headers("legacy-plan-reject"),
    )
    assert rejected.status_code == 202, rejected.text
    assert (
        wait_status(client, created["incident_id"], "rejected")["status"] == "rejected"
    )


def test_review_detail_revision_invalidates_an_old_approval_version(api_environment):
    client, _store, _workflow, sessions, _app = api_environment
    created = create_investigation(client)
    awaiting = wait_status(client, created["incident_id"], "awaiting_approval")
    plan_id = awaiting["response_plan"]["response_plan_id"]
    path = f"/api/v1/response-plans/{plan_id}"
    before = client.get(path).json()
    with sessions.begin() as session:
        session.get(ResponsePlanTable, plan_id).risk_reason += " Review changed."
    after = client.get(path).json()
    assert after["risk_reason"] != before["risk_reason"]
    assert after["plan_version"] != before["plan_version"]

    create_demo_session(client)
    stale = client.post(
        f"{path}/approve",
        json={"reason": "Reviewed", "plan_version": before["plan_version"]},
        headers=decision_headers("stale-risk-version"),
    )
    assert stale.status_code == 409, stale.text
    assert stale.json()["error"]["code"] == "CONFLICT"
