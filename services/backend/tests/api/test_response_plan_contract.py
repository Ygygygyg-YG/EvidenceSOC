from __future__ import annotations

from datetime import UTC, datetime, timedelta
from time import monotonic, sleep

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


def test_expired_plan_can_generate_a_fresh_reviewable_plan_in_same_investigation(
    api_environment,
):
    client, _store, _workflow, sessions, _app = api_environment
    created = create_investigation(client)
    awaiting = wait_status(client, created["incident_id"], "awaiting_approval")
    old_id = awaiting["response_plan"]["response_plan_id"]
    with sessions.begin() as session:
        old_plan = session.get(ResponsePlanTable, old_id)
        old_plan.expires_at = old_plan.created_at + timedelta(milliseconds=1)
    old_detail = client.get(f"/api/v1/response-plans/{old_id}").json()
    create_demo_session(client)

    accepted = client.post(
        f"/api/v1/response-plans/{old_id}/renew",
        json={"plan_version": old_detail["plan_version"]},
        headers=decision_headers("renew-" + old_id),
    )
    assert accepted.status_code == 202, accepted.text
    assert accepted.json()["investigation_id"] == created["investigation_id"]

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
    replay = client.post(
        f"/api/v1/response-plans/{old_id}/renew",
        json={"plan_version": old_detail["plan_version"]},
        headers=decision_headers("renew-" + old_id),
    )
    assert replay.status_code == 200, replay.text
    assert replay.json()["investigation_id"] == created["investigation_id"]
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
