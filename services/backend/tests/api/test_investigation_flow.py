from __future__ import annotations

import asyncio
import hashlib
import json
import re
import time
from datetime import UTC, datetime, timedelta, timezone
from urllib.parse import quote

import pytest
from evidencesoc.agents.graph import InvestigationWorkflow
from evidencesoc.agents.services import PostgresWorkflowServices
from evidencesoc.config import Settings
from evidencesoc.domain.models import EvidenceItem
from evidencesoc.ids import new_evidence_id
from evidencesoc.ingestion.normalize import calculate_content_sha256
from evidencesoc.persistence.tables import (
    AgentRunTable,
    AlertTable,
    ApprovalTable,
    AttackStepTable,
    EvaluationRunTable,
    EvidenceItemTable,
    IncidentTable,
    ResponsePlanTable,
    SecurityEventTable,
    ValidationResultTable,
)
from fastapi.testclient import TestClient
from langgraph.checkpoint.memory import InMemorySaver
from sqlalchemy import JSON, CheckConstraint, MetaData, create_engine, event, select
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import sessionmaker

NOW = datetime(2026, 9, 21, 10, 20, 17, tzinfo=UTC)
PAYLOAD = {
    "title": "SQL injection",
    "severity": "high",
    "event_ids": ["SE-api"],
    "created_at": NOW.isoformat(),
}
FRONTEND_ORIGIN = "http://127.0.0.1:3000"


@pytest.fixture
def api_environment(tmp_path):
    from evidencesoc.api.storage import ApiStore
    from evidencesoc.api.tables import ApiBase
    from evidencesoc.main import create_app

    engine = create_engine(
        f"sqlite:///{tmp_path / 'api.db'}", connect_args={"check_same_thread": False}
    )

    @event.listens_for(engine, "connect")
    def foreign_keys(connection, _record):
        connection.execute("PRAGMA foreign_keys=ON")

    metadata = MetaData()
    for model in (
        SecurityEventTable,
        AlertTable,
        IncidentTable,
        EvidenceItemTable,
        AttackStepTable,
        AgentRunTable,
        ResponsePlanTable,
        ApprovalTable,
        ValidationResultTable,
        EvaluationRunTable,
    ):
        table = model.__table__.to_metadata(metadata)
        for column in table.columns:
            if isinstance(column.type, JSONB):
                column.type = JSON()
        for constraint in list(table.constraints):
            if isinstance(constraint, CheckConstraint):
                table.constraints.remove(constraint)
    metadata.create_all(engine)
    ApiBase.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine, expire_on_commit=False)
    raw = {
        "source_ip": "203.0.113.42",
        "host": "shop.example.test",
        "service": "checkout-api",
        "message": "UNION SELECT password FROM users",
    }
    with sessions() as session, session.begin():
        session.add(
            SecurityEventTable(
                event_id="SE-api",
                source="nginx",
                deduplication_key="id:api",
                observed_at=NOW,
                ingested_at=NOW,
                severity="high",
                event_type="web.request",
                raw=raw,
                content_sha256=calculate_content_sha256(raw),
                index_status="indexed",
            )
        )

    settings = Settings(
        _env_file=None,
        llm_mode="fixture",
        demo_session_enabled=True,
        frontend_origin=FRONTEND_ORIGIN,
    )

    class FixtureServices(PostgresWorkflowServices):
        async def collect(self, state, run_id):
            await asyncio.sleep(0.02)
            evidence = EvidenceItem(
                evidence_id=new_evidence_id(),
                event_id="SE-api",
                source="nginx",
                observed_at=NOW,
                query={"event_id": "SE-api"},
                summary="Verified SQL pattern",
                content_sha256=calculate_content_sha256(raw),
            )
            with sessions() as session, session.begin():
                session.add(
                    EvidenceItemTable(
                        **evidence.model_dump(), incident_id=state["incident_id"]
                    )
                )
            return {
                "evidence": [{**evidence.model_dump(mode="json"), "raw": raw}],
                "knowledge": [
                    {
                        "knowledge_chunk_id": "KC-api",
                        "technique_id": "T1190",
                        "source_uri": "https://attack.mitre.org/techniques/T1190/",
                    }
                ],
            }

        async def verify(self, state, run_id):
            plan = state["response_plan"]
            return {
                "evidence": state["evidence"],
                "executed_checks": [
                    {
                        "check_id": plan["validation_checks"][index]["check_id"],
                        "condition": {
                            "time_from": (NOW - timedelta(minutes=5)).isoformat(),
                            "time_to": (NOW + timedelta(minutes=5)).isoformat(),
                            "filters": action["verification_query"]["filters"],
                            "limit": action["verification_query"].get("limit", 100),
                        },
                        "evidence_ids": [
                            item["evidence_id"] for item in state["evidence"]
                        ],
                    }
                    for index, action in enumerate(plan["actions"])
                ],
            }

    store = ApiStore(sessions)
    services = FixtureServices(settings, session_factory=sessions)
    workflow = InvestigationWorkflow(
        services=services, settings=settings, checkpointer=InMemorySaver()
    )
    application = create_app(settings=settings, store=store, workflow=workflow)
    try:
        with TestClient(
            application,
            raise_server_exceptions=False,
            client=("127.0.0.1", 50000),
        ) as client:
            yield client, store, workflow, sessions, application
    finally:
        services.close()
        engine.dispose()


def wait_status(client, incident_id, status):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        response = client.get(f"/api/v1/incidents/{incident_id}")
        assert response.status_code == 200, response.text
        data = response.json()
        if data["status"] == status:
            return data
        time.sleep(0.01)
    pytest.fail(f"investigation did not reach {status}: {data}")


def create_investigation(client):
    alert = client.post("/api/v1/alerts", json=PAYLOAD)
    assert alert.status_code == 201, alert.text
    create_demo_session(client)
    response = client.post(
        "/api/v1/investigations",
        json={"alert_id": alert.json()["alert_id"], "mode": "rules"},
        headers={
            "Idempotency-Key": "start-" + alert.json()["alert_id"],
            "Origin": FRONTEND_ORIGIN,
        },
    )
    assert response.status_code == 202, response.text
    return response.json()


def create_demo_session(client):
    response = client.post("/api/v1/session/demo", headers={"Origin": FRONTEND_ORIGIN})
    assert response.status_code == 200, response.text
    assert response.json()["actor_id"] == "demo-reviewer"
    assert client.get("/api/v1/session").json() == response.json()
    return response.json()


def test_investigation_start_requires_session_and_trusted_origin_before_work(
    api_environment,
):
    client, store, _workflow, _sessions, _app = api_environment
    alert, _ = store.ingest_alert({**PAYLOAD, "alert_id": "AL-auth-start"}, None)
    path = "/api/v1/investigations"
    body = {"alert_id": alert["alert_id"], "mode": "rules"}
    headers = {"Idempotency-Key": "auth-start", "Origin": FRONTEND_ORIGIN}

    missing = client.post(path, json=body, headers=headers)
    assert missing.status_code == 401, missing.text
    assert (
        client.get(f"/api/v1/alerts/{alert['alert_id']}").json()["investigation_id"]
        is None
    )

    create_demo_session(client)
    for origin in (None, "https://evil.example"):
        unsafe_headers = {"Idempotency-Key": "auth-start"}
        if origin is not None:
            unsafe_headers["Origin"] = origin
        result = client.post(path, json=body, headers=unsafe_headers)
        assert result.status_code == 403, result.text
    assert (
        client.get(f"/api/v1/alerts/{alert['alert_id']}").json()["investigation_id"]
        is None
    )

    accepted = client.post(path, json=body, headers=headers)
    assert accepted.status_code == 202, accepted.text


def test_evidence_raw_detail_requires_session_but_summary_remains_public(
    api_environment,
):
    client, store, _workflow, sessions, _app = api_environment
    alert, _ = store.ingest_alert({**PAYLOAD, "alert_id": "AL-auth-evidence"}, None)
    evidence_id = "EV-" + "E" * 26
    with sessions.begin() as session:
        event = session.get(SecurityEventTable, "SE-api")
        session.add(
            IncidentTable(
                incident_id="IN-auth-evidence",
                alert_id=alert["alert_id"],
                status="received",
                created_at=NOW,
            )
        )
        session.flush()
        session.add(
            EvidenceItemTable(
                evidence_id=evidence_id,
                incident_id="IN-auth-evidence",
                event_id="SE-api",
                source="nginx",
                observed_at=NOW,
                query={"event_id": "SE-api"},
                summary="Safe evidence summary",
                content_sha256=event.content_sha256,
            )
        )
    base = "/api/v1/incidents/IN-auth-evidence/evidence"
    summary = client.get(base)
    assert summary.status_code == 200, summary.text
    assert summary.json()["items"][0]["summary"] == "Safe evidence summary"
    assert "UNION SELECT password" not in summary.text

    raw = client.get(f"{base}/{evidence_id}")
    assert raw.status_code == 401, raw.text
    assert "UNION SELECT password" not in raw.text

    create_demo_session(client)
    raw = client.get(f"{base}/{evidence_id}")
    assert raw.status_code == 200, raw.text
    assert (
        raw.json()["raw_event"]["raw"]["message"] == "UNION SELECT password FROM users"
    )


def decision_headers(key):
    return {"Origin": FRONTEND_ORIGIN, "Idempotency-Key": key}


def parse_sse(body):
    frames = []
    for block in body.replace("\r\n", "\n").split("\n\n"):
        fields = dict(
            line.split(": ", 1)
            for line in block.splitlines()
            if ": " in line and not line.startswith(":")
        )
        if "data" in fields:
            frames.append(
                {
                    "id": int(fields["id"]),
                    "event": fields["event"],
                    "data": json.loads(fields["data"]),
                }
            )
    return frames


def test_alert_idempotency_pagination_filters_and_conflict(api_environment):
    client, _store, _workflow, _sessions, _app = api_environment
    first = client.post(
        "/api/v1/alerts", json=PAYLOAD, headers={"Idempotency-Key": "same-alert"}
    )
    assert first.status_code == 201
    repeat = client.post(
        "/api/v1/alerts", json=PAYLOAD, headers={"Idempotency-Key": "same-alert"}
    )
    assert repeat.status_code == 200
    assert repeat.json() == first.json()
    changed = client.post(
        "/api/v1/alerts",
        json={**PAYLOAD, "title": "changed"},
        headers={"Idempotency-Key": "same-alert"},
    )
    assert changed.status_code == 409
    assert changed.json()["error"]["code"] == "CONFLICT"
    listing = client.get("/api/v1/alerts?severity=high&page=1&page_size=1").json()
    assert listing["total"] == 1 and len(listing["items"]) == 1
    assert client.get("/api/v1/alerts?severity=low").json()["total"] == 0


def test_alert_list_time_and_text_filters_accept_timezone_offsets(api_environment):
    client = api_environment[0]
    for alert_id, title, created_at in (
        ("AL-before", "Needle before", NOW - timedelta(seconds=1)),
        ("AL-start", "Needle% at start", NOW),
        ("AL-middle", "Needle in window", NOW + timedelta(minutes=15)),
        ("AL-end", "Needle after", NOW + timedelta(minutes=30)),
    ):
        response = client.post(
            "/api/v1/alerts",
            json={
                **PAYLOAD,
                "alert_id": alert_id,
                "title": title,
                "created_at": created_at.isoformat(),
            },
        )
        assert response.status_code == 201, response.text

    response = client.get(
        "/api/v1/alerts",
        params={
            "time_from": NOW.isoformat().replace("+00:00", "Z"),
            "time_to": (NOW + timedelta(minutes=30))
            .astimezone(timezone(timedelta(hours=8)))
            .isoformat(),
            "query": "  NEEDLE  ",
            "severity": "high",
            "status": "received",
            "page": 2,
            "page_size": 1,
        },
    )
    assert response.status_code == 200, response.text
    assert response.json()["total"] == 2
    assert [item["alert_id"] for item in response.json()["items"]] == ["AL-start"]
    literal = client.get(
        "/api/v1/alerts",
        params={
            "time_from": NOW.isoformat(),
            "time_to": (NOW + timedelta(minutes=30)).isoformat(),
            "query": "%",
        },
    )
    assert literal.status_code == 200, literal.text
    assert [item["alert_id"] for item in literal.json()["items"]] == ["AL-start"]


@pytest.mark.parametrize(
    "params",
    [
        {"time_from": "2026-09-21T10:20:17Z"},
        {"time_to": "2026-09-21T10:20:17Z"},
        {"time_from": "2026-09-21T10:20:17", "time_to": "2026-09-21T10:21:17Z"},
        {"time_from": "2026-09-21T10:20:17Z", "time_to": "2026-09-21T10:20:17Z"},
        {"time_from": "2026-09-21T10:21:17Z", "time_to": "2026-09-21T10:20:17Z"},
        {"query": "  "},
        {"query": "x" * 201},
    ],
)
def test_alert_list_rejects_invalid_time_or_text_filters(api_environment, params):
    response = api_environment[0].get("/api/v1/alerts", params=params)
    assert response.status_code == 422, response.text


def test_alert_detail_exposes_real_event_summary_and_existing_investigation(
    api_environment,
):
    client = api_environment[0]
    alert = client.post("/api/v1/alerts", json=PAYLOAD).json()
    path = f"/api/v1/alerts/{alert['alert_id']}"

    initial = client.get(path)
    assert initial.status_code == 200, initial.text
    assert initial.json() == {
        **alert,
        "status": "received",
        "execution_mode": "rules",
        "incident_id": None,
        "investigation_id": None,
        "events": [
            {
                "event_id": "SE-api",
                "source": "nginx",
                "observed_at": NOW.isoformat().replace("+00:00", "Z"),
                "severity": "high",
                "event_type": "web.request",
            }
        ],
    }
    assert "UNION SELECT password" not in initial.text
    assert "raw" not in initial.text

    create_demo_session(client)
    started = client.post(
        "/api/v1/investigations",
        json={"alert_id": alert["alert_id"], "mode": "rules"},
        headers={
            "Idempotency-Key": "start-" + alert["alert_id"],
            "Origin": FRONTEND_ORIGIN,
        },
    )
    assert started.status_code == 202, started.text
    awaiting = wait_status(client, started.json()["incident_id"], "awaiting_approval")
    detail = client.get(path)
    assert detail.status_code == 200, detail.text
    assert detail.json()["incident_id"] == started.json()["incident_id"]
    assert detail.json()["investigation_id"] == started.json()["investigation_id"]
    assert detail.json()["status"] == awaiting["status"]
    assert detail.json()["events"] == initial.json()["events"]


def test_alert_detail_missing_uses_safe_404_envelope(api_environment):
    response = api_environment[0].get("/api/v1/alerts/AL-missing-secret")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "NOT_FOUND"
    assert "AL-missing-secret" not in response.text


def test_alert_detail_accepts_url_encoded_legal_alert_id(api_environment):
    client = api_environment[0]
    alert_id = "AL:tenant/edge:1"
    created = client.post("/api/v1/alerts", json={**PAYLOAD, "alert_id": alert_id})
    assert created.status_code == 201, created.text
    response = client.get(f"/api/v1/alerts/{quote(alert_id, safe='')}")
    assert response.status_code == 200, response.text
    assert response.json()["alert_id"] == alert_id


def test_incident_list_http_contract_and_invalid_paging(api_environment):
    client, store, _workflow, sessions, _app = api_environment
    alert, _ = store.ingest_alert({**PAYLOAD, "alert_id": "AL-list-http"}, None)
    with sessions.begin() as session:
        session.add(
            IncidentTable(
                incident_id="IN-list-http",
                alert_id=alert["alert_id"],
                status="received",
                created_at=NOW,
            )
        )
    response = client.get("/api/v1/incidents?page=1&page_size=20&status=received")
    assert response.status_code == 200, response.text
    assert response.json() == {
        "items": [
            {
                "incident_id": "IN-list-http",
                "investigation_id": None,
                "alert_id": "AL-list-http",
                "alert_title": "SQL injection",
                "severity": "high",
                "status": "received",
                "created_at": NOW.isoformat().replace("+00:00", "Z"),
                "evidence_count": 0,
                "validation_outcome": None,
            }
        ],
        "total": 1,
        "page": 1,
        "page_size": 20,
    }
    assert client.get("/api/v1/incidents?page=0").status_code == 422
    assert client.get("/api/v1/incidents?page_size=201").status_code == 422
    assert client.get("/api/v1/incidents?status=invalid").status_code == 422


def test_incident_list_http_time_bounds_and_risk_contract(api_environment):
    client, store, _workflow, sessions, _app = api_environment
    alert, _ = store.ingest_alert({**PAYLOAD, "alert_id": "AL-list-time"}, None)
    with sessions.begin() as session:
        session.add(
            IncidentTable(
                incident_id="IN-list-time",
                alert_id=alert["alert_id"],
                status="received",
                created_at=NOW,
            )
        )
    response = client.get(
        "/api/v1/incidents",
        params={
            "risk": "high",
            "time_from": (NOW - timedelta(seconds=1)).isoformat(),
            "time_to": (NOW + timedelta(seconds=1)).isoformat(),
        },
    )
    assert response.status_code == 200, response.text
    assert response.json()["total"] == 1
    assert response.json()["items"][0]["incident_id"] == "IN-list-time"
    for params in (
        {"time_from": NOW.isoformat()},
        {
            "time_from": (NOW + timedelta(seconds=1)).isoformat(),
            "time_to": NOW.isoformat(),
        },
        {"time_from": "2026-09-21T10:20:16", "time_to": NOW.isoformat()},
        {"risk": "low"},
    ):
        assert client.get("/api/v1/incidents", params=params).status_code == 422


def test_alert_detail_execution_mode_uses_app_settings(api_environment):
    from evidencesoc.main import create_app

    _client, store, workflow, _sessions, _app = api_environment
    alert, _ = store.ingest_alert({**PAYLOAD, "alert_id": "AL-mode"}, None)
    settings = Settings(_env_file=None, llm_mode="deepseek")
    application = create_app(settings=settings, store=store, workflow=workflow)
    with TestClient(application, raise_server_exceptions=False) as client:
        detail = client.get(f"/api/v1/alerts/{alert['alert_id']}")
        assert detail.status_code == 200, detail.text
        assert detail.json()["execution_mode"] == "model"
        assert "deepseek_api_key" not in detail.text


def test_investigation_snapshot_http_contract_and_safe_missing_error(api_environment):
    client, store, _workflow, _sessions, _app = api_environment
    alert, _ = store.ingest_alert({**PAYLOAD, "alert_id": "AL-snapshot"}, None)
    created, _ = store.create_investigation(
        alert_id=alert["alert_id"], incident_id=None
    )
    identity = created["investigation_id"]
    store.append_event(identity, "investigation.started", {}, "started")
    store.save_state(identity, {"status": "analyzing"})

    response = client.get(f"/api/v1/investigations/{identity}")
    assert response.status_code == 200, response.text
    snapshot = response.json()
    assert snapshot["investigation_id"] == identity
    assert snapshot["incident_id"] == created["incident_id"]
    assert snapshot["trace_id"] == created["trace_id"]
    assert snapshot["status"] == "analyzing"
    assert snapshot["stream_cursor"] == "1"
    assert int(snapshot["revision"]) > 1
    assert snapshot["mode"] == "rules"
    assert snapshot["incident"]["status"] == "analyzing"
    assert snapshot["alert"]["alert_id"] == alert["alert_id"]
    assert snapshot["evidence_summary"] == {"total": 0, "items": []}
    assert snapshot["attack_graph"]["edges"] == []
    assert snapshot["available_actions"] == []
    assert snapshot["runs"] == snapshot["agent_runs"] == []
    assert snapshot["knowledge_refs"] == []

    missing = client.get("/api/v1/investigations/IV-private-missing")
    assert missing.status_code == 404
    assert missing.json()["error"]["code"] == "NOT_FOUND"
    assert "IV-private-missing" not in missing.text


@pytest.mark.parametrize(
    "method,path,body",
    [
        ("post", "/api/v1/alerts", {**PAYLOAD, "event_ids": []}),
        ("post", "/api/v1/alerts", {**PAYLOAD, "event_ids": ["missing"]}),
        ("post", "/api/v1/alerts", {**PAYLOAD, "title": "  "}),
        ("post", "/api/v1/investigations", {}),
        (
            "post",
            "/api/v1/investigations",
            {"alert_id": "missing", "incident_id": "missing"},
        ),
        ("get", "/api/v1/alerts?page=0", None),
        ("get", "/api/v1/incidents/missing", None),
        ("get", "/api/v1/investigations/missing/stream", None),
        ("get", "/api/v1/evaluations/missing", None),
        ("get", "/api/v1/unknown?password=do-not-echo", None),
    ],
)
def test_invalid_requests_have_one_safe_error_envelope(
    api_environment, method, path, body
):
    client = api_environment[0]
    kwargs = {"json": body} if body is not None else {}
    response = getattr(client, method)(path, **kwargs)
    assert response.status_code in {404, 422}
    assert set(response.json()) == {"error"}
    assert {"code", "message", "trace_id"} <= response.json()["error"].keys()
    assert "do-not-echo" not in response.text


def test_complete_flow_durable_order_reconnect_trace_and_duplicate_approval(
    api_environment,
):
    client, store, _workflow, sessions, _app = api_environment
    created = create_investigation(client)
    incident_id, investigation_id = created["incident_id"], created["investigation_id"]
    awaiting = wait_status(client, incident_id, "awaiting_approval")
    assert (
        awaiting["response_plan"] and awaiting["evidence"] and awaiting["attack_steps"]
    )
    assert awaiting["trace_id"] == created["trace_id"]
    events = store.list_events(investigation_id, 0)
    assert events[0]["event"] == "investigation.started"
    assert events[-1]["event"] == "approval.required"
    plan_id = awaiting["response_plan"]["response_plan_id"]
    create_demo_session(client)
    plan_version = client.get(f"/api/v1/response-plans/{plan_id}").json()[
        "plan_version"
    ]
    decision = {
        "reason": "Reviewed action, impact and rollback",
        "plan_version": plan_version,
    }
    approved = client.post(
        f"/api/v1/response-plans/{plan_id}/approve",
        json=decision,
        headers=decision_headers("approve-once"),
    )
    assert approved.status_code == 202, approved.text
    duplicate = client.post(
        f"/api/v1/response-plans/{plan_id}/approve",
        json=decision,
        headers=decision_headers("different-decision-request"),
    )
    assert duplicate.status_code == 409
    # This fixture supplies target presence but no before/after effect observations.
    final = wait_status(client, incident_id, "manual_review")
    assert final["validation_result"]["outcome"] == "insufficient_evidence"
    assert final["fallback_used"] is True
    assert final["simulation"] and all(
        action["simulated"] for action in final["simulation"]
    )
    stream = client.get(f"/api/v1/investigations/{investigation_id}/stream")
    assert stream.status_code == 200
    assert stream.headers["content-type"].startswith("text/event-stream")
    frames = parse_sse(stream.text)
    assert [item["id"] for item in frames] == list(range(1, len(frames) + 1))
    assert len([item for item in frames if item["event"] == "agent.started"]) == 6
    assert len([item for item in frames if item["event"] == "agent.completed"]) == 6
    assert frames[-2]["event"] == "validation.completed"
    assert frames[-1]["event"] == "investigation.failed"
    assert all(item["data"]["trace_id"] == created["trace_id"] for item in frames)
    cursor = events[-1]["id"]
    replay = client.get(
        f"/api/v1/investigations/{investigation_id}/stream",
        headers={"Last-Event-ID": str(cursor)},
    )
    assert parse_sse(replay.text) == [item for item in frames if item["id"] > cursor]
    bad_cursor = client.get(
        f"/api/v1/investigations/{investigation_id}/stream",
        headers={"Last-Event-ID": "invalid-secret"},
    )
    assert bad_cursor.status_code == 422 and "invalid-secret" not in bad_cursor.text
    with sessions() as session:
        approvals = session.scalars(
            select(ApprovalTable).where(ApprovalTable.response_plan_id == plan_id)
        ).all()
        assert len(approvals) == 1


def test_tampered_cited_event_blocks_http_approval_but_allows_rejection(
    api_environment,
):
    client, _store, _workflow, sessions, _app = api_environment
    created = create_investigation(client)
    awaiting = wait_status(client, created["incident_id"], "awaiting_approval")
    plan_id = awaiting["response_plan"]["response_plan_id"]
    create_demo_session(client)
    evidence_id = awaiting["response_plan"]["evidence_ids"][0]
    with sessions.begin() as session:
        session.get(SecurityEventTable, "SE-api").raw = {"message": "TAMPERED"}

    evidence = client.get(
        f"/api/v1/incidents/{created['incident_id']}/evidence/{evidence_id}"
    )
    assert evidence.status_code == 200
    assert evidence.json()["integrity"]["status"] == "mismatch"
    detail = client.get(f"/api/v1/response-plans/{plan_id}")
    assert detail.status_code == 200
    assert detail.json()["available_actions"] == ["reject"]
    decision = {
        "reason": "Evidence hash failed",
        "plan_version": detail.json()["plan_version"],
    }
    approved = client.post(
        f"/api/v1/response-plans/{plan_id}/approve",
        json=decision,
        headers=decision_headers("tampered-approve"),
    )
    assert approved.status_code == 409
    assert approved.json()["error"]["code"] == "CONFLICT"
    rejected = client.post(
        f"/api/v1/response-plans/{plan_id}/reject",
        json=decision,
        headers=decision_headers("tampered-reject"),
    )
    assert rejected.status_code == 202
    final = wait_status(client, created["incident_id"], "rejected")
    assert final["simulation"] == []


def test_rejection_requires_reason_and_stops_simulation(api_environment):
    client = api_environment[0]
    created = create_investigation(client)
    data = wait_status(client, created["incident_id"], "awaiting_approval")
    plan_id = data["response_plan"]["response_plan_id"]
    create_demo_session(client)
    version = client.get(f"/api/v1/response-plans/{plan_id}").json()["plan_version"]
    assert (
        client.post(
            f"/api/v1/response-plans/{plan_id}/reject",
            json={"reason": " ", "plan_version": version},
            headers=decision_headers("reject-empty-reason"),
        ).status_code
        == 422
    )
    response = client.post(
        f"/api/v1/response-plans/{plan_id}/reject",
        json={
            "reason": "Risk rejected",
            "plan_version": version,
        },
        headers=decision_headers("reject-risk"),
    )
    assert response.status_code == 202
    final = wait_status(client, created["incident_id"], "rejected")
    assert (
        final["approval"]["reason"] == "Risk rejected"
        and final["approval"]["decided_by"] == "demo-reviewer"
        and not final["validation_result"]
    )
    frames = parse_sse(
        client.get(f"/api/v1/investigations/{created['investigation_id']}/stream").text
    )
    assert frames[-1]["event"] == "investigation.completed"
    assert frames[-1]["data"]["status"] == "rejected"
    assert not any(item["event"] == "validation.completed" for item in frames)


def test_response_plan_get_routes_return_typed_page_and_safe_not_found(
    api_environment,
):
    client, store, _workflow, sessions, _app = api_environment
    initial = client.get("/api/v1/response-plans?page=1&page_size=20")
    assert initial.status_code == 200, initial.text
    assert initial.json() == {"items": [], "total": 0, "page": 1, "page_size": 20}
    assert (
        client.get("/api/v1/response-plans?decision_state=unknown").status_code == 422
    )
    assert client.get("/api/v1/response-plans?page=0").status_code == 422
    assert client.get("/api/v1/response-plans?page_size=201").status_code == 422
    missing = client.get("/api/v1/response-plans/RP-private-secret")
    assert missing.status_code == 404
    assert missing.json()["error"]["code"] == "NOT_FOUND"
    assert "RP-private-secret" not in missing.text

    alert, _ = store.ingest_alert({**PAYLOAD, "alert_id": "AL-plan-http"}, None)
    with sessions.begin() as session:
        session.add(
            IncidentTable(
                incident_id="IN-plan-http",
                alert_id=alert["alert_id"],
                status="received",
                created_at=NOW,
            )
        )
        session.flush()
        session.add(
            ResponsePlanTable(
                response_plan_id="RP-plan-http",
                incident_id="IN-plan-http",
                summary="Only simulated actions",
                actions=[
                    {
                        "action": "block_ip_simulated",
                        "target": "203.0.113.42",
                        "risk": "Source IP may be shared",
                        "impact": "Simulation only",
                        "preview": "Simulate blocking the observed source",
                        "rollback": "Remove the simulated block",
                        "verification_query": {
                            "filters": {"source_ip": "203.0.113.42"}
                        },
                    }
                ],
                created_at=NOW,
                requires_approval=True,
                evidence_ids=["EV-api"],
            )
        )
    listed = client.get("/api/v1/response-plans?decision_state=pending")
    assert listed.status_code == 200, listed.text
    assert listed.json()["total"] == 1
    assert listed.json()["items"][0]["response_plan_id"] == "RP-plan-http"
    detail = client.get("/api/v1/response-plans/RP-plan-http")
    assert detail.status_code == 200, detail.text
    assert detail.json()["alert_id"] == alert["alert_id"]
    assert detail.json()["decision_state"] == "pending"
    assert detail.json()["approval"] is None
    assert detail.json()["validation_result"] is None
    assert detail.json()["available_actions"] == []


def test_response_plan_version_hashes_persisted_plan_and_changes_with_it(
    api_environment,
):
    client, store, _workflow, sessions, _app = api_environment
    created = create_investigation(client)
    awaiting = wait_status(client, created["incident_id"], "awaiting_approval")
    plan_id = awaiting["response_plan"]["response_plan_id"]
    path = f"/api/v1/response-plans/{plan_id}"
    detail = client.get(path)
    assert detail.status_code == 200, detail.text
    version = detail.json()["plan_version"]
    assert re.fullmatch(r"[0-9a-f]{64}", version)
    persisted = store.get_plan(plan_id)
    persisted.pop("investigation_id")
    canonical = json.dumps(
        persisted, sort_keys=True, separators=(",", ":"), allow_nan=False
    )
    assert version == hashlib.sha256(canonical.encode()).hexdigest()
    assert client.get(path).json()["plan_version"] == version

    with sessions.begin() as session:
        session.get(ResponsePlanTable, plan_id).summary += " (revised)"
    assert client.get(path).json()["plan_version"] != version


def test_decision_requires_header_and_current_plan_version(api_environment):
    client, _store, _workflow, sessions, _app = api_environment
    created = create_investigation(client)
    awaiting = wait_status(client, created["incident_id"], "awaiting_approval")
    plan_id = awaiting["response_plan"]["response_plan_id"]
    create_demo_session(client)
    path = f"/api/v1/response-plans/{plan_id}/approve"
    version = client.get(f"/api/v1/response-plans/{plan_id}").json()["plan_version"]
    body = {"reason": "Reviewed", "plan_version": version}

    for invalid_body, headers in (
        (body, {}),
        (
            {"reason": "Reviewed"},
            {"Idempotency-Key": "missing-version"},
        ),
        (body, {"Idempotency-Key": " "}),
        (body, {"Idempotency-Key": "x" * 256}),
        (
            {**body, "plan_version": version.upper()},
            {"Idempotency-Key": "upper-version"},
        ),
        (
            {**body, "decided_by": "admin"},
            {"Idempotency-Key": "spoofed-actor"},
        ),
    ):
        response = client.post(
            path, json=invalid_body, headers={"Origin": FRONTEND_ORIGIN, **headers}
        )
        assert response.status_code == 422, response.text

    with sessions.begin() as session:
        session.get(ResponsePlanTable, plan_id).summary += " (revised)"
    stale = client.post(
        path, json=body, headers=decision_headers("retry-after-refresh")
    )
    assert stale.status_code == 409, stale.text
    assert stale.json()["error"]["code"] == "CONFLICT"
    assert (
        client.get(f"/api/v1/response-plans/{plan_id}").json()["decision_state"]
        == "pending"
    )

    fresh = client.get(f"/api/v1/response-plans/{plan_id}").json()["plan_version"]
    accepted = client.post(
        path,
        json={**body, "plan_version": fresh},
        headers=decision_headers("retry-after-refresh"),
    )
    assert accepted.status_code == 202, accepted.text


def test_decision_requires_a_valid_local_demo_session(api_environment, monkeypatch):
    from evidencesoc.api.demo_session import COOKIE_NAME, SESSION_LIFETIME_SECONDS

    client, _store, _workflow, _sessions, app = api_environment
    created = create_investigation(client)
    awaiting = wait_status(client, created["incident_id"], "awaiting_approval")
    plan_id = awaiting["response_plan"]["response_plan_id"]
    version = client.get(f"/api/v1/response-plans/{plan_id}").json()["plan_version"]
    path = f"/api/v1/response-plans/{plan_id}/approve"
    body = {"plan_version": version, "reason": "Reviewed"}
    headers = decision_headers("session-required")

    client.cookies.clear()
    missing = client.post(path, json=body, headers=headers)
    assert missing.status_code == 401, missing.text
    assert missing.json()["error"]["code"] == "SESSION_REQUIRED"
    spoofed_header = client.post(
        path, json=body, headers={**headers, "X-Reviewer-Id": "demo-reviewer"}
    )
    assert spoofed_header.status_code == 401, spoofed_header.text
    client.cookies.set(COOKIE_NAME, "forged")
    forged = client.post(path, json=body, headers=headers)
    assert forged.status_code == 401, forged.text
    client.cookies.clear()

    create_demo_session(client)
    token = client.cookies.get(COOKIE_NAME)
    missing_origin = client.post(
        path, json=body, headers={"Idempotency-Key": "missing-origin"}
    )
    assert missing_origin.status_code == 403, missing_origin.text
    wrong_origin = client.post(
        path,
        json=body,
        headers={"Origin": "http://evil.example", "Idempotency-Key": "wrong-origin"},
    )
    assert wrong_origin.status_code == 403, wrong_origin.text

    outside = TestClient(
        app, raise_server_exceptions=False, client=("203.0.113.7", 50001)
    )
    outside.cookies.set(COOKIE_NAME, token)
    issue = outside.post("/api/v1/session/demo", headers={"Origin": FRONTEND_ORIGIN})
    assert issue.status_code == 403, issue.text
    direct = outside.post(path, json=body, headers=headers)
    assert direct.status_code == 403, direct.text
    outside.close()

    clock = app.state.demo_sessions._clock
    monkeypatch.setattr(
        app.state.demo_sessions,
        "_clock",
        lambda: clock() + SESSION_LIFETIME_SECONDS + 1,
    )
    expired = client.post(path, json=body, headers=headers)
    assert expired.status_code == 401, expired.text
    monkeypatch.setattr(app.state.demo_sessions, "_clock", clock)

    assert (
        client.get(f"/api/v1/response-plans/{plan_id}").json()["decision_state"]
        == "pending"
    )
    accepted = client.post(path, json=body, headers=headers)
    assert accepted.status_code == 202, accepted.text


@pytest.mark.parametrize(
    ("action", "terminal_status"),
    [("approve", "manual_review"), ("reject", "rejected")],
)
def test_decision_key_replays_original_response_after_terminal_without_rescheduling(
    api_environment, monkeypatch, action, terminal_status
):
    from evidencesoc.api.storage import ApiStore

    client, _store, _workflow, sessions, app = api_environment
    created = create_investigation(client)
    awaiting = wait_status(client, created["incident_id"], "awaiting_approval")
    plan_id = awaiting["response_plan"]["response_plan_id"]
    create_demo_session(client)
    version = client.get(f"/api/v1/response-plans/{plan_id}").json()["plan_version"]
    body = {"reason": "Reviewed", "plan_version": version}
    path = f"/api/v1/response-plans/{plan_id}/{action}"
    key = f"decision-{action}-once"
    headers = decision_headers(key)
    first = client.post(path, json=body, headers=headers)
    assert first.status_code == 202, first.text
    terminal = wait_status(client, created["incident_id"], terminal_status)
    if action == "approve":
        assert terminal["validation_result"]["outcome"] == "insufficient_evidence"
    before = app.state.runner.store.list_events(created["investigation_id"], 0)
    scheduled = []
    monkeypatch.setattr(
        app.state.runner, "schedule", lambda metadata: scheduled.append(metadata)
    )

    from evidencesoc.api.demo_session import COOKIE_NAME

    client.cookies.clear()
    unauthenticated_replay = client.post(path, json=body, headers=headers)
    assert unauthenticated_replay.status_code == 401, unauthenticated_replay.text
    client.cookies.set(COOKIE_NAME, "forged")
    forged_replay = client.post(path, json=body, headers=headers)
    assert forged_replay.status_code == 401, forged_replay.text
    client.cookies.clear()
    create_demo_session(client)

    replay = client.post(path, json=body, headers=headers)
    assert replay.status_code == 202, replay.text
    assert replay.json() == first.json()
    assert replay.json()["trace_id"] == created["trace_id"]
    assert scheduled == []
    assert app.state.runner.store.list_events(created["investigation_id"], 0) == before

    changed = client.post(path, json={**body, "reason": "Changed"}, headers=headers)
    assert changed.status_code == 409, changed.text
    other_action = "reject" if action == "approve" else "approve"
    cross_action = client.post(
        f"/api/v1/response-plans/{plan_id}/{other_action}",
        json=body,
        headers=headers,
    )
    assert cross_action.status_code == 409, cross_action.text
    new_key = client.post(path, json=body, headers=decision_headers(key + "-new"))
    assert new_key.status_code == 409, new_key.text

    restored = ApiStore(sessions)
    durable = restored.record_decision_idempotent(
        plan_id,
        {
            **body,
            "decided_by": "demo-reviewer",
            "decision": "approved" if action == "approve" else "rejected",
            "response_plan_id": plan_id,
        },
        key,
    )
    assert durable["replayed"] is True
    assert durable["response"] == first.json()


def test_evidence_detail_http_scopes_raw_log_to_owning_incident(api_environment):
    client, store, _workflow, sessions, _app = api_environment
    alert, _ = store.ingest_alert({**PAYLOAD, "alert_id": "AL-evidence-http"}, None)
    evidence_id = "EV-" + "2" * 26
    with sessions.begin() as session:
        event = session.get(SecurityEventTable, "SE-api")
        for incident_id in ("IN-evidence-own", "IN-evidence-other"):
            session.add(
                IncidentTable(
                    incident_id=incident_id,
                    alert_id=alert["alert_id"],
                    status="received",
                    created_at=NOW,
                )
            )
        session.flush()
        session.add(
            EvidenceItemTable(
                evidence_id=evidence_id,
                incident_id="IN-evidence-own",
                event_id="SE-api",
                source="nginx",
                observed_at=NOW,
                query={"event_id": "SE-api"},
                summary="Verified SQL pattern",
                content_sha256=event.content_sha256,
            )
        )
    base = "/api/v1/incidents"
    create_demo_session(client)
    own = client.get(f"{base}/IN-evidence-own/evidence/{evidence_id}")
    assert own.status_code == 200, own.text
    assert own.json()["evidence"]["incident_id"] == "IN-evidence-own"
    assert (
        own.json()["raw_event"]["raw"]["message"] == "UNION SELECT password FROM users"
    )
    assert own.json()["integrity"]["status"] == "verified"
    assert own.json()["integrity"]["scope"] == "postgresql"
    other = client.get(f"{base}/IN-evidence-other/evidence/{evidence_id}")
    assert other.status_code == 404
    assert other.json()["error"]["code"] == "NOT_FOUND"
    assert "UNION SELECT password" not in other.text
    missing = client.get(f"{base}/IN-evidence-own/evidence/EV-missing")
    assert missing.status_code == 404


def test_incident_evidence_page_scopes_and_orders_authorized_summaries(api_environment):
    client, store, _workflow, sessions, _app = api_environment
    alert, _ = store.ingest_alert({**PAYLOAD, "alert_id": "AL-evidence-page"}, None)
    with sessions.begin() as session:
        for incident_id in ("IN-evidence-page", "IN-evidence-neighbor"):
            session.add(
                IncidentTable(
                    incident_id=incident_id,
                    alert_id=alert["alert_id"],
                    status="received",
                    created_at=NOW,
                )
            )
        session.flush()
        for evidence_id, incident_id, observed_at in (
            ("EV-" + "C" * 26, "IN-evidence-page", NOW + timedelta(minutes=1)),
            ("EV-" + "B" * 26, "IN-evidence-page", NOW),
            ("EV-" + "A" * 26, "IN-evidence-page", NOW),
            ("EV-" + "D" * 26, "IN-evidence-neighbor", NOW),
        ):
            session.add(
                EvidenceItemTable(
                    evidence_id=evidence_id,
                    incident_id=incident_id,
                    event_id="SE-api",
                    source="nginx",
                    observed_at=observed_at,
                    query={"event_id": "SE-api"},
                    summary=f"Summary {evidence_id}",
                    content_sha256="a" * 64,
                )
            )

    base = "/api/v1/incidents/IN-evidence-page/evidence"
    first = client.get(base, params={"page": 1, "page_size": 2})
    assert first.status_code == 200, first.text
    assert (first.json()["total"], first.json()["page"], first.json()["page_size"]) == (
        3,
        1,
        2,
    )
    assert [item["evidence_id"] for item in first.json()["items"]] == [
        "EV-" + "A" * 26,
        "EV-" + "B" * 26,
    ]
    assert {item["incident_id"] for item in first.json()["items"]} == {
        "IN-evidence-page"
    }
    assert all(
        "raw" not in item and "raw_event" not in item for item in first.json()["items"]
    )
    assert "UNION SELECT password" not in first.text

    second = client.get(base, params={"page": 2, "page_size": 2})
    assert second.status_code == 200, second.text
    assert [item["evidence_id"] for item in second.json()["items"]] == [
        "EV-" + "C" * 26
    ]
    beyond = client.get(base, params={"page": 3, "page_size": 2})
    assert beyond.status_code == 200
    assert beyond.json() == {"items": [], "total": 3, "page": 3, "page_size": 2}

    neighbor = client.get("/api/v1/incidents/IN-evidence-neighbor/evidence")
    assert neighbor.status_code == 200
    assert [item["evidence_id"] for item in neighbor.json()["items"]] == [
        "EV-" + "D" * 26
    ]
    missing = client.get("/api/v1/incidents/IN-no-such-incident/evidence")
    assert missing.status_code == 404
    assert missing.json()["error"]["code"] == "NOT_FOUND"
    for query in ("page=0", "page_size=0", "page_size=201"):
        invalid = client.get(f"{base}?{query}")
        assert invalid.status_code == 422
        assert invalid.json()["error"]["code"] == "INVALID_REQUEST"


def test_repeated_investigation_is_reused_and_health_is_available(api_environment):
    client = api_environment[0]
    created = create_investigation(client)
    repeat = client.post(
        "/api/v1/investigations",
        json={"incident_id": created["incident_id"], "mode": "rules"},
        headers={
            "Idempotency-Key": "repeat-" + created["incident_id"],
            "Origin": FRONTEND_ORIGIN,
        },
    )
    assert repeat.status_code == 200
    assert repeat.json()["investigation_id"] == created["investigation_id"]
    assert client.get("/health/live").json() == {"status": "ok"}


def test_investigation_start_requires_mode_and_key_and_replays_same_request(
    api_environment,
):
    client = api_environment[0]
    create_demo_session(client)
    alert = client.post("/api/v1/alerts", json=PAYLOAD).json()
    path = "/api/v1/investigations"
    body = {"alert_id": alert["alert_id"], "mode": "rules"}
    headers = {"Idempotency-Key": "start-contract-1", "Origin": FRONTEND_ORIGIN}
    assert client.post(path, json=body).status_code == 422
    assert (
        client.post(
            path, json={"alert_id": alert["alert_id"]}, headers=headers
        ).status_code
        == 422
    )
    wrong_mode = client.post(path, json={**body, "mode": "model"}, headers=headers)
    assert wrong_mode.status_code == 409
    assert wrong_mode.json()["error"]["code"] == "EXECUTION_MODE_MISMATCH"

    first = client.post(path, json=body, headers=headers)
    assert first.status_code == 202, first.text
    replay = client.post(path, json=body, headers=headers)
    assert replay.status_code == 200, replay.text
    assert replay.json() == first.json()

    other = client.post(
        "/api/v1/alerts", json={**PAYLOAD, "alert_id": "AL-other"}
    ).json()
    conflict = client.post(
        path, json={"alert_id": other["alert_id"], "mode": "rules"}, headers=headers
    )
    assert conflict.status_code == 409
    assert conflict.json()["error"]["code"] == "CONFLICT"


def test_readiness_failure_has_safe_error_and_recovers(api_environment):
    from evidencesoc.main import create_app

    _client, store, workflow, _sessions, _app = api_environment
    healthy = False

    async def probe():
        if not healthy:
            raise RuntimeError("database password=readiness-secret")

    application = create_app(store=store, workflow=workflow, readiness_probe=probe)
    with TestClient(application, raise_server_exceptions=False) as client:
        failure = client.get("/health/ready")
        assert failure.status_code == 503 and "readiness-secret" not in failure.text
        assert client.get("/health/live").status_code == 200
        healthy = True
        assert client.get("/health/ready").json() == {"status": "ok"}


def test_startup_dependency_failure_recovers_without_restart(
    api_environment, monkeypatch
):
    from contextlib import asynccontextmanager

    from evidencesoc import main

    _client, store, workflow, _sessions, _app = api_environment
    healthy = False

    @asynccontextmanager
    async def open_workflow(_settings):
        if not healthy:
            raise RuntimeError("password=startup-secret")
        yield workflow

    async def probe():
        return None

    monkeypatch.setattr(main, "open_workflow", open_workflow)
    application = main.create_app(store=store, readiness_probe=probe)
    with TestClient(application, raise_server_exceptions=False) as client:
        assert client.get("/health/live").status_code == 200
        failure = client.get("/health/ready")
        assert failure.status_code == 503 and "startup-secret" not in failure.text
        healthy = True
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            if client.get("/health/ready").status_code == 200:
                return
            time.sleep(0.05)
        pytest.fail("startup dependencies did not recover without restarting the API")


def test_dashboard_summary_uses_real_window_counts_and_current_pending_state(
    api_environment,
):
    client, _store, _workflow, _sessions, _app = api_environment
    invalid = client.get("/api/v1/dashboard/summary?window=invalid")
    assert invalid.status_code == 422

    created = client.post(
        "/api/v1/alerts",
        json={
            **PAYLOAD,
            "alert_id": "AL-dashboard-now",
            "created_at": datetime.now(UTC).isoformat(),
        },
    )
    assert created.status_code == 201, created.text
    create_demo_session(client)
    started = client.post(
        "/api/v1/investigations",
        json={"alert_id": "AL-dashboard-now", "mode": "rules"},
        headers={
            "Idempotency-Key": "start-AL-dashboard-now",
            "Origin": FRONTEND_ORIGIN,
        },
    )
    assert started.status_code == 202, started.text
    wait_status(client, started.json()["incident_id"], "awaiting_approval")

    response = client.get("/api/v1/dashboard/summary?window=1h")
    assert response.status_code == 200, response.text
    summary = response.json()
    assert summary["window"] == "1h"
    assert summary["execution_mode"] == "rules"
    assert summary["metrics"] == {
        "alerts_in_window": 1,
        "high_risk_incidents": 1,
        "running_investigations": 0,
        "pending_response_plans": 1,
    }
    assert len(summary["alert_trend"]) == 12
    assert sum(bucket["total"] for bucket in summary["alert_trend"]) == 1
    assert sum(bucket["high_risk"] for bucket in summary["alert_trend"]) == 1
    assert summary["incident_status_distribution"] == [
        {"status": "awaiting_approval", "count": 1}
    ]
    assert summary["recent_alerts"][0]["alert_id"] == "AL-dashboard-now"
    assert summary["recent_activity"]
    assert summary["source_health"]["postgresql_status"] is None
    assert summary["source_health"]["opensearch_status"] is None
