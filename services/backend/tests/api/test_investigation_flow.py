from __future__ import annotations

import asyncio
import json
import time
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient
from langgraph.checkpoint.memory import InMemorySaver
from sqlalchemy import JSON, CheckConstraint, MetaData, create_engine, event, select
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import sessionmaker

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

NOW = datetime(2026, 9, 21, 10, 20, 17, tzinfo=UTC)
PAYLOAD = {
    "title": "SQL injection",
    "severity": "high",
    "event_ids": ["SE-api"],
    "created_at": NOW.isoformat(),
}


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

    settings = Settings(_env_file=None, llm_mode="fixture")

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
            return {"evidence": state["evidence"]}

    store = ApiStore(sessions)
    services = FixtureServices(settings, session_factory=sessions)
    workflow = InvestigationWorkflow(
        services=services, settings=settings, checkpointer=InMemorySaver()
    )
    application = create_app(settings=settings, store=store, workflow=workflow)
    try:
        with TestClient(application, raise_server_exceptions=False) as client:
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
    response = client.post(
        "/api/v1/investigations", json={"alert_id": alert.json()["alert_id"]}
    )
    assert response.status_code == 202, response.text
    return response.json()


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
    decision = {
        "reason": "Reviewed action, impact and rollback",
        "decided_by": "reviewer",
    }
    approved = client.post(f"/api/v1/response-plans/{plan_id}/approve", json=decision)
    assert approved.status_code == 202, approved.text
    duplicate = client.post(f"/api/v1/response-plans/{plan_id}/approve", json=decision)
    assert duplicate.status_code == 409
    final = wait_status(client, incident_id, "completed")
    assert final["validation_result"]["outcome"] == "success"
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
    assert frames[-1]["event"] == "investigation.completed"
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


def test_rejection_requires_reason_and_stops_simulation(api_environment):
    client = api_environment[0]
    created = create_investigation(client)
    data = wait_status(client, created["incident_id"], "awaiting_approval")
    plan_id = data["response_plan"]["response_plan_id"]
    assert (
        client.post(
            f"/api/v1/response-plans/{plan_id}/reject",
            json={"reason": " ", "decided_by": "reviewer"},
        ).status_code
        == 422
    )
    response = client.post(
        f"/api/v1/response-plans/{plan_id}/reject",
        json={"reason": "Risk rejected", "decided_by": "reviewer"},
    )
    assert response.status_code == 202
    final = wait_status(client, created["incident_id"], "rejected")
    assert (
        final["approval"]["reason"] == "Risk rejected"
        and not final["validation_result"]
    )
    frames = parse_sse(
        client.get(f"/api/v1/investigations/{created['investigation_id']}/stream").text
    )
    assert frames[-1]["event"] == "investigation.completed"
    assert frames[-1]["data"]["status"] == "rejected"
    assert not any(item["event"] == "validation.completed" for item in frames)


def test_repeated_investigation_is_reused_and_health_is_available(api_environment):
    client = api_environment[0]
    created = create_investigation(client)
    repeat = client.post(
        "/api/v1/investigations", json={"incident_id": created["incident_id"]}
    )
    assert repeat.status_code == 200
    assert repeat.json()["investigation_id"] == created["investigation_id"]
    assert client.get("/health/live").json() == {"status": "ok"}


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
