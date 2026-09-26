from __future__ import annotations

import importlib
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import pytest
from sqlalchemy import JSON, CheckConstraint, MetaData, create_engine, func, select
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import sessionmaker

from evidencesoc.config import Settings
from evidencesoc.domain.models import EvidenceItem
from evidencesoc.ids import new_evidence_id
from evidencesoc.ingestion.normalize import calculate_content_sha256
from evidencesoc.persistence.tables import (
    AgentRunTable,
    AlertTable,
    ApprovalTable,
    AttackStepTable,
    EvidenceItemTable,
    IncidentTable,
    ResponsePlanTable,
    SecurityEventTable,
    ValidationResultTable,
)

NOW = datetime(2026, 9, 21, 10, 20, tzinfo=UTC)


@pytest.fixture
def database(tmp_path: Any) -> Any:
    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'workflow.db'}")
    metadata = MetaData()
    for model in (
        AlertTable,
        IncidentTable,
        SecurityEventTable,
        EvidenceItemTable,
        AgentRunTable,
        ResponsePlanTable,
        ApprovalTable,
        ValidationResultTable,
        AttackStepTable,
    ):
        table = model.__table__.to_metadata(metadata)
        for column in table.columns:
            if isinstance(column.type, JSONB):
                column.type = JSON()
        for constraint in list(table.constraints):
            if isinstance(constraint, CheckConstraint):
                table.constraints.remove(constraint)
    metadata.create_all(engine)
    sessions = sessionmaker(bind=engine, expire_on_commit=False)
    raw = {
        "source_ip": "203.0.113.42",
        "host": "shop.example.test",
        "service": "checkout-api",
        "message": "UNION SELECT probe",
        "tags": ["sql-injection"],
        "labels": ["do-not-load"],
        "username": "alice",
        "http": {"path": "/login", "status_code": 401},
    }
    with sessions() as session:
        session.add_all(
            [
                AlertTable(
                    alert_id="AL-1",
                    title="Suspicious web request",
                    severity="high",
                    created_at=NOW,
                    event_ids=["SE-1"],
                ),
                IncidentTable(
                    incident_id="IN-1",
                    alert_id="AL-1",
                    status="received",
                    created_at=NOW,
                ),
                IncidentTable(
                    incident_id="IN-2",
                    alert_id="AL-1",
                    status="received",
                    created_at=NOW,
                ),
                SecurityEventTable(
                    event_id="SE-1",
                    source="nginx",
                    external_id="request-1",
                    deduplication_key="id:request-1",
                    observed_at=NOW,
                    ingested_at=NOW,
                    severity="high",
                    event_type="web.request",
                    raw=raw,
                    content_sha256=calculate_content_sha256(raw),
                    index_status="indexed",
                ),
            ]
        )
        session.commit()
        evidence = EvidenceItem(
            evidence_id=new_evidence_id(),
            event_id="SE-1",
            source="nginx",
            observed_at=NOW,
            query={"matched_event_id": "SE-1"},
            summary="Verified web request",
            content_sha256=calculate_content_sha256(raw),
        )
        session.add(EvidenceItemTable(**evidence.model_dump(), incident_id="IN-1"))
        session.commit()
    yield sessions, evidence
    engine.dispose()


def service(database: Any) -> Any:
    module = importlib.import_module("evidencesoc.agents.services")
    return module.PostgresWorkflowServices(
        Settings(_env_file=None),
        session_factory=database[0],
    )


def test_close_preserves_injected_database_engine(database: Any) -> None:
    api = service(database)
    api.close()
    with database[0]() as session:
        assert session.get(IncidentTable, "IN-1") is not None


@pytest.mark.asyncio
async def test_load_incident_and_agent_runs_are_persisted(database: Any) -> None:
    api = service(database)
    result = await api.load_incident("IN-1")
    assert result["alerts"][0]["alert_id"] == "AL-1"
    assert result["status"] == "received"
    with pytest.raises(LookupError):
        await api.load_incident("IN-missing")
    run_id = await api.start_run({"incident_id": "IN-1"}, "triage")
    await api.finish_run(run_id, {"evidence": [database[1].model_dump(mode="json")]})
    with database[0]() as session:
        row = session.get(AgentRunTable, run_id)
        assert row.agent_name == "triage"
        assert row.status == "completed"
        assert row.finished_at is not None
        assert row.evidence_ids == [database[1].evidence_id]
    analysis_run = await api.start_run({"incident_id": "IN-1"}, "analyze")
    await api.finish_run(
        analysis_run, {"origin": {"evidence_ids": [database[1].evidence_id]}}
    )
    with database[0]() as session:
        assert session.get(AgentRunTable, analysis_run).evidence_ids == [
            database[1].evidence_id
        ]


@pytest.mark.asyncio
async def test_role_run_is_reused_after_restart_and_distinct_for_fallback_attempt(
    database: Any,
) -> None:
    first = service(database)
    state = {"incident_id": "IN-1", "trace_id": "TRACE-restart", "fallback_count": 0}
    original = await first.start_run(state, "collect")
    recovered = service(database)
    resumed = await recovered.start_run(state, "collect")
    assert resumed == original
    await recovered.finish_run(
        resumed, {"evidence": [database[1].model_dump(mode="json")]}
    )
    retry = await recovered.start_run({**state, "fallback_count": 1}, "collect")
    assert retry != original
    with database[0]() as session:
        rows = session.scalars(
            select(AgentRunTable).where(AgentRunTable.incident_id == "IN-1")
        ).all()
        assert len(rows) == 2
        assert session.get(AgentRunTable, original).status == "completed"


@pytest.mark.asyncio
async def test_collect_uses_three_real_tool_contracts_and_filters_observations(
    database: Any, monkeypatch: Any
) -> None:
    api = service(database)
    module = importlib.import_module("evidencesoc.agents.services")
    calls: list[tuple[str, dict[str, Any]]] = []
    evidence = database[1].model_dump(mode="json")
    knowledge = {
        "knowledge_chunk_id": "KC-verified",
        "technique_id": "T1190",
        "title": "Exploit Public-Facing Application",
        "summary": "Exploit an application",
        "source_uri": "https://attack.mitre.org/techniques/T1190/",
        "version": "19.2",
    }

    class Session:
        async def list_tools(self) -> Any:
            return SimpleNamespace(
                tools=[
                    SimpleNamespace(name=name)
                    for name in (
                        "search_security_events",
                        "get_alert_context",
                        "lookup_attack_technique",
                    )
                ]
            )

        async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
            calls.append((name, arguments))
            return SimpleNamespace(
                isError=False,
                structuredContent={
                    "result": [knowledge]
                    if name == "lookup_attack_technique"
                    else [evidence]
                },
            )

    @asynccontextmanager
    async def open_session(*args: Any, **kwargs: Any) -> Any:
        yield Session()

    monkeypatch.setattr(module, "open_stdio_session", open_session)
    result = await api.collect({"incident_id": "IN-1", "trace_id": "TRACE-1"}, "AR-1")
    assert {name for name, _ in calls} == {
        "search_security_events",
        "get_alert_context",
        "lookup_attack_technique",
    }
    assert len(result["evidence"]) == 1
    assert result["evidence"][0]["raw"]["source_ip"] == "203.0.113.42"
    assert "tags" not in result["evidence"][0]["raw"]
    assert "labels" not in result["evidence"][0]["raw"]
    search = next(
        arguments for name, arguments in calls if name == "search_security_events"
    )
    assert search["filters"]["source_ip"] == "203.0.113.42"
    assert result["knowledge"] == [knowledge]


@pytest.mark.asyncio
async def test_foreign_or_forged_evidence_cannot_enter_state(database: Any) -> None:
    api = service(database)
    with pytest.raises(PermissionError):
        await api.hydrate_evidence("IN-2", [database[1].model_dump(mode="json")])
    forged = database[1].model_dump(mode="json")
    forged["content_sha256"] = "0" * 64
    with pytest.raises(ValueError):
        await api.hydrate_evidence("IN-1", [forged])


@pytest.mark.asyncio
async def test_verify_distinguishes_empty_result_from_mcp_error(
    database: Any, monkeypatch: Any
) -> None:
    api = service(database)
    module = importlib.import_module("evidencesoc.agents.services")
    failed = False

    class Session:
        async def list_tools(self) -> Any:
            return SimpleNamespace(
                tools=[
                    SimpleNamespace(name=name)
                    for name in (
                        "search_security_events",
                        "get_alert_context",
                        "lookup_attack_technique",
                    )
                ]
            )

        async def call_tool(self, *args: Any, **kwargs: Any) -> Any:
            return SimpleNamespace(
                isError=failed,
                structuredContent={"error": {"code": "DEPENDENCY_TIMEOUT"}}
                if failed
                else {"result": []},
            )

    @asynccontextmanager
    async def open_session(*args: Any, **kwargs: Any) -> Any:
        yield Session()

    monkeypatch.setattr(module, "open_stdio_session", open_session)
    state = verification_state(database, [{"filters": {"source_ip": "203.0.113.42"}}])
    assert await api.verify(state, "AR-1") == {"evidence": []}
    failed = True
    with pytest.raises(RuntimeError, match="DEPENDENCY_TIMEOUT"):
        await api.verify(state, "AR-1")


def verification_state(database: Any, queries: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "incident_id": "IN-1",
        "trace_id": "TRACE-1",
        "response_plan": {
            "response_plan_id": "RP-1",
            "incident_id": "IN-1",
            "summary": "Local simulation",
            "created_at": NOW.isoformat(),
            "evidence_ids": [database[1].evidence_id],
            "actions": [
                {
                    "action": "block_ip_simulated",
                    "target": "203.0.113.42",
                    "risk": "Shared source",
                    "impact": "Simulation only",
                    "preview": "Preview block",
                    "rollback": "Remove overlay",
                    "verification_query": query,
                }
                for query in queries
            ],
        },
    }


@pytest.mark.asyncio
async def test_verify_executes_distinct_plan_queries_with_original_scope(
    database: Any, monkeypatch: Any
) -> None:
    api = service(database)
    module = importlib.import_module("evidencesoc.agents.services")
    calls: list[dict[str, Any]] = []

    class Session:
        async def list_tools(self) -> Any:
            return SimpleNamespace(
                tools=[
                    SimpleNamespace(name=name)
                    for name in (
                        "search_security_events",
                        "get_alert_context",
                        "lookup_attack_technique",
                    )
                ]
            )

        async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
            assert name == "search_security_events"
            calls.append(arguments)
            return SimpleNamespace(
                isError=False,
                structuredContent={"result": [database[1].model_dump(mode="json")]},
            )

    @asynccontextmanager
    async def open_session(*args: Any, **kwargs: Any) -> Any:
        yield Session()

    monkeypatch.setattr(module, "open_stdio_session", open_session)
    first = {"filters": {"source_ip": "203.0.113.42"}, "limit": 10}
    second = {
        "filters": {"source_ip": "203.0.113.42", "event_type": "web.request"},
        "time_from": "2026-09-21T10:19:00Z",
        "time_to": "2026-09-21T10:21:00Z",
        "limit": 5,
    }
    result = await api.verify(
        verification_state(database, [first, first, second]), "AR-1"
    )
    assert len(calls) == 2
    assert calls[0]["limit"] == 10
    assert calls[1]["limit"] == 5
    assert calls[1]["filters"] == {
        "source_ip": "203.0.113.42",
        "host": "shop.example.test",
        "service": "checkout-api",
        "event_type": "web.request",
    }
    assert calls[1]["time_from"] == "2026-09-21T10:19:00+00:00"
    assert len(result["evidence"]) == 1
    assert result["evidence"][0]["raw"]["username"] == "alice"
    assert "labels" not in result["evidence"][0]["raw"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "query",
    [
        {"filters": {"source_ip": "198.51.100.99"}},
        {"filters": {"host": "foreign.example.test"}},
        {
            "filters": {"source_ip": "203.0.113.42"},
            "time_from": "2026-09-21T10:04:00Z",
            "time_to": "2026-09-21T10:21:00Z",
        },
        {
            "filters": {"source_ip": "203.0.113.42"},
            "time_from": "2026-09-21T10:19:00Z",
            "time_to": "2026-09-21T10:36:00Z",
        },
        {"filters": {"source_ip": "203.0.113.42"}, "limit": 101},
        {
            "filters": {"source_ip": "203.0.113.42"},
            "time_from": "2026-09-21T10:19:00",
            "time_to": "2026-09-21T10:21:00",
        },
    ],
)
async def test_verify_rejects_model_query_that_expands_incident_scope(
    database: Any, monkeypatch: Any, query: dict[str, Any]
) -> None:
    api = service(database)
    module = importlib.import_module("evidencesoc.agents.services")

    def forbidden_session(*args: Any, **kwargs: Any) -> Any:
        pytest.fail("unsafe verification query must be rejected before opening MCP")

    monkeypatch.setattr(module, "open_stdio_session", forbidden_session)
    with pytest.raises((PermissionError, ValueError)):
        await api.verify(verification_state(database, [query]), "AR-1")


@pytest.mark.asyncio
async def test_save_result_is_idempotent_and_preserves_approval_scope(
    database: Any,
) -> None:
    api = service(database)
    evidence_id = database[1].evidence_id
    state = {
        "incident_id": "IN-1",
        "status": "completed",
        "evidence": [database[1].model_dump(mode="json")],
        "response_plan": {
            "response_plan_id": "RP-1",
            "incident_id": "IN-1",
            "summary": "Simulate blocking",
            "actions": [{"action": "block_ip_simulated", "target": "203.0.113.42"}],
            "created_at": NOW.isoformat(),
            "requires_approval": True,
            "evidence_ids": [evidence_id],
        },
        "approval": {
            "approval_id": "AP-1",
            "response_plan_id": "RP-1",
            "decision": "approved",
            "reason": "local simulation",
            "decided_by": "operator",
            "decided_at": NOW.isoformat(),
        },
        "validation_result": {
            "validation_id": "VR-1",
            "response_plan_id": "RP-1",
            "outcome": "success",
            "summary": "Simulation verified",
            "checked_at": NOW.isoformat(),
            "evidence_ids": [evidence_id],
        },
        "attack_steps": [
            {
                "attack_step_id": "AS-1",
                "sequence": 1,
                "phase": "initial_access",
                "technique_id": "T1190",
                "description": "Observed injection probe",
                "occurred_at": NOW.isoformat(),
                "evidence_ids": [evidence_id],
            }
        ],
    }
    await api.save_result(state)
    await api.save_result(state)
    with database[0]() as session:
        assert session.get(IncidentTable, "IN-1").status == "completed"
        for table in (
            ResponsePlanTable,
            ApprovalTable,
            ValidationResultTable,
            AttackStepTable,
        ):
            assert session.scalar(select(func.count()).select_from(table)) == 1
    state["response_plan"]["incident_id"] = "IN-2"
    with pytest.raises(PermissionError):
        await api.save_result(state)
