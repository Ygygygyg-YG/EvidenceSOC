from __future__ import annotations

import asyncio
import importlib
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import pytest
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
    InvestigationToolCallTable,
    ResponsePlanTable,
    SecurityEventTable,
    ValidationResultTable,
)
from sqlalchemy import JSON, CheckConstraint, MetaData, create_engine, func, select
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import sessionmaker

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
        InvestigationToolCallTable,
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


def test_collection_scope_keeps_ait_scenario_inside_a_shared_index(
    database: Any,
) -> None:
    with database[0]() as session:
        event = session.get(SecurityEventTable, "SE-1")
        event.raw = {**event.raw, "dataset_id": "ait-v2.1:shaw"}
        event.content_sha256 = calculate_content_sha256(event.raw)
        session.commit()

    scope = service(database)._scope("IN-1")
    assert scope["filters"] == {
        "source_ip": "203.0.113.42",
        "host": "shop.example.test",
        "service": "checkout-api",
        "dataset_id": "ait-v2.1:shaw",
    }


def test_collection_scope_rejects_mixed_ait_scenarios(database: Any) -> None:
    with database[0]() as session:
        first = session.get(SecurityEventTable, "SE-1")
        first.raw = {**first.raw, "dataset_id": "ait-v2.1:shaw"}
        first.content_sha256 = calculate_content_sha256(first.raw)
        second_raw = {**first.raw, "dataset_id": "ait-v2.1:wilson"}
        session.add(
            SecurityEventTable(
                event_id="SE-2",
                source="nginx",
                external_id="request-2",
                deduplication_key="id:request-2",
                observed_at=NOW,
                ingested_at=NOW,
                severity="high",
                event_type="web.request",
                raw=second_raw,
                content_sha256=calculate_content_sha256(second_raw),
                index_status="indexed",
            )
        )
        session.get(AlertTable, "AL-1").event_ids = ["SE-1", "SE-2"]
        session.commit()

    with pytest.raises(PermissionError, match="dataset"):
        service(database)._scope("IN-1")


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
async def test_renewed_response_preserves_both_agent_run_records(database: Any) -> None:
    api = service(database)
    state = {"incident_id": "IN-1", "trace_id": "TRACE-renew", "fallback_count": 0}
    original = await api.start_run(state, "respond")
    await api.finish_run(
        original, {"response_plan": {"evidence_ids": [database[1].evidence_id]}}
    )
    renewed = await api.start_run({**state, "plan_generation": 1}, "respond")
    await api.finish_run(renewed, {})

    with database[0]() as session:
        rows = session.scalars(
            select(AgentRunTable).where(
                AgentRunTable.incident_id == "IN-1",
                AgentRunTable.agent_name == "respond",
            )
        ).all()
        assert renewed != original
        assert len(rows) == 2
        first = session.get(AgentRunTable, original)
        assert first.status == "completed"
        assert first.evidence_ids == [database[1].evidence_id]


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
    state = {"incident_id": "IN-1", "trace_id": "TRACE-1", "fallback_count": 0}
    run_id = await api.start_run(state, "collect")
    result = await api.collect(state, run_id)
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
    assert result["collection_budget_used"] == 3
    assert result["collection_round"] == 1
    assert len(result["collection_ledger_ids"]) == 3

    replay = await api.collect(state, run_id)
    assert len(calls) == 3
    assert replay["evidence"] == result["evidence"]
    assert replay["knowledge"] == result["knowledge"]
    assert replay["collection_budget_used"] == 3

    await api.finish_run(run_id, result)
    with database[0]() as session:
        summary = session.get(AgentRunTable, run_id).output_summary
    assert summary is not None
    assert summary["collection_round"] == 1
    assert summary["collection_budget_used"] == 3
    assert summary["collection_round_used"] == 3
    assert summary["collection_tool_attempts"] == 3
    assert summary["collection_model_attempts"] == 0
    assert summary["fallback_used"] is True
    assert summary["collection_stop_reason"] == "budget_exhausted"
    assert summary["collection_ledger_ids"] == result["collection_ledger_ids"]
    assert [item["rationale"] for item in summary["collection_observations"]] == [
        item["rationale"] for item in result["collection_observations"]
    ]
    assert "evidence" not in summary

    second_state = {**state, "fallback_count": 1}
    second_run = await api.start_run(second_state, "collect")
    second = await api.collect(second_state, second_run)
    assert len(calls) == 3
    assert second["collection_budget_used"] == 3


@pytest.mark.asyncio
async def test_model_planner_denial_consumes_budget_without_cross_incident_call(
    database: Any, monkeypatch: Any
) -> None:
    module = importlib.import_module("evidencesoc.agents.services")
    api = module.PostgresWorkflowServices(
        Settings(_env_file=None, llm_mode="deepseek"),
        session_factory=database[0],
    )
    evidence = database[1].model_dump(mode="json")
    tool_calls: list[str] = []

    class Model:
        def __init__(self) -> None:
            self.calls = 0

        async def structured(
            self, role: str, schema: Any, state: dict[str, Any]
        ) -> Any:
            assert role == "collect"
            assert "labels" not in str(state)
            self.calls += 1
            scope = state["collection_context"]["scope"]
            if self.calls == 1:
                return schema(
                    action="call",
                    tool_name="get_alert_context",
                    arguments={"alert_id": "AL-other"},
                    rationale="Try a different alert.",
                )
            return schema(
                action="call",
                tool_name="search_security_events",
                arguments={
                    key: value for key, value in scope.items() if key != "alert_id"
                },
                rationale="Search the incident scope.",
            )

    class Session:
        async def list_tools(self) -> Any:
            return SimpleNamespace(
                tools=[
                    SimpleNamespace(name=name)
                    for name in (
                        "get_alert_context",
                        "search_security_events",
                        "lookup_attack_technique",
                    )
                ]
            )

        async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
            tool_calls.append(name)
            return SimpleNamespace(
                isError=False, structuredContent={"result": [evidence]}
            )

    @asynccontextmanager
    async def open_session(*args: Any, **kwargs: Any) -> Any:
        yield Session()

    monkeypatch.setattr(module, "open_stdio_session", open_session)
    api.planner_model = Model()
    state = {"incident_id": "IN-1", "trace_id": "TRACE-model", "fallback_count": 0}
    run_id = await api.start_run(state, "collect")
    result = await api.collect(state, run_id)
    assert tool_calls == ["get_alert_context", "search_security_events"]
    assert result["collection_budget_used"] == 3
    assert any(
        item.get("error_code") == "POLICY_DENIED"
        for item in result["collection_observations"]
    )
    assert result["collection_stop_reason"] == "budget_exhausted"


@pytest.mark.asyncio
async def test_collect_resumes_incomplete_seed_without_new_logical_charge(
    database: Any, monkeypatch: Any
) -> None:
    module = importlib.import_module("evidencesoc.agents.services")
    evidence = database[1].model_dump(mode="json")
    calls: list[str] = []

    class Session:
        async def list_tools(self) -> Any:
            return SimpleNamespace(
                tools=[
                    SimpleNamespace(name=name)
                    for name in (
                        "get_alert_context",
                        "search_security_events",
                        "lookup_attack_technique",
                    )
                ]
            )

        async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
            calls.append(name)
            if len(calls) == 1:
                raise asyncio.CancelledError()
            return SimpleNamespace(
                isError=False,
                structuredContent={
                    "result": [] if name == "lookup_attack_technique" else [evidence]
                },
            )

    @asynccontextmanager
    async def open_session(*args: Any, **kwargs: Any) -> Any:
        yield Session()

    monkeypatch.setattr(module, "open_stdio_session", open_session)
    state = {
        "incident_id": "IN-1",
        "trace_id": "TRACE-recover-seed",
        "fallback_count": 0,
    }
    first = service(database)
    run_id = await first.start_run(state, "collect")
    with pytest.raises(asyncio.CancelledError):
        await first.collect(state, run_id)

    recovered = service(database)
    result = await recovered.collect(state, run_id)
    assert calls.count("get_alert_context") == 2
    assert result["collection_budget_used"] == 3
    assert result["collection_tool_attempts"] == 4
    assert len(result["collection_ledger_ids"]) == 3


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
    run_id = await api.start_run(state, "validate")
    empty_result = await api.verify(state, run_id)
    assert empty_result["evidence"] == []
    assert empty_result["executed_checks"][0]["evidence_ids"] == []
    assert empty_result["executed_checks"][0]["condition"]["filters"] == {
        "source_ip": "203.0.113.42",
        "host": "shop.example.test",
        "service": "checkout-api",
    }
    assert empty_result["verification_call_count"] == 1
    assert empty_result["verification_attempts"] == 1
    failed = True
    failed_state = {**state, "trace_id": "TRACE-verify-failed"}
    failed_run = await api.start_run(failed_state, "validate")
    with pytest.raises(RuntimeError, match="DEPENDENCY_TIMEOUT"):
        await api.verify(failed_state, failed_run)


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
                structuredContent={
                    "result": [database[1].model_dump(mode="json")]
                    if len(calls) == 1
                    else []
                },
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
    state = verification_state(database, [first, first, second])
    state["response_plan"]["validation_checks"] = [
        {
            "check_id": f"VC-{index}",
            "description": "Requery the observed source.",
            "target": "203.0.113.42",
            "expected_result": "Compare fresh evidence.",
            "query": query,
            "evidence_ids": [database[1].evidence_id],
        }
        for index, query in enumerate((first, first, second), start=1)
    ]
    run_id = await api.start_run(state, "validate")
    result = await api.verify(state, run_id)
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
    assert [check["check_id"] for check in result["executed_checks"]] == [
        "VC-1",
        "VC-2",
        "VC-3",
    ]
    assert result["executed_checks"][0]["condition"] == calls[0]
    assert result["executed_checks"][1]["evidence_ids"] == [database[1].evidence_id]
    assert result["executed_checks"][2]["condition"] == calls[1]
    assert result["executed_checks"][2]["evidence_ids"] == []
    assert result["verification_call_count"] == 2
    assert result["verification_attempts"] == 2


@pytest.mark.asyncio
async def test_verify_uses_each_alert_source_for_two_cited_targets(
    database: Any, monkeypatch: Any
) -> None:
    api = service(database)
    module = importlib.import_module("evidencesoc.agents.services")
    other_raw = {
        "source_ip": "203.0.113.43",
        "host": "other.example.test",
        "service": "checkout-api",
    }
    other_evidence = EvidenceItem(
        evidence_id=new_evidence_id(),
        event_id="SE-2",
        source="nginx",
        observed_at=NOW,
        query={"matched_event_id": "SE-2"},
        summary="Verified second source",
        content_sha256=calculate_content_sha256(other_raw),
    )
    with database[0].begin() as session:
        alert = session.get(AlertTable, "AL-1")
        alert.event_ids = [*alert.event_ids, "SE-2"]
        session.add(
            SecurityEventTable(
                event_id="SE-2",
                source="nginx",
                external_id="request-2",
                deduplication_key="id:request-2",
                observed_at=NOW,
                ingested_at=NOW,
                severity="high",
                event_type="web.request",
                raw=other_raw,
                content_sha256=calculate_content_sha256(other_raw),
                index_status="indexed",
            )
        )
        session.add(
            EvidenceItemTable(**other_evidence.model_dump(), incident_id="IN-1")
        )

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
            evidence = (
                database[1]
                if arguments["filters"]["source_ip"] == "203.0.113.42"
                else other_evidence
            )
            return SimpleNamespace(
                isError=False,
                structuredContent={"result": [evidence.model_dump(mode="json")]},
            )

    @asynccontextmanager
    async def open_session(*args: Any, **kwargs: Any) -> Any:
        yield Session()

    monkeypatch.setattr(module, "open_stdio_session", open_session)
    state = verification_state(
        database,
        [
            {"filters": {"source_ip": "203.0.113.42"}, "limit": 10},
            {"filters": {"source_ip": "203.0.113.43"}, "limit": 10},
        ],
    )
    state["response_plan"]["actions"][1]["target"] = "203.0.113.43"
    state["response_plan"]["actions"][1]["evidence_ids"] = [other_evidence.evidence_id]
    state["response_plan"]["evidence_ids"].append(other_evidence.evidence_id)

    run_id = await api.start_run(state, "validate")
    result = await api.verify(state, run_id)
    assert len(calls) == 2
    assert [call["filters"]["host"] for call in calls] == [
        "shop.example.test",
        "other.example.test",
    ]
    assert all(call["limit"] <= 100 for call in calls)
    assert all(
        call["time_from"] == "2026-09-21T10:05:00+00:00"
        and call["time_to"] == "2026-09-21T10:35:00+00:00"
        for call in calls
    )
    assert [check["evidence_ids"] for check in result["executed_checks"]] == [
        [database[1].evidence_id],
        [other_evidence.evidence_id],
    ]


@pytest.mark.asyncio
async def test_verify_rejects_target_absent_from_alert_source_events(
    database: Any, monkeypatch: Any
) -> None:
    api = service(database)
    module = importlib.import_module("evidencesoc.agents.services")

    def forbidden_session(*args: Any, **kwargs: Any) -> Any:
        pytest.fail("unobserved target must be rejected before opening MCP")

    monkeypatch.setattr(module, "open_stdio_session", forbidden_session)
    state = verification_state(database, [{"filters": {"source_ip": "198.51.100.99"}}])
    state["response_plan"]["actions"][0]["target"] = "198.51.100.99"
    with pytest.raises(PermissionError, match="not observed"):
        await api.verify(state, "AR-1")


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
        {"filters": {"source_ip": "203.0.113.42", "dataset_id": "other-scenario"}},
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
            "actions": [
                {
                    "action": "block_ip_simulated",
                    "target": "203.0.113.42",
                    "risk": "Source IP may be shared",
                    "impact": "Simulation only",
                    "preview": "Simulate blocking the observed source",
                    "rollback": "Remove the simulated block",
                    "verification_query": {"filters": {"source_ip": "203.0.113.42"}},
                }
            ],
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
            "time_from": (NOW.replace(minute=19)).isoformat(),
            "time_to": NOW.isoformat(),
            "checks": [
                {
                    "check_id": "VC-1",
                    "condition": {
                        "time_from": (NOW.replace(minute=19)).isoformat(),
                        "time_to": NOW.isoformat(),
                        "filters": {"source_ip": "203.0.113.42"},
                        "limit": 10,
                    },
                    "outcome": "success",
                    "evidence_ids": [evidence_id],
                    "explanation": "Fresh target evidence matched.",
                }
            ],
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
        validation = session.get(ValidationResultTable, "VR-1")
        assert validation.time_from.replace(tzinfo=UTC) == NOW.replace(minute=19)
        assert validation.checks[0]["check_id"] == "VC-1"
    state["response_plan"]["incident_id"] = "IN-2"
    with pytest.raises(PermissionError):
        await api.save_result(state)
