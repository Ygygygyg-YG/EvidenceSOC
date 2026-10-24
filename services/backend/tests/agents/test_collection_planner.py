"""Planner failures and interrupted calls have bounded, explicit outcomes."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any

import pytest
from evidencesoc.agents.collection import BoundedCollector
from evidencesoc.agents.nodes import NodeHandlers
from evidencesoc.config import Settings
from evidencesoc.persistence.tables import InvestigationToolCallTable
from evidencesoc.tools.ledger import AttemptLimitExceeded, BudgetExceeded, Ledger
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

SCOPE = {
    "alert_id": "AL-1",
    "time_from": "2026-09-21T10:05:00+00:00",
    "time_to": "2026-09-21T10:35:00+00:00",
    "filters": {"source_ip": "203.0.113.42"},
    "limit": 100,
}


def collector(ledger: Any = None, model: Any = None) -> BoundedCollector:
    async def invoke(_name: str, _arguments: dict[str, Any]) -> list[dict[str, Any]]:
        raise AssertionError("this test must not invoke an MCP tool")

    return BoundedCollector(
        ledger=ledger,
        invoke=invoke,
        scope=SCOPE,
        state={"incident_id": "IN-1", "alerts": [{"title": "Incident"}]},
        run_id="AR-1",
        model=model,
        llm_mode="deepseek",
    )


def test_rule_lookup_uses_sql_exploitation_intent_for_sqli_alert() -> None:
    planner = collector()
    planner.state = {
        "incident_id": "IN-1",
        "alerts": [{"title": "Task9 SQL injection acceptance"}],
    }
    planner.observations = [
        {"tool_name": "get_alert_context"},
        {"tool_name": "search_security_events"},
    ]
    planner.values = [{"summary": "UNION SELECT probe"}]

    decision = planner._rule()
    assert decision.tool_name == "lookup_attack_technique"
    assert (
        decision.arguments["query"] == "SQL injection exploit public facing application"
    )


@pytest.mark.asyncio
async def test_planner_retries_keep_one_explicit_logical_call_identity():
    seen = []

    class Model:
        async def structured(self, role, schema, current):
            seen.append(current.get("_model_call_id"))
            raise ValueError("invalid response")

    planner = collector(model=Model())
    await planner._plan(1)
    await planner._plan(1)
    assert len(seen) == 6
    assert seen[0] and seen[:3] == [seen[0]] * 3
    assert seen[3] and seen[3:] == [seen[3]] * 3
    assert seen[0] != seen[3]


@pytest.mark.asyncio
async def test_a1_preserves_reserved_slot_and_never_calls_log_tools(memory_ledger):
    from evidencesoc.agents.capabilities import InvestigationCapabilities

    calls = []

    class Model:
        async def structured(self, role, schema, state):
            assert state["collection_context"]["allowed_tools"] == [
                "lookup_attack_technique"
            ]
            return {
                "action": "call",
                "tool_name": "lookup_attack_technique",
                "arguments": {"query": f"query-{len(calls)}", "limit": 8},
                "rationale": "Public knowledge lookup.",
            }

    async def invoke(name, arguments):
        assert name == "lookup_attack_technique"
        calls.append(arguments)
        return [{"knowledge_chunk_id": f"KC-{len(calls)}"}]

    policy = InvestigationCapabilities(
        allowed_tools=frozenset({"lookup_attack_technique"}),
        first_round_reserved_calls=1,
        total_reserved_calls=1,
    )
    first = await BoundedCollector(
        ledger=memory_ledger,
        invoke=invoke,
        scope=SCOPE,
        state={"incident_id": "IN-1"},
        run_id="AR-1",
        model=Model(),
        llm_mode="deepseek",
        capabilities=policy,
    ).run()
    assert len(calls) == 2
    assert first["collection_budget_used"] == 2
    second = await BoundedCollector(
        ledger=memory_ledger,
        invoke=invoke,
        scope=SCOPE,
        state={"incident_id": "IN-1", "fallback_count": 1},
        run_id="AR-1",
        model=Model(),
        llm_mode="deepseek",
        capabilities=policy,
    ).run()
    assert len(calls) == 5
    assert second["collection_budget_used"] == 5
    assert second["collection_reserved_calls"] == 1


def test_reserved_slots_are_enforced_by_atomic_ledger_reservation(memory_ledger):
    protected = memory_ledger.with_reservations(
        first_round_reserved_calls=1, total_reserved_calls=1
    )
    for index in range(2):
        protected.reserve(
            "IN-1",
            "AR-1",
            1,
            "lookup_attack_technique",
            {"query": f"query-{index}"},
            "Knowledge.",
        )
    with pytest.raises(BudgetExceeded):
        protected.reserve(
            "IN-1",
            "AR-1",
            1,
            "lookup_attack_technique",
            {"query": "denied"},
            "Knowledge.",
        )
    for index in range(3):
        protected.reserve(
            "IN-1",
            "AR-1",
            2,
            "lookup_attack_technique",
            {"query": f"round2-{index}"},
            "Knowledge.",
        )
    with pytest.raises(BudgetExceeded):
        protected.reserve(
            "IN-1",
            "AR-1",
            3,
            "lookup_attack_technique",
            {"query": "denied-total"},
            "Knowledge.",
        )
    assert protected.summary("IN-1", 1).round_remaining == 0
    assert protected.summary("IN-1", 3).total_remaining == 0
    assert protected.summary("IN-1", 3).total_used == 5


@pytest.fixture
def memory_ledger() -> Ledger:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    with engine.begin() as connection:
        connection.execute(
            text("CREATE TABLE incidents (incident_id VARCHAR(64) PRIMARY KEY)")
        )
        connection.execute(
            text(
                "CREATE TABLE agent_runs (run_id VARCHAR(64) PRIMARY KEY, incident_id VARCHAR(64))"
            )
        )
        connection.execute(text("INSERT INTO incidents VALUES ('IN-1')"))
        connection.execute(text("INSERT INTO agent_runs VALUES ('AR-1', 'IN-1')"))
    InvestigationToolCallTable.__table__.create(engine)
    try:
        yield Ledger(sessionmaker(engine, expire_on_commit=False))
    finally:
        engine.dispose()


@pytest.mark.asyncio
async def test_model_timeouts_fall_back_to_scoped_rule_plan() -> None:
    class TimeoutModel:
        async def structured(self, *_args: Any) -> Any:
            raise TimeoutError("model stalled")

    planner = collector(model=TimeoutModel())
    decision = await planner._plan(2)
    assert decision.action == "call"
    assert decision.tool_name == "search_security_events"
    assert planner.model_attempts == 3
    assert planner.fallback_used is True
    assert planner.observations[-1]["error_code"] == "MODEL_TIMEOUT"


@pytest.mark.asyncio
async def test_invalid_model_output_records_distinct_fallback_code() -> None:
    class InvalidModel:
        async def structured(self, *_args: Any) -> Any:
            return {"action": "call", "tool_name": None, "rationale": "invalid"}

    planner = collector(model=InvalidModel())
    await planner._plan(2)
    assert planner.observations[-1]["error_code"] == "MODEL_INVALID_OUTPUT"


@pytest.mark.asyncio
async def test_unrecoverable_pending_call_stops_without_new_query() -> None:
    pending = SimpleNamespace(
        call_id="LC-pending",
        fingerprint="pending-fingerprint",
        tool_name="get_alert_context",
        arguments={"alert_id": "AL-1", "before_seconds": 900, "after_seconds": 900},
        status="running",
        attempts=3,
        rationale="Read alert context.",
        error_code=None,
        result=None,
    )

    class FailedRecoveryLedger:
        def __init__(self) -> None:
            self.reserve_calls = 0

        def calls(self, *_args: Any) -> list[Any]:
            return [pending]

        def begin_attempt(self, _call_id: str) -> Any:
            raise AttemptLimitExceeded("already tried three times")

        def fail(self, _call_id: str, error_code: str) -> Any:
            return SimpleNamespace(
                **{**vars(pending), "status": "failed", "error_code": error_code}
            )

        def reserve(self, *_args: Any) -> Any:
            self.reserve_calls += 1
            raise AssertionError("recovery failure must stop before new reservation")

        def summary(self, *_args: Any) -> Any:
            return SimpleNamespace(total_used=1, round_used=1)

    ledger = FailedRecoveryLedger()
    result = await collector(ledger=ledger).run()
    assert result["collection_stop_reason"] == "recovery_failed"
    assert result["collection_budget_used"] == 1
    assert ledger.reserve_calls == 0


@pytest.mark.asyncio
async def test_unrecoverable_collection_routes_to_manual_review() -> None:
    class FailedService:
        async def collect(self, _state: Any, _run_id: str) -> dict[str, Any]:
            return {
                "evidence": [],
                "knowledge": [],
                "collection_stop_reason": "recovery_failed",
            }

    node = NodeHandlers(FailedService(), Settings(_env_file=None, llm_mode="fixture"))
    result = await node.collect({"incident_id": "IN-1", "_run_id": "AR-1"})
    assert result["status"] == "manual_review"
    assert result["stop_reason"] == "recovery_failed"


@pytest.mark.asyncio
async def test_two_empty_queries_stop_with_budget_remaining(
    memory_ledger: Ledger,
) -> None:
    called: list[str] = []

    async def invoke(name: str, _arguments: dict[str, Any]) -> list[dict[str, Any]]:
        called.append(name)
        return []

    planner = collector(ledger=memory_ledger)
    planner.llm_mode = "fixture"
    planner.invoke = invoke
    result = await planner.run()
    assert called == ["get_alert_context", "search_security_events"]
    assert result["collection_round_used"] == 2
    assert result["collection_stop_reason"] == "no_new_evidence"


@pytest.mark.asyncio
async def test_repeated_failed_query_does_not_spend_another_call(
    memory_ledger: Ledger,
) -> None:
    calls: list[str] = []

    class RepeatingModel:
        async def structured(
            self, _role: str, schema: Any, state: dict[str, Any]
        ) -> Any:
            scope = state["collection_context"]["scope"]
            return schema(
                action="call",
                tool_name="search_security_events",
                arguments={
                    key: value for key, value in scope.items() if key != "alert_id"
                },
                rationale="Repeat the same event query.",
            )

    async def invoke(name: str, _arguments: dict[str, Any]) -> list[dict[str, Any]]:
        calls.append(name)
        if name == "search_security_events":
            raise RuntimeError("dependency unavailable")
        return [{"evidence_id": "EV-1"}]

    planner = collector(ledger=memory_ledger, model=RepeatingModel())
    planner.invoke = invoke
    result = await planner.run()
    assert result["collection_round_used"] == 2
    assert calls.count("search_security_events") == 3
    assert result["collection_stop_reason"] == "duplicate_query"


@pytest.mark.asyncio
async def test_concurrent_budget_denial_has_its_own_outcome() -> None:
    class DeniedLedger:
        def reserve(self, *_args: Any) -> Any:
            raise BudgetExceeded("another worker spent the remaining call")

    planner = collector(ledger=DeniedLedger())
    outcome = await planner._call(
        "get_alert_context",
        {"alert_id": "AL-1", "before_seconds": 900, "after_seconds": 900},
        "Read alert context.",
    )
    assert outcome == "budget_exhausted"


@pytest.mark.asyncio
async def test_interrupted_call_recovers_with_same_logical_budget(
    memory_ledger: Ledger,
) -> None:
    invoked: list[str] = []

    async def invoke(name: str, _arguments: dict[str, Any]) -> list[dict[str, Any]]:
        invoked.append(name)
        if len(invoked) == 1:
            raise asyncio.CancelledError()
        if name == "lookup_attack_technique":
            return [{"knowledge_chunk_id": "KC-1"}]
        return [{"evidence_id": "EV-1"}]

    first = collector(ledger=memory_ledger)
    first.llm_mode = "fixture"
    first.invoke = invoke
    with pytest.raises(asyncio.CancelledError):
        await first.run()

    recovered = collector(ledger=memory_ledger)
    recovered.llm_mode = "fixture"
    recovered.invoke = invoke
    result = await recovered.run()
    assert result["collection_round_used"] == 3
    assert result["collection_tool_attempts"] == 4
    assert invoked.count("get_alert_context") == 2
    assert len(result["collection_ledger_ids"]) == 3

    replay = collector(ledger=memory_ledger)
    replay.llm_mode = "fixture"
    replay.invoke = invoke
    await replay.run()
    assert len(invoked) == 4


@pytest.mark.asyncio
async def test_next_round_accounts_for_prior_unfinished_call(
    memory_ledger: Ledger,
) -> None:
    invocations: list[str] = []

    async def invoke(name: str, _arguments: dict[str, Any]) -> list[dict[str, Any]]:
        invocations.append(name)
        if len(invocations) == 1:
            raise asyncio.CancelledError()
        if name == "lookup_attack_technique":
            return [{"knowledge_chunk_id": "KC-1"}]
        return [{"evidence_id": "EV-1"}]

    initial = collector(ledger=memory_ledger)
    initial.llm_mode = "fixture"
    initial.invoke = invoke
    with pytest.raises(asyncio.CancelledError):
        await initial.run()
    pending_id = memory_ledger.calls("IN-1", 1)[0].call_id

    next_round = BoundedCollector(
        ledger=memory_ledger,
        invoke=invoke,
        scope=SCOPE,
        state={
            "incident_id": "IN-1",
            "fallback_count": 1,
            "alerts": [{"title": "Incident"}],
        },
        run_id="AR-1",
        model=None,
        llm_mode="fixture",
    )
    result = await next_round.run()
    assert result["collection_round"] == 2
    assert result["collection_budget_used"] == 3
    assert result["collection_round_used"] == 2
    assert pending_id in result["collection_ledger_ids"]
    assert result["collection_tool_attempts"] == 4


@pytest.mark.asyncio
async def test_next_round_recovers_prior_call_before_planner_can_stop(
    memory_ledger: Ledger,
) -> None:
    seed = memory_ledger.reserve(
        "IN-1",
        "AR-1",
        1,
        "get_alert_context",
        {"alert_id": "AL-1", "before_seconds": 900, "after_seconds": 900},
        "Read alert context.",
    )
    memory_ledger.begin_attempt(seed.call_id)
    memory_ledger.complete(seed.call_id, {"values": [{"evidence_id": "EV-1"}]})
    pending = memory_ledger.reserve(
        "IN-1",
        "AR-1",
        1,
        "search_security_events",
        {key: value for key, value in SCOPE.items() if key != "alert_id"},
        "Search events.",
    )
    memory_ledger.begin_attempt(pending.call_id)
    calls: list[str] = []

    async def invoke(name: str, _arguments: dict[str, Any]) -> list[dict[str, Any]]:
        calls.append(name)
        return [{"evidence_id": "EV-2"}]

    class StopModel:
        async def structured(self, _role: str, schema: Any, _state: Any) -> Any:
            return schema(action="stop", rationale="Enough evidence.")

    planner = BoundedCollector(
        ledger=memory_ledger,
        invoke=invoke,
        scope=SCOPE,
        state={"incident_id": "IN-1", "fallback_count": 1, "alerts": []},
        run_id="AR-1",
        model=StopModel(),
        llm_mode="deepseek",
    )
    result = await planner.run()
    assert calls == ["search_security_events"]
    assert memory_ledger.calls("IN-1", 1)[1].status == "completed"
    assert pending.call_id in result["collection_ledger_ids"]
    assert result["collection_budget_used"] == 2
    assert result["collection_stop_reason"] == "planner_stopped"


@pytest.mark.asyncio
async def test_second_round_rule_skips_completed_queries_and_uses_old_results(
    memory_ledger: Ledger,
) -> None:
    for name, arguments in (
        (
            "get_alert_context",
            {"alert_id": "AL-1", "before_seconds": 900, "after_seconds": 900},
        ),
        (
            "search_security_events",
            {key: value for key, value in SCOPE.items() if key != "alert_id"},
        ),
    ):
        row = memory_ledger.reserve("IN-1", "AR-1", 1, name, arguments, "First round.")
        memory_ledger.begin_attempt(row.call_id)
        memory_ledger.complete(row.call_id, {"values": []})

    invoked: list[str] = []

    async def invoke(name: str, _arguments: dict[str, Any]) -> list[dict[str, Any]]:
        invoked.append(name)
        assert name == "lookup_attack_technique"
        return [{"knowledge_chunk_id": "KC-1"}]

    planner = BoundedCollector(
        ledger=memory_ledger,
        invoke=invoke,
        scope=SCOPE,
        state={
            "incident_id": "IN-1",
            "fallback_count": 1,
            "alerts": [{"title": "Incident"}],
        },
        run_id="AR-1",
        model=None,
        llm_mode="fixture",
    )
    result = await planner.run()
    assert invoked == ["lookup_attack_technique"]
    assert result["knowledge"] == [{"knowledge_chunk_id": "KC-1"}]
    assert result["collection_round_used"] == 1
    assert result["collection_stop_reason"] == "planner_stopped"


@pytest.mark.asyncio
async def test_second_round_reused_seed_does_not_advance_no_new_streak(
    memory_ledger: Ledger,
) -> None:
    for name, arguments in (
        (
            "get_alert_context",
            {"alert_id": "AL-1", "before_seconds": 900, "after_seconds": 900},
        ),
        (
            "search_security_events",
            {key: value for key, value in SCOPE.items() if key != "alert_id"},
        ),
    ):
        row = memory_ledger.reserve("IN-1", "AR-1", 1, name, arguments, "First round.")
        memory_ledger.begin_attempt(row.call_id)
        memory_ledger.complete(row.call_id, {"values": []})

    invoked: list[str] = []

    async def invoke(name: str, _arguments: dict[str, Any]) -> list[dict[str, Any]]:
        invoked.append(name)
        return []

    planner = BoundedCollector(
        ledger=memory_ledger,
        invoke=invoke,
        scope=SCOPE,
        state={"incident_id": "IN-1", "fallback_count": 1, "alerts": []},
        run_id="AR-1",
        model=None,
        llm_mode="fixture",
    )
    result = await planner.run()
    assert invoked == ["lookup_attack_technique"]
    assert planner.no_new_streak == 1
    assert result["collection_stop_reason"] == "planner_stopped"


@pytest.mark.asyncio
async def test_second_round_model_sees_completed_prior_round_results(
    memory_ledger: Ledger,
) -> None:
    prior_values = (
        ("get_alert_context", {"evidence_id": "EV-SEED", "summary": "Prior alert"}),
        (
            "search_security_events",
            {"evidence_id": "EV-SEARCH", "summary": "Prior event search"},
        ),
    )
    for name, value in prior_values:
        arguments = (
            {"alert_id": "AL-1", "before_seconds": 900, "after_seconds": 900}
            if name == "get_alert_context"
            else {key: item for key, item in SCOPE.items() if key != "alert_id"}
        )
        row = memory_ledger.reserve("IN-1", "AR-1", 1, name, arguments, "First round.")
        memory_ledger.begin_attempt(row.call_id)
        memory_ledger.complete(row.call_id, {"values": [value]})

    contexts: list[dict[str, Any]] = []

    class InspectModel:
        async def structured(
            self, _role: str, schema: Any, state: dict[str, Any]
        ) -> Any:
            contexts.append(state["collection_context"])
            return schema(
                action="stop", rationale="Prior evidence already covers the gap."
            )

    async def invoke(_name: str, _arguments: dict[str, Any]) -> list[dict[str, Any]]:
        raise AssertionError("completed prior calls must not be physically retried")

    planner = BoundedCollector(
        ledger=memory_ledger,
        invoke=invoke,
        scope=SCOPE,
        state={"incident_id": "IN-1", "fallback_count": 1, "alerts": []},
        run_id="AR-1",
        model=InspectModel(),
        llm_mode="deepseek",
    )
    result = await planner.run()
    assert len(contexts) == 1
    assert {item["tool_name"] for item in contexts[0]["observations"]} >= {
        "get_alert_context",
        "search_security_events",
    }
    assert {item["evidence_id"] for item in contexts[0]["evidence_summaries"]} == {
        "EV-SEED",
        "EV-SEARCH",
    }
    assert {item["evidence_id"] for item in result["evidence_values"]} == {
        "EV-SEED",
        "EV-SEARCH",
    }
    assert planner.no_new_streak == 0
    assert result["collection_round_used"] == 0
    assert result["collection_stop_reason"] == "planner_stopped"


@pytest.mark.asyncio
async def test_second_round_rule_can_retry_a_failed_prior_query(
    memory_ledger: Ledger,
) -> None:
    seed = memory_ledger.reserve(
        "IN-1",
        "AR-1",
        1,
        "get_alert_context",
        {"alert_id": "AL-1", "before_seconds": 900, "after_seconds": 900},
        "First round.",
    )
    memory_ledger.begin_attempt(seed.call_id)
    memory_ledger.complete(seed.call_id, {"values": []})
    failed = memory_ledger.reserve(
        "IN-1",
        "AR-1",
        1,
        "search_security_events",
        {key: value for key, value in SCOPE.items() if key != "alert_id"},
        "First round.",
    )
    memory_ledger.fail(failed.call_id, "DEPENDENCY_UNAVAILABLE")

    invoked: list[str] = []

    async def invoke(name: str, _arguments: dict[str, Any]) -> list[dict[str, Any]]:
        invoked.append(name)
        if name == "lookup_attack_technique":
            return [{"knowledge_chunk_id": "KC-1"}]
        return [{"evidence_id": "EV-1"}]

    planner = BoundedCollector(
        ledger=memory_ledger,
        invoke=invoke,
        scope=SCOPE,
        state={
            "incident_id": "IN-1",
            "fallback_count": 1,
            "alerts": [{"title": "Incident"}],
        },
        run_id="AR-1",
        model=None,
        llm_mode="fixture",
    )
    await planner.run()
    assert invoked[0] == "search_security_events"


@pytest.mark.asyncio
async def test_model_receives_actual_server_tool_schemas_and_search_contract() -> None:
    from evidencesoc.agents.capabilities import InvestigationCapabilities
    from evidencesoc.mcp_server.context import RunContext
    from evidencesoc.mcp_server.main import create_server

    seen: list[dict[str, Any]] = []

    class InspectModel:
        async def structured(self, _role: str, schema: Any, state: dict) -> Any:
            seen.append(state["collection_context"])
            return schema(action="stop", rationale="Recorded stop.")

    planner = collector(model=InspectModel())
    planner.capabilities = InvestigationCapabilities(
        allowed_tools=frozenset({"search_security_events"}), rag_mode="disabled"
    )
    await planner._plan(2)
    # Metadata discovery must not require business dependencies or execute a tool.
    server = create_server(
        context=RunContext("AR-1", "IN-1", "TRACE-schema"),
        boundary_audit=SimpleNamespace(
            record=lambda _row: pytest.fail("audit invoked")
        ),
        event_tools=SimpleNamespace(),
        alert_tools=SimpleNamespace(),
        attack_tools=SimpleNamespace(),
    )
    actual = {tool.name: tool for tool in await server.list_tools()}
    assert "tool_schemas" in seen[0]
    supplied = seen[0]["tool_schemas"]
    assert [tool["name"] for tool in supplied] == ["search_security_events"]
    assert supplied[0]["inputSchema"] == actual["search_security_events"].inputSchema
    assert seen[0]["required_search_arguments"] == [
        "time_from",
        "time_to",
        "filters",
        "limit",
    ]
    assert seen[0]["scope"] == SCOPE
    assert seen[0]["remaining_logical_calls"] == 2


# Recorded request 3127051e-066f-4d1f-934f-fe7bce27b45a from the immutable
# dedale/row-0be1c35fa8f8c957a3276881/attempt-001/result.json, SHA256
# 402728df481117965bdaa3218f83749e802d86546d57bf0823001b3d8d4bdffc.
# Identifiers/host/dataset are replaced; the original extra alert_id, timestamps,
# argument structure, and limit are retained. No endpoint or model is used.
RECORDED_SEARCH_SCOPE = {
    "alert_id": "AL-1",
    "time_from": "2025-01-06T09:47:25.097000+00:00",
    "time_to": "2025-01-06T10:17:25.097000+00:00",
    "filters": {"host": "client.example.test", "dataset_id": "dedale-v2.1:recorded"},
    "limit": 100,
}


@pytest.mark.asyncio
async def test_recorded_extra_alert_id_is_rejected_before_any_physical_call(
    memory_ledger: Ledger,
) -> None:
    planner = collector(ledger=memory_ledger)
    planner.scope = RECORDED_SEARCH_SCOPE
    outcome = await planner._call(
        "search_security_events", dict(RECORDED_SEARCH_SCOPE), "Recorded search gap."
    )
    assert outcome == "policy_denied"
    row = memory_ledger.calls("IN-1", 1)[0]
    assert row.status == "failed"
    assert row.error_code == "POLICY_ARGUMENTS_INVALID"
    assert row.attempts == 0
    assert row.charged is True


@pytest.mark.asyncio
async def test_recorded_search_can_be_legally_replayed_using_supplied_contract(
    memory_ledger: Ledger,
) -> None:
    contexts: list[dict] = []
    invoked: list[tuple[str, dict]] = []

    class RecordedModel:
        async def structured(self, _role: str, schema: Any, state: dict) -> Any:
            context = state["collection_context"]
            contexts.append(context)
            if len(contexts) > 1:
                return schema(
                    action="stop", rationale="Recorded evidence gap resolved."
                )
            search = next(
                tool
                for tool in context.get("tool_schemas", [])
                if tool["name"] == "search_security_events"
            )
            keys = context["required_search_arguments"]
            assert set(keys) == set(search["inputSchema"]["properties"])
            return schema(
                action="call",
                tool_name="search_security_events",
                arguments={key: context["scope"][key] for key in keys},
                rationale="Recorded search gap with the published tool contract.",
            )

    async def invoke(name: str, arguments: dict) -> list[dict]:
        invoked.append((name, arguments))
        return [{"evidence_id": f"EV-{len(invoked)}"}]

    planner = collector(ledger=memory_ledger, model=RecordedModel())
    planner.scope = RECORDED_SEARCH_SCOPE
    planner.invoke = invoke
    result = await planner.run()
    assert result["fallback_used"] is False
    assert [name for name, _args in invoked] == [
        "get_alert_context",
        "search_security_events",
    ]
    assert invoked[1][1] == {
        key: value for key, value in RECORDED_SEARCH_SCOPE.items() if key != "alert_id"
    }
    assert result["collection_stop_reason"] == "planner_stopped"
    assert result["collection_refusal_codes"] == []
    assert result["collection_round_used"] == 2
    assert result["collection_tool_attempts"] == 2
    assert result["collection_model_attempts"] == 2


@pytest.mark.asyncio
async def test_report_keeps_refusal_separate_from_later_planner_stop(
    memory_ledger: Ledger,
) -> None:
    class StopModel:
        async def structured(self, _role: str, schema: Any, _state: dict) -> Any:
            return schema(action="stop", rationale="Recorded reason for stopping.")

    async def invoke(_name: str, _arguments: dict) -> list[dict]:
        return [{"evidence_id": "EV-1"}]

    planner = collector(ledger=memory_ledger, model=StopModel())
    planner.invoke = invoke
    await planner._call(
        "search_security_events", dict(SCOPE), "Malformed recorded call."
    )
    result = await planner.run()
    assert result["collection_stop_reason"] == "planner_stopped"
    assert result.get("collection_refusal_codes") == ["POLICY_ARGUMENTS_INVALID"]
    assert result["collection_observations"][-1] == {
        "status": "planner_stopped",
        "rationale": "Recorded reason for stopping.",
    }


@pytest.mark.asyncio
async def test_empty_seed_then_denied_arguments_can_be_corrected_in_original_budget(memory_ledger):
    calls, plans = [], []

    class CorrectingModel:
        async def structured(self, _role, schema, state):
            plans.append(state)
            scope = state["collection_context"]["scope"]
            arguments = dict(scope) if len(plans) == 1 else {
                key: scope[key] for key in ("time_from", "time_to", "filters", "limit")
            }
            return schema(action="call", tool_name="search_security_events",
                          arguments=arguments, rationale="Correct the bounded query.")

    async def invoke(name, arguments):
        calls.append((name, arguments))
        return [] if name == "get_alert_context" else [{"evidence_id": "EV-corrected"}]

    planner = collector(ledger=memory_ledger, model=CorrectingModel())
    planner.invoke = invoke
    result = await planner.run()
    assert len(plans) == 2
    assert [name for name, _ in calls] == ["get_alert_context", "search_security_events"]
    assert result["collection_round_used"] == 3
    assert result["collection_refusal_codes"] == ["POLICY_ARGUMENTS_INVALID"]
    assert result["collection_stop_reason"] == "budget_exhausted"
    assert result["evidence_values"] == [{"evidence_id": "EV-corrected"}]
