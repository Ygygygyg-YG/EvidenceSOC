"""Task 12 residual acceptance against PostgreSQL, OpenSearch and stdio MCP.

Only benign synthetic records are used. The retry cases disconnect a real TCP
connection before forwarding subsequent requests to the actual OpenSearch node.
No API, repository or MCP response is replaced by a fixture response.
"""

from __future__ import annotations

import json
import os
import socket
import threading
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import httpx
import pytest
from evidencesoc.agents.collection import BoundedCollector
from evidencesoc.agents.services import PostgresWorkflowServices
from evidencesoc.config import BACKEND_ROOT, Settings
from evidencesoc.ids import new_ulid
from evidencesoc.ingestion.normalize import calculate_content_sha256
from evidencesoc.ingestion.service import IngestionService
from evidencesoc.mcp_server.client import open_stdio_session
from evidencesoc.mcp_server.context import RunContext
from evidencesoc.persistence.database import (
    create_database_engine,
    create_session_factory,
)
from evidencesoc.persistence.event_repository import EventRepository
from evidencesoc.persistence.event_search import (
    OpenSearchEventStore,
    create_opensearch_client,
)
from evidencesoc.persistence.tables import (
    AgentRunTable,
    AlertTable,
    IncidentTable,
    SecurityEventTable,
    ToolCallTable,
)
from evidencesoc.tools.ledger import BudgetExceeded, Ledger
from evidencesoc.tools.policy import ALLOWED_TOOLS
from sqlalchemy import delete, select

pytestmark = pytest.mark.skipif(
    os.getenv("EVIDENCESOC_TEST_POSTGRES") != "1"
    or os.getenv("EVIDENCESOC_TEST_OPENSEARCH") != "1",
    reason="explicit isolated PostgreSQL/OpenSearch/MCP acceptance",
)


@dataclass
class LiveScope:
    settings: Settings
    sessions: Any
    search: Any
    events: list[str]
    incidents: list[str]
    alerts: list[str]
    runs: list[str]
    scope: dict[str, Any]
    initial_import: Any
    repeated_import: Any

    @property
    def context(self) -> RunContext:
        return self.context_for_run(0)

    def context_for_run(self, number: int) -> RunContext:
        return RunContext(self.runs[number], self.incidents[0], "TRACE-" + new_ulid())

    def collector(self, session: Any, *, round_no: int = 1) -> BoundedCollector:
        return BoundedCollector(
            ledger=Ledger(self.sessions),
            invoke=lambda name, arguments: PostgresWorkflowServices._call(
                session, name, arguments
            ),
            scope=self.scope,
            state={"incident_id": self.incidents[0], "fallback_count": round_no - 1},
            run_id=self.runs[min(round_no - 1, 2)],
            model=None,
            llm_mode="fixture",
        )


@pytest.fixture
def live_scope(tmp_path: Path) -> Iterator[LiveScope]:
    suffix = new_ulid()
    index = "security-events-task12-" + suffix.lower()
    settings = Settings(opensearch_index=index)
    engine = create_database_engine(settings.database_url)
    assert engine.dialect.name == "postgresql", "live acceptance requires PostgreSQL"
    sessions = create_session_factory(engine)
    search = create_opensearch_client(settings.opensearch_url)
    incidents = ["IN-" + new_ulid(), "IN-" + new_ulid()]
    alerts = ["AL-" + new_ulid(), "AL-" + new_ulid()]
    runs = ["AR-" + new_ulid() for _ in range(4)]
    events: list[str] = []
    source = "task12-" + suffix.lower()
    at = datetime(2026, 9, 21, 12, 0, tzinfo=UTC)
    path = tmp_path / "benign-events.jsonl"
    raws = [
        {
            "source": source,
            "external_id": f"benign-{offset}",
            "observed_at": at.isoformat(),
            "event_type": "host.health",
            "severity": "info",
            "host": "same-host.example.test",
            "source_ip": "203.0.113.15",
            "dataset_id": "task12:" + suffix + (":a" if offset < 2 else ":b"),
            "message": "Routine benign service health check",
        }
        for offset in range(3)
    ]
    path.write_text("".join(json.dumps(raw) + "\n" for raw in raws), encoding="utf-8")
    try:
        template = json.loads(
            (
                BACKEND_ROOT.parents[1]
                / "infra/opensearch/security-events-template.json"
            ).read_text(encoding="utf-8")
        )
        search.indices.create(index=index, body=template["template"])
        with sessions() as session:
            importer = IngestionService(
                EventRepository(session), OpenSearchEventStore(search, index_name=index)
            )
            first = importer.import_file(path)
            events.extend(first.event_ids)
            repeated = importer.import_file(path)
        assert first.inserted == first.indexed == 3
        assert repeated.duplicated == 3 and repeated.indexed == 0
        assert repeated.event_ids == events
        search.indices.refresh(index=index)
        with sessions() as session, session.begin():
            for number in range(2):
                session.add(
                    AlertTable(
                        alert_id=alerts[number],
                        title="Benign health check",
                        severity="info",
                        created_at=at,
                        event_ids=events[:2] if number == 0 else events[2:],
                    )
                )
            session.flush()
            for number in range(2):
                session.add(
                    IncidentTable(
                        incident_id=incidents[number],
                        alert_id=alerts[number],
                        status="received",
                        created_at=at,
                    )
                )
            session.flush()
            for number, run in enumerate(runs):
                session.add(
                    AgentRunTable(
                        run_id=run,
                        incident_id=incidents[0 if number < 3 else 1],
                        agent_name="validate" if number == 2 else "collect",
                        status="running",
                        started_at=at,
                        evidence_ids=[],
                    )
                )
        services = PostgresWorkflowServices(settings, session_factory=sessions)
        scope = services._scope(incidents[0])
        yield LiveScope(
            settings,
            sessions,
            search,
            events,
            incidents,
            alerts,
            runs,
            scope,
            first,
            repeated,
        )
    finally:
        with sessions() as session, session.begin():
            session.execute(
                delete(IncidentTable).where(IncidentTable.incident_id.in_(incidents))
            )
            session.execute(delete(AlertTable).where(AlertTable.alert_id.in_(alerts)))
            session.execute(
                delete(SecurityEventTable).where(SecurityEventTable.source == source)
            )
        if search.indices.exists(index=index):
            search.indices.delete(index=index)
        search.close()
        engine.dispose()


def search_arguments(live: LiveScope, *, limit: int = 10) -> dict[str, Any]:
    return {
        **{key: live.scope[key] for key in ("time_from", "time_to", "filters")},
        "limit": limit,
    }


@pytest.mark.asyncio
async def test_live_ingestion_hash_and_exact_mcp_whitelist_boundaries(live_scope):
    live = live_scope
    async with open_stdio_session(
        live.context,
        settings=live.settings,
        backend_dir=BACKEND_ROOT,
        managed_attempts=True,
    ) as session:
        tools = await session.list_tools()
        assert len(tools.tools) == 3
        assert {tool.name for tool in tools.tools} == ALLOWED_TOOLS
        assert all(
            not {"run_id", "incident_id", "trace_id"}
            & set(tool.inputSchema["properties"])
            for tool in tools.tools
        )
        values = await PostgresWorkflowServices._call(
            session, "search_security_events", search_arguments(live)
        )
        assert {value["event_id"] for value in values} == set(live.events[:2])
        context = await PostgresWorkflowServices._call(
            session, "get_alert_context", {"alert_id": live.alerts[0]}
        )
        assert {value["event_id"] for value in context} == set(live.events[:2])
        assert (
            await PostgresWorkflowServices._call(
                session, "lookup_attack_technique", {"query": "T9999", "limit": 10}
            )
            == []
        )
        denied = [
            ("run_shell", {}),
            ("get_alert_context", {"alert_id": live.alerts[0], "before_seconds": 901}),
            ("get_alert_context", {"alert_id": live.alerts[0], "after_seconds": 901}),
            ("lookup_attack_technique", {"query": "T1190", "limit": 11}),
            ("search_security_events", search_arguments(live, limit=201)),
            (
                "search_security_events",
                {
                    **search_arguments(live),
                    "filters": {"command": "anything"},
                },
            ),
            (
                "get_alert_context",
                {"alert_id": live.alerts[0], "incident_id": live.incidents[1]},
            ),
        ]
        for name, arguments in denied:
            result = await session.call_tool(name, arguments)
            assert result.isError
            assert result.structuredContent["error"]["code"] == "POLICY_DENIED"
    with live.sessions() as stored:
        repository = EventRepository(stored)
        store = OpenSearchEventStore(
            live.search, index_name=live.settings.opensearch_index
        )
        for value in values:
            event = repository.get(value["event_id"])
            document = store.get_document(event.event_id)
            assert document is not None
            assert document["raw_event"] == event.raw
            assert value["content_sha256"] == event.content_sha256
            assert calculate_content_sha256(event.raw) == event.content_sha256
        calls = stored.scalars(
            select(ToolCallTable).where(ToolCallTable.run_id == live.runs[0])
        ).all()
        assert sum(call.success for call in calls) == 3
        assert sum(call.error_code == "POLICY_DENIED" for call in calls) == 7
    print(
        "task12_live whitelist=3 boundary_denials=7 inserted=3 duplicated=3 verified_hashes=2"
    )


@pytest.mark.asyncio
async def test_live_failed_empty_duplicate_budget_and_separate_verification(live_scope):
    live = live_scope
    ledger = Ledger(live.sessions)
    seed = {"alert_id": live.alerts[0], "before_seconds": 900, "after_seconds": 900}
    async with open_stdio_session(
        live.context,
        settings=live.settings,
        backend_dir=BACKEND_ROOT,
        managed_attempts=True,
    ) as session:
        collector = live.collector(session)
        assert (
            await collector._call("get_alert_context", seed, "Fixed benign seed")
            == "called"
        )
        empty = search_arguments(live)
        empty["filters"] = {**empty["filters"], "event_type": "absent.benign.event"}
        assert (
            await collector._call("search_security_events", empty, "Empty valid query")
            == "called"
        )
        assert (
            await collector._call("run_shell", {}, "Denied invalid tool")
            == "policy_denied"
        )
        assert (
            await collector._call("get_alert_context", seed, "Duplicate fingerprint")
            == "duplicate_query"
        )
        first = ledger.calls(live.incidents[0], 1)
        assert len(first) == 3
        assert any(
            row.status == "completed" and row.result == {"values": []} for row in first
        )
        assert any(
            row.status == "failed" and row.error_code == "POLICY_TOOL_DENIED"
            for row in first
        )
        with pytest.raises(BudgetExceeded):
            ledger.reserve(
                live.incidents[0],
                live.runs[0],
                1,
                "lookup_attack_technique",
                {"query": "T9999"},
                "Fourth round call",
            )
    async with open_stdio_session(
        live.context_for_run(1),
        settings=live.settings,
        backend_dir=BACKEND_ROOT,
        managed_attempts=True,
    ) as session:
        second = live.collector(session, round_no=2)
        assert (
            await second._call("get_alert_context", seed, "Reuse completed seed")
            == "duplicate_query"
        )
        for limit in (1, 2, 3):
            assert (
                await second._call(
                    "search_security_events",
                    search_arguments(live, limit=limit),
                    "Bounded valid query",
                )
                == "called"
            )
        summary = Ledger(live.sessions).summary(live.incidents[0], 2)
        assert (summary.round_used, summary.total_used) == (3, 6)
        with pytest.raises(BudgetExceeded):
            ledger.reserve(
                live.incidents[0],
                live.runs[2],
                3,
                "lookup_attack_technique",
                {"query": "T9999"},
                "Seventh case call",
            )
    # Verification has its own AgentRun and actual MCP query after the simulated
    # approval boundary. The existing live API tests enforce approval itself.
    async with open_stdio_session(
        live.context_for_run(2),
        settings=live.settings,
        backend_dir=BACKEND_ROOT,
        managed_attempts=True,
    ) as session:
        services = PostgresWorkflowServices(
            live.settings, session_factory=live.sessions
        )
        values = await services._verification_call(
            ledger,
            session,
            live.incidents[0],
            live.runs[2],
            search_arguments(live, limit=1),
        )
        assert len(values) == 1
    summary = Ledger(live.sessions).summary(live.incidents[0], 2)
    assert (
        summary.total_used,
        summary.verification_calls,
        summary.verification_attempts,
    ) == (6, 1, 1)
    aliases = [row for row in ledger.calls(live.incidents[0], 2) if not row.charged]
    assert len(aliases) == 1 and aliases[0].source_call_id == first[0].call_id
    assert {row.run_id for row in first} == {live.runs[0]}
    assert {row.run_id for row in ledger.calls(live.incidents[0], 2)} == {live.runs[1]}
    with live.sessions() as session:
        audits = {
            run_id: session.scalars(
                select(ToolCallTable).where(ToolCallTable.run_id == run_id)
            ).all()
            for run_id in live.runs[:3]
        }
        # The policy denies run_shell before MCP; duplicate reuse makes no new
        # physical request. Round two and verification own their MCP sessions.
        assert [len(audits[run_id]) for run_id in live.runs[:3]] == [2, 3, 1]
        assert all(call.success for calls in audits.values() for call in calls)
        assert audits[live.runs[2]][0].tool_name == "search_security_events"
    print(
        "task12_live logical_round=3 logical_case=6 failed=1 empty=1 duplicate_uncharged=1 verification=1 physical_audits_by_run=2,3,1"
    )


@pytest.mark.asyncio
async def test_live_concurrent_postgres_reservations_cannot_overspend(live_scope):
    live = live_scope

    def reserve(limit: int):
        # Every worker owns its transaction/connection and Ledger instance.
        return Ledger(live.sessions).reserve(
            live.incidents[0],
            live.runs[0],
            1,
            "search_security_events",
            search_arguments(live, limit=limit),
            "Concurrent bounded query",
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        duplicated = list(pool.map(lambda _number: reserve(1), range(8)))
        futures = [pool.submit(reserve, limit) for limit in range(2, 10)]
        outcomes = [
            future.result() if future.exception() is None else future.exception()
            for future in futures
        ]
    assert len({row.call_id for row in duplicated}) == 1
    assert sum(not isinstance(row, Exception) for row in outcomes) == 2
    assert all(
        isinstance(row, BudgetExceeded)
        for row in outcomes
        if isinstance(row, Exception)
    )
    async with open_stdio_session(
        live.context,
        settings=live.settings,
        backend_dir=BACKEND_ROOT,
        managed_attempts=True,
    ) as session:
        collector = live.collector(session)
        for row in collector.ledger.calls(live.incidents[0], 1):
            completed = await collector._execute(row)
            assert completed.status == "completed" and completed.attempts == 1
    assert Ledger(live.sessions).summary(live.incidents[0], 1).round_used == 3
    print(
        "task12_live concurrent_duplicate_workers=8 competing_workers=8 accepted_new=2 denied_new=6 charged=3"
    )


@pytest.mark.asyncio
async def test_live_cross_case_scenario_and_time_expansion_are_denied(
    live_scope, tmp_path
):
    live = live_scope
    async with open_stdio_session(
        live.context,
        settings=live.settings,
        backend_dir=BACKEND_ROOT,
        managed_attempts=True,
    ) as session:
        collector = live.collector(session)
        cross_scenario = search_arguments(live)
        cross_scenario["filters"] = {
            **cross_scenario["filters"],
            "dataset_id": live.scope["filters"]["dataset_id"].removesuffix(":a") + ":b",
        }
        expanded = {**search_arguments(live), "time_from": "2026-09-20T00:00:00+00:00"}
        for name, arguments in (
            ("get_alert_context", {"alert_id": live.alerts[1]}),
            ("search_security_events", cross_scenario),
            ("search_security_events", expanded),
        ):
            assert (
                await collector._call(name, arguments, "Attempt scope expansion")
                == "policy_denied"
            )
        rows = collector.ledger.calls(live.incidents[0], 1)
        assert len(rows) == 3
        assert all(
            row.status == "failed"
            and row.error_code in {
                "POLICY_INCIDENT_DENIED",
                "POLICY_TARGET_SCOPE_DENIED",
                "POLICY_TIME_SCOPE_DENIED",
            }
            and row.attempts == 0
            for row in rows
        )
        assert {row.error_code for row in rows} == {
            "POLICY_INCIDENT_DENIED",
            "POLICY_TARGET_SCOPE_DENIED",
            "POLICY_TIME_SCOPE_DENIED",
        }
        # Real bound MCP independently refuses a different incident's alert.
        result = await session.call_tool(
            "get_alert_context", {"alert_id": live.alerts[1]}
        )
        assert (
            result.isError and result.structuredContent["error"]["code"] == "NOT_FOUND"
        )
    with pytest.raises(PermissionError, match="run does not belong"):
        Ledger(live.sessions).reserve(
            live.incidents[0],
            live.runs[3],
            1,
            "search_security_events",
            search_arguments(live),
            "Foreign run",
        )
    services = PostgresWorkflowServices(live.settings, session_factory=live.sessions)
    async with open_stdio_session(
        live.context,
        settings=live.settings,
        backend_dir=BACKEND_ROOT,
    ) as session:
        values = await services._call(
            session, "get_alert_context", {"alert_id": live.alerts[0]}
        )
    with pytest.raises(PermissionError, match="not owned"):
        await services.hydrate_evidence(live.incidents[1], values)
    with (tmp_path / "invalid-context.log").open(
        "w+", encoding="utf-8", errors="replace"
    ) as errlog:
        with pytest.raises(Exception) as error:
            async with open_stdio_session(
                RunContext(live.runs[0], live.incidents[1], "TRACE-invalid"),
                settings=live.settings,
                backend_dir=BACKEND_ROOT,
                errlog=errlog,
            ):
                pytest.fail("mismatched incident must not initialize MCP")
        errlog.seek(0)
        assert "PermissionError: invalid run context" in errlog.read()
        assert not isinstance(error.value, (OSError, TimeoutError))
    print(
        "task12_live scope_denials=3 foreign_run=1 foreign_evidence=1 foreign_alert=1 invalid_mcp_context=1"
    )


@pytest.mark.asyncio
async def test_live_mcp_search_enforces_scope_and_accepts_second_observed_source(
    live_scope, tmp_path
):
    """Real MCP must reject valid-shaped escapes itself, before search/evidence."""
    live = live_scope
    with live.sessions() as session:
        original = session.get(SecurityEventTable, live.events[0])
        raw = dict(original.raw)
    raw.update(
        external_id="second-observed-source",
        host="second.example.test",
        source_ip="198.51.100.17",
    )
    path = tmp_path / "second-source.jsonl"
    path.write_text(json.dumps(raw) + "\n", encoding="utf-8")
    with live.sessions() as session:
        importer = IngestionService(
            EventRepository(session),
            OpenSearchEventStore(
                live.search, index_name=live.settings.opensearch_index
            ),
        )
        imported = importer.import_file(path)
    assert imported.inserted == imported.indexed == 1
    live.events.extend(imported.event_ids)
    with live.sessions.begin() as session:
        alert = session.get(AlertTable, live.alerts[0])
        alert.event_ids = [*alert.event_ids, *imported.event_ids]
    live.search.indices.refresh(index=live.settings.opensearch_index)
    services = PostgresWorkflowServices(live.settings, session_factory=live.sessions)
    scope = services._scope(live.incidents[0])
    base = {key: scope[key] for key in ("time_from", "time_to", "filters", "limit")}
    escapes = [
        {
            **base,
            "time_from": (
                datetime.fromisoformat(scope["time_from"]) - timedelta(seconds=1)
            ).isoformat(),
        },
        {
            **base,
            "time_to": (
                datetime.fromisoformat(scope["time_to"]) + timedelta(seconds=1)
            ).isoformat(),
        },
        {**base, "filters": {**scope["filters"], "dataset_id": "unrelated-case"}},
        {**base, "filters": {**scope["filters"], "host": "unrelated.example.test"}},
        {**base, "filters": {}},
        {**base, "index": "security-events-v1"},
        {**base, "index_name": "security-events-v1"},
    ]
    async with open_stdio_session(
        live.context,
        settings=live.settings,
        backend_dir=BACKEND_ROOT,
        managed_attempts=True,
    ) as session:
        for request in escapes:
            denied = await session.call_tool("search_security_events", request)
            assert (
                denied.isError
                and denied.structuredContent["error"]["code"] == "POLICY_DENIED"
            )
        second = next(
            source
            for source in scope["source_scopes"]
            if source["filters"].get("host") == raw["host"]
        )
        values = await PostgresWorkflowServices._call(
            session,
            "search_security_events",
            {
                "time_from": scope["time_from"],
                "time_to": scope["time_to"],
                "filters": second["filters"],
            },
        )
    assert {value["event_id"] for value in values} == set(imported.event_ids)
    with live.sessions() as session:
        audits = session.scalars(
            select(ToolCallTable).where(ToolCallTable.run_id == live.runs[0])
        ).all()
        assert len(audits) == len(escapes) + 1
        assert sum(row.success for row in audits) == 1
        assert all(
            row.error_code == "POLICY_DENIED" for row in audits if not row.success
        )
    print(
        "task13_mcp direct_scope_denials=7 actual_second_source_query=1 default_limit=100"
    )


class DisconnectingProxy(ThreadingHTTPServer):
    def __init__(self, upstream: str, disconnects: int):
        self.upstream = upstream.rstrip("/")
        self.disconnects = disconnects
        self.search_requests = 0
        self.forwarded_searches = 0
        self.lock = threading.Lock()
        super().__init__(("127.0.0.1", 0), ProxyHandler)


class ProxyHandler(BaseHTTPRequestHandler):
    def log_message(self, _format: str, *args: Any) -> None:
        pass

    def do_POST(self) -> None:
        self.forward()

    def do_GET(self) -> None:
        self.forward()

    def forward(self) -> None:
        proxy = self.server
        assert isinstance(proxy, DisconnectingProxy)
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        if self.path.split("?")[0].endswith("/_search"):
            with proxy.lock:
                proxy.search_requests += 1
                disconnect = proxy.search_requests <= proxy.disconnects
                if not disconnect:
                    proxy.forwarded_searches += 1
            if disconnect:
                self.close_connection = True
                self.connection.shutdown(socket.SHUT_RDWR)
                self.connection.close()
                return
        response = httpx.request(
            self.command,
            proxy.upstream + self.path,
            content=body,
            headers={"Content-Type": "application/json", "Accept-Encoding": "identity"},
            timeout=10,
            trust_env=False,
        )
        self.send_response(response.status_code)
        self.send_header(
            "Content-Type", response.headers.get("content-type", "application/json")
        )
        self.send_header("Content-Length", str(len(response.content)))
        self.end_headers()
        self.wfile.write(response.content)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "disconnects", [2, 3], ids=["retry-recovers", "retry-exhausted"]
)
async def test_live_physical_tcp_retries_charge_one_logical_call(
    live_scope, disconnects
):
    live = live_scope
    proxy = DisconnectingProxy(live.settings.opensearch_url, disconnects)
    worker = threading.Thread(target=proxy.serve_forever, daemon=True)
    worker.start()
    settings = live.settings.model_copy(
        update={"opensearch_url": f"http://127.0.0.1:{proxy.server_port}"}
    )
    try:
        async with open_stdio_session(
            live.context,
            settings=settings,
            backend_dir=BACKEND_ROOT,
            managed_attempts=True,
        ) as session:
            collector = live.collector(session)
            assert (
                await collector._call(
                    "search_security_events",
                    search_arguments(live),
                    "Operational TCP disconnect test",
                )
                == "called"
            )
        rows = Ledger(live.sessions).calls(live.incidents[0], 1)
        assert len(rows) == 1 and rows[0].attempts == 3 and rows[0].charged
        assert rows[0].status == ("completed" if disconnects == 2 else "failed")
        assert proxy.search_requests == 3
        assert proxy.forwarded_searches == (1 if disconnects == 2 else 0)
        with live.sessions() as session:
            calls = session.scalars(
                select(ToolCallTable).where(ToolCallTable.run_id == live.runs[0])
            ).all()
            assert len(calls) == 3
            assert sum(call.success for call in calls) == (1 if disconnects == 2 else 0)
        assert Ledger(live.sessions).summary(live.incidents[0], 1).total_used == 1
        print(
            f"task12_live disconnects={disconnects} physical_attempts=3 logical_charged=1 forwarded_real_searches={proxy.forwarded_searches}"
        )
    finally:
        proxy.shutdown()
        proxy.server_close()
        worker.join(timeout=5)


@pytest.mark.asyncio
async def test_live_missing_model_credentials_downgrades_to_bounded_rules(live_scope):
    live = live_scope
    # Real provider initialization fails because credentials are explicitly absent;
    # no model request is submitted and no provider response is fabricated.
    settings = live.settings.model_copy(
        update={"llm_mode": "deepseek", "deepseek_api_key": None}
    )
    services = PostgresWorkflowServices(settings, session_factory=live.sessions)
    state = {
        "incident_id": live.incidents[0],
        "trace_id": "TRACE-" + new_ulid(),
        "alerts": [
            {"alert_id": live.alerts[0], "title": "Routine benign health check"}
        ],
    }
    result = await services.collect(state, live.runs[0])
    assert result["fallback_used"] is True
    assert result["collection_budget_used"] == result["collection_round_used"] == 3
    assert result["collection_model_attempts"] == 6
    assert (
        sum(
            item["status"] == "planner_fallback"
            for item in result["collection_observations"]
        )
        == 2
    )
    assert {item["event_id"] for item in result["evidence"]} == set(live.events[:2])
    with live.sessions() as session:
        calls = session.scalars(
            select(ToolCallTable).where(ToolCallTable.run_id == live.runs[0])
        ).all()
        assert len(calls) == 3 and all(call.success for call in calls)
        assert {call.tool_name for call in calls} == ALLOWED_TOOLS
    print(
        "task12_live unavailable_model_attempts=6 rule_fallbacks=2 real_tools=3 logical_charged=3"
    )
