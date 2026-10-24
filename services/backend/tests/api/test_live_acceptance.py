"""Task 9 acceptance through real TCP, PostgreSQL, OpenSearch, and MCP."""

from __future__ import annotations

import asyncio
import json
import math
import os
import socket
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from evidencesoc.agents.checkpoint import open_checkpointer
from evidencesoc.agents.graph import ROLE_NAMES, TERMINAL_STATES
from evidencesoc.api.tables import ApiInvestigationEventTable, ApiInvestigationTable
from evidencesoc.config import Settings
from evidencesoc.ids import new_event_id, new_ulid
from evidencesoc.ingestion.jsonl import ParsedLogRecord
from evidencesoc.ingestion.normalize import normalize_record
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
    ApprovalTable,
    IncidentTable,
    InvestigationToolCallTable,
    SecurityEventTable,
    ValidationResultTable,
)
from evidencesoc.tools.ledger import Ledger
from sqlalchemy import delete, select

ROOT = Path(__file__).resolve().parents[4]
API = "/api/v1"
FRONTEND_ORIGIN = "http://127.0.0.1:3000"
CHILD_CODE = """
import asyncio, os, sys
from pathlib import Path
import uvicorn
from evidencesoc.config import Settings
from evidencesoc.main import create_app
from evidencesoc.agents.services import PostgresWorkflowServices
from evidencesoc.tools.ledger import Ledger

crash_stage = os.environ.get('EVIDENCESOC_TEST_COLLECT_CRASH_STAGE')
crash_alert = os.environ.get('EVIDENCESOC_TEST_COLLECT_CRASH_ALERT')
crash_marker = os.environ.get('EVIDENCESOC_TEST_COLLECT_CRASH_MARKER')

def crash_if(stage, alert_id):
    if stage == crash_stage and alert_id == crash_alert:
        Path(crash_marker).write_text(stage, encoding='utf-8')
        os._exit(73)

if crash_stage == 'after_reservation':
    original_reserve = Ledger.reserve
    def interrupted_reserve(self, *args, **kwargs):
        row = original_reserve(self, *args, **kwargs)
        if row.purpose == 'collection' and row.tool_name == 'get_alert_context':
            crash_if('after_reservation', row.arguments.get('alert_id'))
        return row
    Ledger.reserve = interrupted_reserve
elif crash_stage == 'before_result_confirmation':
    original_call = PostgresWorkflowServices._call
    async def interrupted_call(session, name, arguments, *, capabilities=None):
        values = await original_call(session, name, arguments, capabilities=capabilities)
        if name == 'get_alert_context':
            crash_if('before_result_confirmation', arguments.get('alert_id'))
        return values
    PostgresWorkflowServices._call = staticmethod(interrupted_call)
elif crash_stage == 'before_node_return':
    original_collect_for_crash = PostgresWorkflowServices.collect
    async def interrupted_collect(self, state, run_id):
        result = await original_collect_for_crash(self, state, run_id)
        alert_id = (state.get('alerts') or [{}])[0].get('alert_id')
        crash_if('before_node_return', alert_id)
        return result
    PostgresWorkflowServices.collect = interrupted_collect

delay = float(sys.argv[3])
if delay:
    original_collect_for_delay = PostgresWorkflowServices.collect
    async def delayed_collect(self, state, run_id):
        await asyncio.sleep(delay)
        return await original_collect_for_delay(self, state, run_id)
    PostgresWorkflowServices.collect = delayed_collect
settings = Settings(llm_mode='fixture', opensearch_index=sys.argv[1],
                    demo_session_enabled=True,
                    frontend_origin='http://127.0.0.1:3000')
uvicorn.run(create_app(settings=settings), host='127.0.0.1', port=int(sys.argv[2]),
            log_config=None, access_log=False, loop='asyncio')
"""


@dataclass
class LiveApi:
    settings: Settings
    log_path: Path
    event_ids: list[str]
    port: int
    collect_delay: float = 0
    collect_crash_stage: str | None = None
    collect_crash_alert: str | None = None
    collect_crash_marker: Path | None = None
    process: subprocess.Popen | None = None
    log_handle: Any = None
    alert_ids: set[str] = field(default_factory=set)
    incident_ids: set[str] = field(default_factory=set)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def client(self) -> httpx.Client:
        return httpx.Client(base_url=self.url, timeout=15, trust_env=False)

    def create_review_session(self, client: httpx.Client) -> None:
        response = client.post(
            f"{API}/session/demo", headers={"Origin": FRONTEND_ORIGIN}
        )
        assert response.status_code == 200
        assert response.json()["actor_id"] == "demo-reviewer"
        assert client.cookies.get("evidencesoc_demo_session")

    def plan_version(self, client: httpx.Client, plan_id: str) -> str:
        response = client.get(f"{API}/response-plans/{plan_id}")
        assert response.status_code == 200
        detail = response.json()
        assert detail["response_plan_id"] == plan_id
        version = detail["plan_version"]
        assert len(version) == 64 and all(
            char in "0123456789abcdef" for char in version
        )
        return version

    def decide(
        self,
        client: httpx.Client,
        plan_id: str,
        action: str,
        *,
        version: str,
        reason: str,
        key: str,
    ) -> httpx.Response:
        return client.post(
            f"{API}/response-plans/{plan_id}/{action}",
            headers={"Origin": FRONTEND_ORIGIN, "Idempotency-Key": key},
            json={"plan_version": version, "reason": reason},
        )

    def start(self) -> None:
        self.log_handle = self.log_path.open("ab")
        environment = os.environ.copy()
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        if self.collect_crash_stage is not None:
            assert self.collect_crash_alert and self.collect_crash_marker
            environment["EVIDENCESOC_TEST_COLLECT_CRASH_STAGE"] = (
                self.collect_crash_stage
            )
            environment["EVIDENCESOC_TEST_COLLECT_CRASH_ALERT"] = (
                self.collect_crash_alert
            )
            environment["EVIDENCESOC_TEST_COLLECT_CRASH_MARKER"] = str(
                self.collect_crash_marker
            )
        else:
            for key in (
                "EVIDENCESOC_TEST_COLLECT_CRASH_STAGE",
                "EVIDENCESOC_TEST_COLLECT_CRASH_ALERT",
                "EVIDENCESOC_TEST_COLLECT_CRASH_MARKER",
            ):
                environment.pop(key, None)
        self.process = subprocess.Popen(
            [
                sys.executable,
                "-B",
                "-c",
                CHILD_CODE,
                self.settings.opensearch_index,
                str(self.port),
                str(self.collect_delay),
            ],
            cwd=ROOT / "services/backend",
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=self.log_handle,
            stderr=subprocess.STDOUT,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        deadline = time.monotonic() + 25
        with self.client() as client:
            while time.monotonic() < deadline:
                assert self.process.poll() is None, "acceptance API process exited"
                try:
                    response = client.get("/health/ready", timeout=1)
                    if response.status_code == 200:
                        assert response.json() == {"status": "ok"}
                        return
                except httpx.TransportError:
                    pass
                time.sleep(0.1)
        pytest.fail("real API dependencies did not become ready within 25 seconds")

    def stop(self) -> None:
        if self.process is not None:
            if self.process.poll() is None:
                if os.name == "nt":
                    # MCP is also a child process: keep this test's process tree owned.
                    subprocess.run(
                        ["taskkill", "/PID", str(self.process.pid), "/T", "/F"],
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        check=False,
                        timeout=10,
                        creationflags=subprocess.CREATE_NO_WINDOW,
                    )
                    if self.process.poll() is None:
                        self.process.terminate()
                else:
                    self.process.kill()
                self.process.wait(timeout=10)
            self.process = None
        if self.log_handle is not None:
            self.log_handle.close()
            self.log_handle = None

    def create_alert(self, client: httpx.Client) -> str:
        alert_id = "AL-" + new_ulid()
        self.alert_ids.add(alert_id)
        response = client.post(
            f"{API}/alerts",
            json={
                "alert_id": alert_id,
                "title": "Task9 SQL injection acceptance",
                "severity": "high",
                "event_ids": self.event_ids,
                "created_at": "2026-09-21T10:20:17Z",
            },
        )
        assert response.status_code == 201
        assert response.json()["alert_id"] == alert_id
        return alert_id

    def investigate(self, client: httpx.Client, alert_id: str) -> dict[str, Any]:
        self.create_review_session(client)
        response = client.post(
            f"{API}/investigations",
            headers={
                "Origin": FRONTEND_ORIGIN,
                "Idempotency-Key": "task9-investigation-" + new_ulid(),
            },
            json={"alert_id": alert_id, "mode": "rules"},
        )
        assert response.status_code == 202
        metadata = response.json()
        self.incident_ids.add(metadata["incident_id"])
        assert response.headers["x-trace-id"] == metadata["trace_id"]
        return metadata


@pytest.fixture
def live_api(tmp_path) -> Iterator[tuple[LiveApi, Any]]:
    suffix = new_ulid()
    index = f"security-events-task9-{suffix.lower()}"
    settings = Settings(
        llm_mode="fixture",
        opensearch_index=index,
        demo_session_enabled=True,
        frontend_origin=FRONTEND_ORIGIN,
    )
    engine = create_database_engine(settings.database_url)
    sessions = create_session_factory(engine)
    search = create_opensearch_client(settings.opensearch_url)
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    server = LiveApi(settings, tmp_path / "task9-api.jsonl", [], port)
    try:
        with sessions() as session:
            unrelated = session.scalar(
                select(ApiInvestigationTable.investigation_id)
                .where(ApiInvestigationTable.status.not_in(TERMINAL_STATES))
                .limit(1)
            )
            assert unrelated is None, (
                "finish existing recoverable investigations before this isolated acceptance run"
            )
        template = json.loads(
            (ROOT / "infra/opensearch/security-events-template.json").read_text(
                encoding="utf-8"
            )
        )
        search.indices.create(index=index, body=template["template"])
        store = OpenSearchEventStore(search, index_name=index)
        for offset, line in enumerate(
            (ROOT / "data/samples/sql-injection.jsonl")
            .read_text(encoding="utf-8")
            .splitlines()
        ):
            raw = json.loads(line)
            raw["external_id"] = f"task9-{suffix}-{offset}"
            raw["host"] = f"task9-{suffix.lower()}.example.test"
            raw["username"] = "task9-acceptance-user"
            raw["labels"] = ["forbidden-truth"]
            event = normalize_record(
                ParsedLogRecord(raw, "task9-acceptance", offset + 1),
                event_id=new_event_id(),
                ingested_at=datetime.now(UTC),
            )
            server.event_ids.append(event.event_id)
            with sessions() as session:
                EventRepository(session).register(event)
                session.commit()
            store.index_event(event)
        search.indices.refresh(index=index)
        server.start()
        yield server, sessions
    finally:
        server.stop()
        with sessions() as session:
            server.incident_ids.update(
                session.scalars(
                    select(IncidentTable.incident_id).where(
                        IncidentTable.alert_id.in_(server.alert_ids)
                    )
                )
            )
        if server.incident_ids:

            async def remove_owned_checkpoints():
                async with open_checkpointer(settings.database_url) as saver:
                    for incident_id in server.incident_ids:
                        await saver.adelete_thread(incident_id)

            asyncio.run(remove_owned_checkpoints())
        with sessions() as session:
            session.execute(
                delete(IncidentTable).where(
                    IncidentTable.incident_id.in_(server.incident_ids)
                )
            )
            session.execute(
                delete(AlertTable).where(AlertTable.alert_id.in_(server.alert_ids))
            )
            session.execute(
                delete(SecurityEventTable).where(
                    SecurityEventTable.event_id.in_(server.event_ids)
                )
            )
            session.commit()
        try:
            if search.indices.exists(index=index):
                search.indices.delete(index=index)
        finally:
            search.close()
            engine.dispose()


def wait_status(
    client: httpx.Client, metadata: dict[str, Any], status: str
) -> dict[str, Any]:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        response = client.get(f"{API}/incidents/{metadata['incident_id']}")
        assert response.status_code == 200
        assert response.headers["x-trace-id"] == metadata["trace_id"]
        result = response.json()
        if result["status"] == status:
            return result
        assert result["status"] not in TERMINAL_STATES, (
            f"investigation reached unexpected terminal status {result['status']}"
        )
        time.sleep(0.05)
    pytest.fail(f"investigation did not reach {status} within 30 seconds")


def read_sse(
    client: httpx.Client,
    metadata: dict[str, Any],
    *,
    until: str,
    cursor: int = 0,
    started_at: float | None = None,
    until_agent: str | None = None,
    first_event_samples: list[float] | None = None,
) -> list[dict[str, Any]]:
    frames: list[dict[str, Any]] = []
    frame: dict[str, Any] = {}
    data_lines: list[str] = []
    headers = {"Last-Event-ID": str(cursor)} if cursor else {}
    with client.stream("GET", metadata["stream_url"], headers=headers) as response:
        assert response.status_code == 200
        assert "text/event-stream" in response.headers["content-type"]
        assert response.headers["x-trace-id"] == metadata["trace_id"]
        for line in response.iter_lines():
            if not line:
                if not data_lines:
                    continue
                frame["data"] = json.loads("\n".join(data_lines))
                assert int(frame["id"]) == cursor + 1
                cursor = int(frame["id"])
                assert frame["data"]["trace_id"] == metadata["trace_id"]
                assert frame["data"]["investigation_id"] == metadata["investigation_id"]
                assert frame["data"]["incident_id"] == metadata["incident_id"]
                if not frames and started_at is not None:
                    elapsed = time.perf_counter() - started_at
                    print(
                        f"task9_tcp sse_first_event samples=1 elapsed_ms={elapsed * 1000:.2f}"
                    )
                    if first_event_samples is not None:
                        first_event_samples.append(elapsed * 1000)
                    assert elapsed < 2, f"first TCP SSE event took {elapsed:.3f}s"
                frames.append(frame)
                if frame["event"] == until and (
                    until_agent is None or frame["data"].get("agent") == until_agent
                ):
                    return frames
                frame, data_lines = {}, []
            elif not line.startswith(":"):
                key, separator, value = line.partition(":")
                assert separator
                if key == "data":
                    data_lines.append(value.lstrip(" "))
                elif key in {"id", "event"}:
                    frame[key] = value.lstrip(" ")
    final = client.get(f"{API}/incidents/{metadata['incident_id']}").json()
    diagnostic = {
        key: final.get(key)
        for key in ("status", "stop_reason", "errors", "validation_result")
    }
    pytest.fail(
        f"TCP SSE ended before {until}; terminal={json.dumps(diagnostic)}; "
        f"last_events={json.dumps(frames[-2:])}"
    )


def assert_reviewed_unverified(
    result: dict[str, Any], metadata: dict[str, Any]
) -> None:
    # Real read-only target queries do not establish a simulated effect. These
    # fixtures intentionally supply no before/after effect observations.
    assert result["status"] == "manual_review"
    assert result["stop_reason"] == "insufficient_evidence"
    assert result["errors"] == []
    assert result["trace_id"] == metadata["trace_id"]
    assert result["classification"]["primary_type"] == "sql_injection"
    assert result["origin"]["observed_source_ip"] == "203.0.113.42"
    assert result["evidence"] and result["attack_steps"]
    assert len(result["runs"]) == 6
    assert {run["agent_name"] for run in result["runs"]} == set(ROLE_NAMES)
    assert all(run["status"] == "completed" for run in result["runs"])
    assert result["approval"]["decision"] == "approved"
    assert result["approval"]["decided_by"] == "demo-reviewer"
    assert result["simulation_execution"]["status"] == "completed"
    assert result["validation_result"]["outcome"] == "insufficient_evidence"
    assert "unverified" in result["validation_result"]["summary"]
    assert result["validation_result"]["checks"]
    assert all(
        check["outcome"] == "insufficient_evidence"
        and "Target presence alone" in check["explanation"]
        for check in result["validation_result"]["checks"]
    )
    assert "forbidden-truth" not in json.dumps(result)


def test_live_tcp_approval_stream_performance_and_secret_redaction(live_api):
    server, sessions = live_api
    measurements: dict[str, Any] = {"first_sse_event_ms": [], "ordinary_api": {}}
    with server.client() as client:
        alert_id = server.create_alert(client)
        started_at = time.perf_counter()
        metadata = server.investigate(client, alert_id)
        initial = read_sse(
            client,
            metadata,
            until="approval.required",
            started_at=started_at,
            first_event_samples=measurements["first_sse_event_ms"],
        )
        assert initial[0]["event"] == "investigation.started"
        assert {frame["event"] for frame in initial} >= {
            "agent.started",
            "agent.completed",
            "evidence.added",
            "approval.required",
        }
        before = wait_status(client, metadata, "awaiting_approval")
        assert before["approval"] is None and before["validation_result"] is None
        pending_budget = Ledger(sessions).summary(metadata["incident_id"], 1)
        assert (pending_budget.total_used, pending_budget.verification_calls) == (3, 0)
        plan_id = before["response_plan"]["response_plan_id"]
        version = server.plan_version(client, plan_id)
        barrier = threading.Barrier(2)

        def concurrent_approve():
            with server.client() as decision_client:
                server.create_review_session(decision_client)
                barrier.wait(timeout=5)
                return server.decide(
                    decision_client,
                    plan_id,
                    "approve",
                    version=version,
                    reason="Task9 reviewed simulation",
                    key="task9-concurrent-" + new_ulid(),
                )

        with ThreadPoolExecutor(max_workers=2) as pool:
            responses = list(pool.map(lambda _: concurrent_approve(), range(2)))
        assert sorted(response.status_code for response in responses) == [202, 409]
        accepted = next(
            response for response in responses if response.status_code == 202
        )
        assert accepted.json()["trace_id"] == metadata["trace_id"]
        tail = read_sse(
            client,
            metadata,
            until="investigation.failed",
            cursor=int(initial[-1]["id"]),
        )
        assert {frame["event"] for frame in tail} >= {
            "decision.recorded",
            "validation.completed",
        }
        assert {
            frame["data"]["agent"]
            for frame in [*initial, *tail]
            if frame["event"] == "agent.completed"
        } == set(ROLE_NAMES)
        after = wait_status(client, metadata, "manual_review")
        assert_reviewed_unverified(after, metadata)
        completed_budget = Ledger(sessions).summary(metadata["incident_id"], 1)
        assert (
            completed_budget.total_used,
            completed_budget.verification_calls,
            completed_budget.verification_attempts,
        ) == (3, 1, 1)
        print(
            "task9_tcp approved_collection_calls=3 verification_calls=1 verification_attempts=1"
        )
        with sessions() as session:
            assert (
                len(
                    session.scalars(
                        select(ApprovalTable).where(
                            ApprovalTable.response_plan_id == plan_id
                        )
                    ).all()
                )
                == 1
            )
            assert (
                len(
                    session.scalars(
                        select(ValidationResultTable).where(
                            ValidationResultTable.response_plan_id == plan_id
                        )
                    ).all()
                )
                == 1
            )
        for name, path in (
            ("alerts", f"{API}/alerts"),
            ("incident", f"{API}/incidents/{metadata['incident_id']}"),
        ):
            durations = []
            for _ in range(100):
                started = time.perf_counter()
                response = client.get(path)
                durations.append((time.perf_counter() - started) * 1000)
                assert response.status_code == 200
            p95 = sorted(durations)[math.ceil(len(durations) * 0.95) - 1]
            print(f"task9_tcp {name} samples=100 p95_ms={p95:.2f}")
            assert p95 < 500
            measurements["ordinary_api"][name] = {
                "sample_count": len(durations),
                "durations_ms": durations,
                "p95_ms": p95,
            }
        server.log_path.with_name("task12-api-performance.json").write_text(
            json.dumps(measurements, indent=2) + "\n", encoding="utf-8"
        )
        sentinel = "task9-secret-" + new_ulid()
        invalid = client.post(
            f"{API}/alerts?password={sentinel}&api_key={sentinel}",
            headers={
                "Authorization": f"Bearer {sentinel}",
                "Cookie": f"session={sentinel}",
            },
            json={
                "title": sentinel,
                "severity": sentinel,
                "event_ids": server.event_ids,
                "password": sentinel,
            },
        )
        assert invalid.status_code == 422
        assert sentinel not in invalid.text
        assert invalid.json()["error"]["trace_id"] == invalid.headers["x-trace-id"]
    server.stop()
    log_text = server.log_path.read_text(encoding="utf-8", errors="replace")
    assert sentinel not in log_text
    audits = [
        json.loads(line)
        for line in log_text.splitlines()
        if line.startswith("{") and '"http_request"' in line
    ]
    assert audits
    assert all(
        {"method", "route", "status_code", "duration_ms", "trace_id"} <= audit.keys()
        for audit in audits
    )
    assert all(
        not {"headers", "body", "query", "query_string", "url"} & audit.keys()
        for audit in audits
    )


def test_live_tcp_restart_replays_cursor_and_rejection_without_subscription(live_api):
    server, _sessions = live_api
    with server.client() as client:
        metadata = server.investigate(client, server.create_alert(client))
        # No subscriber is present while the background investigation runs.
        before = wait_status(client, metadata, "awaiting_approval")
        initial = read_sse(client, metadata, until="approval.required")
        plan_id = before["response_plan"]["response_plan_id"]
        version = server.plan_version(client, plan_id)
    server.stop()
    server.start()
    with server.client() as client:
        recovered = wait_status(client, metadata, "awaiting_approval")
        assert recovered["response_plan"] == before["response_plan"]
        assert recovered["trace_id"] == before["trace_id"]
        replay = read_sse(
            client, metadata, until="approval.required", cursor=int(initial[0]["id"])
        )
        assert replay == initial[1:]
        assert server.plan_version(client, plan_id) == version
        server.create_review_session(client)
        decision = server.decide(
            client,
            plan_id,
            "approve",
            version=version,
            reason="reviewed after process restart",
            key="task9-restart-" + new_ulid(),
        )
        assert decision.status_code == 202
        tail = read_sse(
            client,
            metadata,
            until="investigation.failed",
            cursor=int(initial[-1]["id"]),
        )
        assert tail[-1]["data"]["status"] == "manual_review"
        assert_reviewed_unverified(
            wait_status(client, metadata, "manual_review"), metadata
        )

        rejected_metadata = server.investigate(client, server.create_alert(client))
        pending = wait_status(client, rejected_metadata, "awaiting_approval")
        rejected_plan = pending["response_plan"]["response_plan_id"]
        rejected_version = server.plan_version(client, rejected_plan)
        rejection_key = "task9-reject-" + new_ulid()
        assert (
            server.decide(
                client,
                rejected_plan,
                "reject",
                version=rejected_version,
                reason="reject the simulated response",
                key=rejection_key,
            ).status_code
            == 202
        )
        assert (
            server.decide(
                client,
                rejected_plan,
                "reject",
                version=rejected_version,
                reason="reject the simulated response",
                key=rejection_key,
            ).status_code
            == 202
        )
        assert (
            server.decide(
                client,
                rejected_plan,
                "reject",
                version=rejected_version,
                reason="reject the simulated response",
                key="task9-conflict-" + new_ulid(),
            ).status_code
            == 409
        )
        rejected = wait_status(client, rejected_metadata, "rejected")
        assert rejected["approval"]["decision"] == "rejected"
        assert rejected["approval"]["decided_by"] == "demo-reviewer"
        assert rejected["validation_result"] is None
        assert {run["agent_name"] for run in rejected["runs"]} == set(ROLE_NAMES) - {
            "validate"
        }
        rejected_frames = read_sse(
            client, rejected_metadata, until="investigation.completed"
        )
        assert rejected_frames[-1]["data"]["status"] == "rejected"
        assert not any(
            frame["event"] == "validation.completed" for frame in rejected_frames
        )


def test_live_tcp_two_processes_accept_only_one_approval(live_api, tmp_path):
    server, sessions = live_api
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        second_port = listener.getsockname()[1]
    peer = LiveApi(
        server.settings,
        tmp_path / "task9-peer-api.jsonl",
        server.event_ids,
        second_port,
    )
    try:
        peer.start()
        with server.client() as client:
            metadata = server.investigate(client, server.create_alert(client))
            before = wait_status(client, metadata, "awaiting_approval")
            plan_id = before["response_plan"]["response_plan_id"]
            version = server.plan_version(client, plan_id)
            barrier = threading.Barrier(2)

            def approve_from(worker):
                with worker.client() as decision_client:
                    worker.create_review_session(decision_client)
                    barrier.wait(timeout=5)
                    return worker.decide(
                        decision_client,
                        plan_id,
                        "approve",
                        version=version,
                        reason="concurrent independent API workers",
                        key="task9-cross-worker-" + new_ulid(),
                    )

            with ThreadPoolExecutor(max_workers=2) as pool:
                responses = list(pool.map(approve_from, (server, peer)))
            assert sorted(response.status_code for response in responses) == [202, 409]
            accepted = next(
                response for response in responses if response.status_code == 202
            )
            assert accepted.json()["trace_id"] == metadata["trace_id"]
            frames = read_sse(client, metadata, until="investigation.failed")
            assert frames[-1]["data"]["status"] == "manual_review"
            assert sum(frame["event"] == "decision.recorded" for frame in frames) == 1
            assert (
                sum(frame["event"] == "validation.completed" for frame in frames) == 1
            )
            assert_reviewed_unverified(
                wait_status(client, metadata, "manual_review"), metadata
            )
            with peer.client() as other_client:
                assert_reviewed_unverified(
                    wait_status(other_client, metadata, "manual_review"), metadata
                )
            with sessions() as session:
                assert (
                    len(
                        session.scalars(
                            select(ApprovalTable).where(
                                ApprovalTable.response_plan_id == plan_id
                            )
                        ).all()
                    )
                    == 1
                )
                assert (
                    len(
                        session.scalars(
                            select(ValidationResultTable).where(
                                ValidationResultTable.response_plan_id == plan_id
                            )
                        ).all()
                    )
                    == 1
                )
    finally:
        peer.stop()


def test_live_tcp_collect_interruption_resumes_without_event_loss(live_api):
    server, sessions = live_api
    server.stop()
    server.collect_delay = 2
    server.start()
    with server.client() as client:
        metadata = server.investigate(client, server.create_alert(client))
        initial = read_sse(
            client, metadata, until="agent.started", until_agent="collect"
        )
        cursor = int(initial[-1]["id"])
        assert initial[-1]["data"]["agent"] == "collect"
        assert not any(
            frame["event"] == "agent.completed" and frame["data"]["agent"] == "collect"
            for frame in initial
        )
    server.stop()
    server.collect_delay = 0
    server.start()
    with server.client() as client:
        recovered = read_sse(client, metadata, until="approval.required", cursor=cursor)
        collect_restarts = [
            frame
            for frame in recovered
            if frame["event"] == "agent.started" and frame["data"]["agent"] == "collect"
        ]
        assert len(collect_restarts) == 1
        assert any(
            frame["event"] == "agent.completed" and frame["data"]["agent"] == "collect"
            for frame in recovered
        )
        with sessions() as session:
            starts = session.scalars(
                select(ApiInvestigationEventTable).where(
                    ApiInvestigationEventTable.investigation_id
                    == metadata["investigation_id"],
                    ApiInvestigationEventTable.event == "agent.started",
                )
            ).all()
            collect_starts = [row for row in starts if row.data["agent"] == "collect"]
            assert len(collect_starts) == 2
            source_uuids = {
                row.dedup_key.removeprefix("source:").removesuffix(":started")
                for row in collect_starts
            }
            assert len(source_uuids) == 2 and all(
                len(value) == 26 for value in source_uuids
            )
        before = wait_status(client, metadata, "awaiting_approval")
        plan_id = before["response_plan"]["response_plan_id"]
        version = server.plan_version(client, plan_id)
        server.create_review_session(client)
        response = server.decide(
            client,
            plan_id,
            "approve",
            version=version,
            reason="reviewed after interrupted collection",
            key="task9-recovery-" + new_ulid(),
        )
        assert response.status_code == 202
        tail = read_sse(
            client,
            metadata,
            until="investigation.failed",
            cursor=int(recovered[-1]["id"]),
        )
        all_ids = [int(frame["id"]) for frame in [*initial, *recovered, *tail]]
        assert all_ids == list(range(1, all_ids[-1] + 1))
        assert_reviewed_unverified(
            wait_status(client, metadata, "manual_review"), metadata
        )


@pytest.mark.parametrize(
    ("stage", "interrupted_status", "interrupted_attempts", "recovered_attempts"),
    [
        ("after_reservation", "reserved", 0, 1),
        ("before_result_confirmation", "running", 1, 2),
        ("before_node_return", "completed", 1, 1),
    ],
)
def test_live_tcp_collect_internal_crash_keeps_budget_and_recovers(
    live_api, stage, interrupted_status, interrupted_attempts, recovered_attempts
):
    server, sessions = live_api
    with server.client() as client:
        alert_id = server.create_alert(client)
    server.stop()

    marker = server.log_path.with_name(f"collect-crash-{stage}.marker")
    assert not marker.exists()
    server.collect_crash_stage = stage
    server.collect_crash_alert = alert_id
    server.collect_crash_marker = marker
    server.collect_delay = 0.3
    server.start()
    with server.client() as client:
        metadata = server.investigate(client, alert_id)

    assert server.process is not None
    try:
        exit_code = server.process.wait(timeout=45)
    except subprocess.TimeoutExpired:
        with sessions() as session:
            rows = session.scalars(
                select(InvestigationToolCallTable).where(
                    InvestigationToolCallTable.incident_id == metadata["incident_id"]
                )
            ).all()
            statuses = [(row.tool_name, row.status, row.attempts) for row in rows]
            investigation = session.scalar(
                select(ApiInvestigationTable).where(
                    ApiInvestigationTable.incident_id == metadata["incident_id"]
                )
            )
        pytest.fail(
            f"collect crash hook did not fire: {stage}, "
            f"investigation={investigation.status if investigation else None}, "
            f"calls={statuses}"
        )
    assert exit_code == 73
    assert marker.read_text(encoding="utf-8") == stage
    with sessions() as session:
        interrupted = session.scalars(
            select(InvestigationToolCallTable).where(
                InvestigationToolCallTable.incident_id == metadata["incident_id"],
                InvestigationToolCallTable.purpose == "collection",
            )
        ).all()
        seed = next(row for row in interrupted if row.tool_name == "get_alert_context")
        assert seed.status == interrupted_status
        assert seed.attempts == interrupted_attempts
        assert seed.charged is True
        assert sum(row.charged for row in interrupted) == (
            3 if stage == "before_node_return" else 1
        )
        seed_id = seed.call_id

    server.stop()
    server.collect_crash_stage = None
    server.collect_crash_alert = None
    server.collect_crash_marker = None
    server.collect_delay = 0
    server.start()
    with server.client() as client:
        initial = read_sse(client, metadata, until="approval.required")
        collect_started = [
            frame
            for frame in initial
            if frame["event"] == "agent.started" and frame["data"]["agent"] == "collect"
        ]
        collect_completed = [
            frame
            for frame in initial
            if frame["event"] == "agent.completed"
            and frame["data"]["agent"] == "collect"
        ]
        assert len(collect_started) == 2
        assert len(collect_completed) == 1
        before = wait_status(client, metadata, "awaiting_approval")
        plan_id = before["response_plan"]["response_plan_id"]
        server.create_review_session(client)
        response = server.decide(
            client,
            plan_id,
            "approve",
            version=server.plan_version(client, plan_id),
            reason="reviewed recovered plan",
            key="task12-collect-recovery-" + new_ulid(),
        )
        assert response.status_code == 202
        tail = read_sse(
            client,
            metadata,
            until="investigation.failed",
            cursor=int(initial[-1]["id"]),
        )
        all_ids = [int(frame["id"]) for frame in [*initial, *tail]]
        assert all_ids == list(range(1, all_ids[-1] + 1))
        assert_reviewed_unverified(
            wait_status(client, metadata, "manual_review"), metadata
        )

    with sessions() as session:
        rows = session.scalars(
            select(InvestigationToolCallTable).where(
                InvestigationToolCallTable.incident_id == metadata["incident_id"],
                InvestigationToolCallTable.purpose == "collection",
            )
        ).all()
        assert len(rows) == 3
        assert all(row.status == "completed" for row in rows)
        assert sum(row.charged for row in rows) == 3
        recovered_seed = next(row for row in rows if row.call_id == seed_id)
        assert recovered_seed.attempts == recovered_attempts
        collect_run = session.scalar(
            select(AgentRunTable).where(
                AgentRunTable.incident_id == metadata["incident_id"],
                AgentRunTable.agent_name == "collect",
            )
        )
        assert collect_run is not None
        assert collect_run.output_summary["collection_budget_used"] == 3
        assert collect_run.output_summary["collection_tool_attempts"] == sum(
            row.attempts for row in rows
        )
        print(
            f"task12_live collect_crash_stage={stage} charged_after_restart=3 "
            f"seed_physical_attempts={recovered_seed.attempts} "
            f"collect_physical_attempts={sum(row.attempts for row in rows)}"
        )
