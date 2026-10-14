import asyncio
import threading
from types import SimpleNamespace

import pytest
from evidencesoc.tools.errors import ToolDependencyTimeout
from evidencesoc.tools.runtime import run_audited_tool


def test_cancelled_budget_prevents_sql_operation() -> None:
    from evidencesoc.execution import CURRENT_BUDGET, ExecutionBudget
    from evidencesoc.persistence.database import create_database_engine
    from sqlalchemy import text

    budget = ExecutionBudget(float("inf"))
    budget.cancelled.set()
    token = CURRENT_BUDGET.set(budget)
    engine = create_database_engine("sqlite://")
    try:
        with engine.connect() as connection, pytest.raises(ToolDependencyTimeout):
            connection.execute(text("SELECT 1"))
    finally:
        CURRENT_BUDGET.reset(token)
        engine.dispose()


@pytest.mark.asyncio
async def test_cancelled_call_is_audited_once() -> None:
    started = threading.Event()
    release = threading.Event()
    records = []

    def work() -> list:
        started.set()
        release.wait(1)
        return []

    task = asyncio.create_task(run_audited_tool(
        context=SimpleNamespace(run_id="R", incident_id="I", trace_id="T"),
        audit=SimpleNamespace(record=records.append), tool_name="test", arguments={},
        validate=lambda: None, work=work, validate_result=len,
    ))
    await asyncio.to_thread(started.wait, 1)
    task.cancel()
    try:
        with pytest.raises(asyncio.CancelledError):
            await task
        assert len(records) == 1
        assert records[0].success is False
    finally:
        release.set()


@pytest.mark.asyncio
async def test_cancelled_worker_cannot_enter_evidence_persistence() -> None:
    from evidencesoc.evidence.service import EvidenceService

    started = threading.Event()
    release = threading.Event()
    finished = threading.Event()
    persisted = []
    service = EvidenceService(None, SimpleNamespace(add_many=lambda *args: persisted.append(args)), None)

    def work() -> list:
        started.set()
        release.wait(1)
        try:
            return service.create_for_events("I", [], {})
        finally:
            finished.set()

    task = asyncio.create_task(run_audited_tool(
        context=SimpleNamespace(run_id="R", incident_id="I", trace_id="T"),
        audit=SimpleNamespace(record=lambda record: None), tool_name="test", arguments={},
        validate=lambda: None, work=work, validate_result=len,
    ))
    await asyncio.to_thread(started.wait, 1)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    release.set()
    await asyncio.to_thread(finished.wait, 1)
    assert persisted == []


@pytest.mark.asyncio
async def test_audit_is_inside_call_deadline() -> None:
    release = threading.Event()

    def audit(record: object) -> None:
        release.wait(1)

    try:
        with pytest.raises(ToolDependencyTimeout):
            await asyncio.wait_for(run_audited_tool(
                context=SimpleNamespace(run_id="R", incident_id="I", trace_id="T"),
                audit=SimpleNamespace(record=audit), tool_name="test", arguments={},
                validate=lambda: None, work=list, validate_result=len,
                deadline_seconds=0.05,
            ), 0.2)
    finally:
        release.set()


@pytest.mark.asyncio
async def test_boundary_audit_timeout_is_structured_and_attempted_once() -> None:
    from evidencesoc.mcp_server.context import RunContext
    from evidencesoc.mcp_server.restricted import RestrictedFastMCP

    release = threading.Event()
    records = []

    def audit(record: object) -> None:
        records.append(record)
        release.wait(1)

    server = RestrictedFastMCP(
        context=RunContext(run_id="R", incident_id="I", trace_id="T"),
        boundary_audit=SimpleNamespace(record=audit), deadline_seconds=0.05,
    )
    try:
        result = await asyncio.wait_for(server.call_tool("unknown", {}), 0.2)
        assert result.structuredContent["error"]["code"] == "DEPENDENCY_TIMEOUT"
        assert len(records) == 1
    finally:
        release.set()


@pytest.mark.asyncio
async def test_audit_failure_is_sanitized_without_retry() -> None:
    from evidencesoc.tools.errors import ToolDependencyError

    records = []

    def audit(record: object) -> None:
        records.append(record)
        raise RuntimeError("private SQL connection details")

    with pytest.raises(ToolDependencyError, match="^dependency unavailable$"):
        await run_audited_tool(
            context=SimpleNamespace(run_id="R", incident_id="I", trace_id="T"),
            audit=SimpleNamespace(record=audit), tool_name="test", arguments={},
            validate=lambda: None, work=list, validate_result=len,
        )
    assert len(records) == 1


@pytest.mark.asyncio
async def test_audit_database_timeout_keeps_timeout_code() -> None:
    def audit(_record: object) -> None:
        raise ToolDependencyTimeout("dependency timed out")

    with pytest.raises(ToolDependencyTimeout):
        await run_audited_tool(
            context=SimpleNamespace(run_id="R", incident_id="I", trace_id="T"),
            audit=SimpleNamespace(record=audit),
            tool_name="test",
            arguments={},
            validate=lambda: None,
            work=list,
            validate_result=len,
        )


@pytest.mark.asyncio
async def test_external_cancellation_survives_audit_failure() -> None:
    started = threading.Event()
    release = threading.Event()

    def work() -> list:
        started.set()
        release.wait(1)
        return []

    def audit(record: object) -> None:
        raise RuntimeError("database unavailable")

    task = asyncio.create_task(run_audited_tool(
        context=SimpleNamespace(run_id="R", incident_id="I", trace_id="T"),
        audit=SimpleNamespace(record=audit), tool_name="test", arguments={},
        validate=lambda: None, work=work, validate_result=len,
    ))
    await asyncio.to_thread(started.wait, 1)
    task.cancel()
    try:
        with pytest.raises(asyncio.CancelledError):
            await task
    finally:
        release.set()
