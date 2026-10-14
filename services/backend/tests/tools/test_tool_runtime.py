from __future__ import annotations

import threading
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from evidencesoc.tools.errors import (
    ToolDependencyError,
    ToolDependencyTimeout,
    ToolNotFoundError,
)
from evidencesoc.tools.policy import PolicyDeniedError
from evidencesoc.tools.runtime import run_audited_tool, validate_evidence_items

CONTEXT = SimpleNamespace(
    run_id="AR-runtime-test",
    incident_id="IN-runtime-test",
    trace_id="TRACE-runtime-test",
)


class AuditSpy:
    def __init__(self) -> None:
        self.records: list[object] = []

    def record(self, record: object) -> None:
        self.records.append(record)


@pytest.mark.asyncio
async def test_runtime_validates_before_work_and_audits_denial() -> None:
    calls: list[str] = []
    audit = AuditSpy()

    def validate() -> None:
        raise PolicyDeniedError("denied before storage")

    with pytest.raises(PolicyDeniedError):
        await run_audited_tool(
            context=CONTEXT,
            audit=audit,
            tool_name="search_security_events",
            arguments={"limit": 201},
            validate=validate,
            work=lambda: calls.append("work"),
            validate_result=lambda _result: 0,
        )

    assert calls == []
    assert len(audit.records) == 1
    assert audit.records[0].error_code == "POLICY_DENIED"
    assert audit.records[0].result["trace_id"] == CONTEXT.trace_id


@pytest.mark.asyncio
async def test_runtime_wraps_unexpected_dependency_failure() -> None:
    audit = AuditSpy()

    def fail() -> list[object]:
        raise RuntimeError("secret database detail")

    with pytest.raises(ToolDependencyError, match="dependency unavailable"):
        await run_audited_tool(
            context=CONTEXT,
            audit=audit,
            tool_name="search_security_events",
            arguments={},
            validate=lambda: None,
            work=fail,
            validate_result=len,
        )

    assert len(audit.records) == 1
    assert audit.records[0].error_code == "DEPENDENCY_UNAVAILABLE"
    assert audit.records[0].result["reason"] == "dependency unavailable"


@pytest.mark.asyncio
async def test_runtime_audits_success_once() -> None:
    audit = AuditSpy()
    result = ["one", "two"]

    returned = await run_audited_tool(
        context=CONTEXT,
        audit=audit,
        tool_name="test_tool",
        arguments={"limit": 2},
        validate=lambda: None,
        work=lambda: result,
        validate_result=len,
    )

    assert returned is result
    assert len(audit.records) == 1
    record = audit.records[0]
    assert record.success is True
    assert record.error_code is None
    assert record.result == {"trace_id": CONTEXT.trace_id, "result_count": 2}
    assert record.started_at <= record.finished_at <= datetime.now(UTC)


@pytest.mark.asyncio
async def test_runtime_preserves_coded_work_error() -> None:
    audit = AuditSpy()

    def fail() -> list[object]:
        raise ToolNotFoundError("resource not found")

    with pytest.raises(ToolNotFoundError):
        await run_audited_tool(
            context=CONTEXT,
            audit=audit,
            tool_name="test_tool",
            arguments={},
            validate=lambda: None,
            work=fail,
            validate_result=len,
        )

    assert len(audit.records) == 1
    assert audit.records[0].error_code == "NOT_FOUND"
    assert audit.records[0].result["reason"] == "resource not found"


@pytest.mark.asyncio
async def test_runtime_preserves_list_count_after_result_validation_failure() -> None:
    audit = AuditSpy()

    with pytest.raises(ToolDependencyError, match="too many results"):
        await run_audited_tool(
            context=CONTEXT,
            audit=audit,
            tool_name="test_tool",
            arguments={},
            validate=lambda: None,
            work=lambda: [object(), object()],
            validate_result=lambda value: validate_evidence_items(value, limit=1),
        )

    assert len(audit.records) == 1
    assert audit.records[0].result["result_count"] == 2


@pytest.mark.asyncio
async def test_runtime_deadline_audits_timeout_once() -> None:
    audit = AuditSpy()
    entered = threading.Event()
    release = threading.Event()
    exited = threading.Event()

    def blocked_work() -> list[object]:
        entered.set()
        try:
            release.wait(timeout=5)
            return []
        finally:
            exited.set()

    try:
        with pytest.raises(ToolDependencyTimeout, match="dependency timed out"):
            await run_audited_tool(
                context=CONTEXT,
                audit=audit,
                tool_name="test_tool",
                arguments={},
                validate=lambda: None,
                work=blocked_work,
                validate_result=len,
                deadline_seconds=0.05,
            )
        assert entered.is_set()
        assert len(audit.records) == 1
        assert audit.records[0].error_code == "DEPENDENCY_TIMEOUT"
    finally:
        release.set()
        assert exited.wait(timeout=5)


def test_validate_evidence_items_rejects_non_list() -> None:
    with pytest.raises(ToolDependencyError, match="non-list result"):
        validate_evidence_items((), limit=1)


def test_validate_evidence_items_rejects_invalid_item() -> None:
    with pytest.raises(ToolDependencyError, match="invalid evidence item"):
        validate_evidence_items([object()], limit=1)
