from __future__ import annotations

from datetime import UTC, datetime, timedelta
from importlib import import_module
from types import SimpleNamespace
from typing import Self

import pytest
from evidencesoc.tools.audit import ToolCallRecord
from evidencesoc.tools.policy import PolicyDeniedError
from evidencesoc.tools.security_events import SecurityEventTools

NOW = datetime(2026, 9, 21, 12, 0, tzinfo=UTC)


class SessionSpy:
    def __init__(self) -> None:
        self.rows: list[object] = []
        self.commits = 0
        self.closes = 0

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        _exc_type: object,
        _exc: object,
        _traceback: object,
    ) -> None:
        self.closes += 1

    def add(self, row: object) -> None:
        self.rows.append(row)

    def commit(self) -> None:
        self.commits += 1


def test_sql_audit_writer_records_all_fields_once() -> None:
    module = import_module("evidencesoc.tools.audit_sql")
    session = SessionSpy()
    writer = module.SqlAuditWriter(
        session_factory=lambda: session,
        tool_call_id_factory=lambda: "TC-unit-test",
    )
    record = ToolCallRecord(
        run_id="AR-unit-test",
        tool_name="search_security_events",
        arguments={"limit": 201},
        result={"trace_id": "TRACE-unit-test", "reason": "limit"},
        started_at=NOW,
        finished_at=NOW + timedelta(seconds=1),
        success=False,
        error_code="POLICY_DENIED",
    )

    writer.record(record)

    assert session.commits == 1
    assert session.closes == 1
    assert len(session.rows) == 1
    row = session.rows[0]
    assert row.tool_call_id == "TC-unit-test"
    assert row.run_id == record.run_id
    assert row.tool_name == record.tool_name
    assert row.arguments == record.arguments
    assert row.result == record.result
    assert row.started_at == record.started_at
    assert row.finished_at == record.finished_at
    assert row.success is False
    assert row.error_code == "POLICY_DENIED"


@pytest.mark.asyncio
async def test_policy_denial_uses_sql_audit_writer_before_work() -> None:
    module = import_module("evidencesoc.tools.audit_sql")
    session = SessionSpy()
    writer = module.SqlAuditWriter(
        session_factory=lambda: session,
        tool_call_id_factory=lambda: "TC-denied-test",
    )

    class WorkSpy:
        def __init__(self) -> None:
            self.calls = 0

        def __call__(self, **_kwargs: object) -> list[object]:
            self.calls += 1
            return []

    work = WorkSpy()
    tool = SecurityEventTools(
        context=SimpleNamespace(
            run_id="AR-unit-test",
            incident_id="IN-unit-test",
            trace_id="TRACE-unit-test",
        ),
        work=work,
        audit=writer,
    )

    with pytest.raises(PolicyDeniedError):
        await tool.search_security_events(
            NOW,
            NOW + timedelta(minutes=5),
            {},
            limit=201,
        )

    assert work.calls == 0
    assert session.commits == 1
    assert len(session.rows) == 1
    row = session.rows[0]
    assert row.error_code == "POLICY_DENIED"
    assert row.result["trace_id"] == "TRACE-unit-test"
    assert "limit" in row.result["reason"]


def test_generated_tool_call_id_has_prefix() -> None:
    module = import_module("evidencesoc.tools.audit_sql")

    assert module.new_tool_call_id().startswith("TC-")
