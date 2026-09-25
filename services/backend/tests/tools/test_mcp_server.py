from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from evidencesoc.domain.models import EvidenceItem
from evidencesoc.mcp_server.context import RunContext, load_run_context
from evidencesoc.mcp_server.main import create_server, validate_run_context
from evidencesoc.tools.security_events import SecurityEventTools


def test_run_context_requires_all_bound_identifiers() -> None:
    environ = {
        "EVIDENCESOC_RUN_ID": "AR-test",
        "EVIDENCESOC_INCIDENT_ID": "IN-test",
        "EVIDENCESOC_TRACE_ID": "TRACE-test",
    }
    assert load_run_context(environ) == RunContext(
        run_id="AR-test",
        incident_id="IN-test",
        trace_id="TRACE-test",
    )

    for missing in environ:
        incomplete = dict(environ)
        incomplete[missing] = " "
        with pytest.raises(ValueError, match=missing):
            load_run_context(incomplete)


def test_run_context_must_match_a_persisted_agent_run() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    with engine.begin() as connection:
        connection.exec_driver_sql(
            "CREATE TABLE agent_runs ("
            "run_id VARCHAR(64) PRIMARY KEY, "
            "incident_id VARCHAR(64) NOT NULL)"
        )
        connection.exec_driver_sql(
            "INSERT INTO agent_runs (run_id, incident_id) VALUES ('AR-test', 'IN-test')"
        )
    sessions = sessionmaker(bind=engine, class_=Session)
    valid = RunContext("AR-test", "IN-test", "TRACE-test")

    validate_run_context(sessions, valid)
    with pytest.raises(PermissionError, match="run context"):
        validate_run_context(
            sessions,
            RunContext("AR-test", "IN-other", "TRACE-test"),
        )
    with pytest.raises(PermissionError, match="run context"):
        validate_run_context(
            sessions,
            RunContext("AR-missing", "IN-test", "TRACE-test"),
        )
    engine.dispose()


class WorkSpy:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def __call__(self, **kwargs: object) -> list[EvidenceItem]:
        self.calls.append(kwargs)
        return []


class AuditSpy:
    def __init__(self) -> None:
        self.records: list[object] = []

    def record(self, record: object) -> None:
        self.records.append(record)


@pytest.mark.asyncio
async def test_server_exposes_only_bound_event_tool() -> None:
    context = RunContext("AR-test", "IN-test", "TRACE-test")
    work = WorkSpy()
    audit = AuditSpy()
    server = create_server(SecurityEventTools(context=context, work=work, audit=audit))

    tools = await server.list_tools()
    assert [tool.name for tool in tools] == ["search_security_events"]
    assert set(tools[0].inputSchema["properties"]) == {
        "time_from",
        "time_to",
        "filters",
        "limit",
    }

    start = datetime(2026, 9, 21, 12, 0, tzinfo=UTC)
    end = start + timedelta(minutes=5)
    _content, structured = await server.call_tool(
        "search_security_events",
        {
            "time_from": start.isoformat(),
            "time_to": end.isoformat(),
            "filters": {"source": "web"},
            "limit": 2,
        },
    )

    assert structured == {"result": []}
    assert work.calls == [
        {
            "time_from": start,
            "time_to": end,
            "filters": {"source": "web"},
            "limit": 2,
            "incident_id": "IN-test",
        }
    ]
    assert len(audit.records) == 1
    assert audit.records[0].run_id == "AR-test"
    assert audit.records[0].result["trace_id"] == "TRACE-test"
