from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest
from evidencesoc.mcp_server.context import (
    RunContext,
    load_run_context,
    tool_attempt_limit,
)
from evidencesoc.mcp_server.main import create_server
from evidencesoc.tools.alert_context import AlertContextTools
from evidencesoc.tools.attack import AttackTools
from evidencesoc.tools.errors import (
    ToolDependencyError,
    ToolDependencyTimeout,
    ToolNotFoundError,
)
from evidencesoc.tools.policy import PolicyDeniedError
from evidencesoc.tools.security_events import SecurityEventTools
from mcp.types import CallToolResult


class WorkSpy:
    def __init__(self, result: object = None, error: Exception | None = None) -> None:
        self.result = [] if result is None else result
        self.error = error
        self.calls: list[dict[str, object]] = []

    def __call__(self, **kwargs: object) -> object:
        self.calls.append(kwargs)
        if self.error is not None:
            raise self.error
        return self.result


class AuditSpy:
    def __init__(self) -> None:
        self.records: list[object] = []

    def record(self, record: object) -> None:
        self.records.append(record)


def _server(
    *,
    event_work: WorkSpy | None = None,
    alert_work: WorkSpy | None = None,
    attack_work: WorkSpy | None = None,
) -> tuple[object, AuditSpy, AuditSpy, WorkSpy, WorkSpy, WorkSpy]:
    context = RunContext("AR-test", "IN-test", "TRACE-test")
    business_audit = AuditSpy()
    boundary_audit = AuditSpy()
    event_work = event_work or WorkSpy()
    alert_work = alert_work or WorkSpy()
    attack_work = attack_work or WorkSpy()
    event_tools = SecurityEventTools(
        context=context,
        work=event_work,
        audit=business_audit,
    )
    alert_tools = AlertContextTools(
        context=context,
        work=alert_work,
        audit=business_audit,
    )
    attack_tools = AttackTools(
        context=context,
        work=attack_work,
        audit=business_audit,
    )
    return (
        create_server(
            context=context,
            boundary_audit=boundary_audit,
            event_tools=event_tools,
            alert_tools=alert_tools,
            attack_tools=attack_tools,
        ),
        business_audit,
        boundary_audit,
        event_work,
        alert_work,
        attack_work,
    )


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


def test_tool_attempt_limit_defaults_to_three_and_accepts_managed_one() -> None:
    assert tool_attempt_limit({}) == 3
    assert tool_attempt_limit({"EVIDENCESOC_MAX_TOOL_ATTEMPTS": "1"}) == 1
    with pytest.raises(ValueError):
        tool_attempt_limit({"EVIDENCESOC_MAX_TOOL_ATTEMPTS": "4"})


@pytest.mark.asyncio
async def test_server_exposes_exactly_three_tools_without_private_context() -> None:
    server, _business, _boundary, _event, _alert, _attack = _server()

    tools = await server.list_tools()
    assert {tool.name for tool in tools} == {
        "search_security_events",
        "get_alert_context",
        "lookup_attack_technique",
    }
    assert len(tools) == 3
    for tool in tools:
        assert not (
            {"run_id", "incident_id", "trace_id"}
            & set(tool.inputSchema["properties"])
        )


@pytest.mark.asyncio
async def test_valid_tools_delegate_with_private_context_hidden() -> None:
    server, business, boundary, event, alert, attack = _server()
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
    await server.call_tool("get_alert_context", {"alert_id": "AL-1"})
    await server.call_tool("lookup_attack_technique", {"query": "T1190"})

    assert event.calls[0]["incident_id"] == "IN-test"
    assert alert.calls[0]["incident_id"] == "IN-test"
    assert attack.calls == [{"query": "T1190", "limit": 10}]
    assert len(business.records) == 3
    assert boundary.records == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("name", "arguments"),
    [
        ("run_shell", {}),
        ("get_alert_context", {}),
        (
            "search_security_events",
            {
                "time_from": 123,
                "time_to": "2026-09-21T12:05:00+00:00",
                "filters": {},
            },
        ),
        (
            "lookup_attack_technique",
            {"query": "T1190", "limit": 10, "extra": True},
        ),
    ],
)
async def test_boundary_denials_are_structured_and_audited_once(
    name: str,
    arguments: dict[str, object],
) -> None:
    server, business, boundary, *_ = _server()

    result = await server.call_tool(name, arguments)

    assert isinstance(result, CallToolResult)
    assert result.isError is True
    assert result.structuredContent == {
        "error": {
            "code": "POLICY_DENIED",
            "message": "request denied",
            "trace_id": "TRACE-test",
        }
    }
    assert json.loads(result.content[0].text) == result.structuredContent
    assert len(boundary.records) == 1
    assert business.records == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("error", "code", "message"),
    [
        (PolicyDeniedError("denied"), "POLICY_DENIED", "request denied"),
        (ToolNotFoundError("missing"), "NOT_FOUND", "resource not found"),
        (
            ToolDependencyTimeout("slow"),
            "DEPENDENCY_TIMEOUT",
            "dependency timed out",
        ),
        (
            ToolDependencyError("down"),
            "DEPENDENCY_UNAVAILABLE",
            "dependency unavailable",
        ),
    ],
)
async def test_business_coded_failures_are_not_double_audited(
    error: Exception,
    code: str,
    message: str,
) -> None:
    server, business, boundary, *_ = _server(event_work=WorkSpy(error=error))
    start = datetime(2026, 9, 21, 12, 0, tzinfo=UTC)

    result = await server.call_tool(
        "search_security_events",
        {
            "time_from": start.isoformat(),
            "time_to": (start + timedelta(minutes=5)).isoformat(),
            "filters": {},
        },
    )

    assert result.structuredContent["error"]["code"] == code
    assert result.structuredContent["error"]["message"] == message
    assert len(business.records) == 1
    assert boundary.records == []
