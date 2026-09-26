from __future__ import annotations

import json
from contextvars import ContextVar
from datetime import UTC, datetime
from time import monotonic
from typing import Any

from mcp.server.fastmcp import FastMCP
from mcp.types import CallToolResult, TextContent

from evidencesoc.execution import CALL_DEADLINE
from evidencesoc.mcp_server.context import RunContext
from evidencesoc.tools.audit import AuditWriter, ToolCallRecord
from evidencesoc.tools.errors import ToolExecutionError
from evidencesoc.tools.policy import ALLOWED_TOOLS, PolicyDeniedError
from evidencesoc.tools.runtime import write_audit

TOOL_ARGUMENTS: dict[str, tuple[frozenset[str], frozenset[str]]] = {
    "search_security_events": (
        frozenset({"time_from", "time_to", "filters"}),
        frozenset({"limit"}),
    ),
    "get_alert_context": (
        frozenset({"alert_id"}),
        frozenset({"before_seconds", "after_seconds"}),
    ),
    "lookup_attack_technique": (
        frozenset({"query"}),
        frozenset({"limit"}),
    ),
}

_BUSINESS_INVOKED: ContextVar[bool] = ContextVar(
    "evidencesoc_business_invoked",
    default=False,
)


def _error_result(code: str, message: str, trace_id: str) -> CallToolResult:
    payload = {
        "error": {
            "code": code,
            "message": message,
            "trace_id": trace_id,
        }
    }
    return CallToolResult(
        content=[
            TextContent(
                type="text",
                text=json.dumps(payload, ensure_ascii=False),
            )
        ],
        structuredContent=payload,
        isError=True,
    )


def _coded_error(error: BaseException) -> ToolExecutionError | PolicyDeniedError | None:
    current: BaseException | None = error
    while current is not None:
        if isinstance(current, (PolicyDeniedError, ToolExecutionError)):
            return current
        current = current.__cause__
    return None


def _valid_argument_types(name: str, arguments: dict[str, Any]) -> bool:
    if name == "search_security_events":
        return (
            isinstance(arguments.get("time_from"), str)
            and isinstance(arguments.get("time_to"), str)
            and isinstance(arguments.get("filters"), dict)
            and all(isinstance(key, str) and isinstance(value, str)
                    for key, value in arguments["filters"].items())
            and (
                "limit" not in arguments
                or (
                    isinstance(arguments["limit"], int)
                    and not isinstance(arguments["limit"], bool)
                )
            )
        )
    if name == "get_alert_context":
        return (
            isinstance(arguments.get("alert_id"), str)
            and all(
                key not in arguments
                or (
                    isinstance(arguments[key], int)
                    and not isinstance(arguments[key], bool)
                )
                for key in ("before_seconds", "after_seconds")
            )
        )
    return (
        isinstance(arguments.get("query"), str)
        and (
            "limit" not in arguments
            or (
                isinstance(arguments["limit"], int)
                and not isinstance(arguments["limit"], bool)
            )
        )
    )


class RestrictedFastMCP(FastMCP):
    def __init__(
        self,
        *,
        context: RunContext,
        boundary_audit: AuditWriter,
        deadline_seconds: float = 10.0,
    ) -> None:
        super().__init__("EvidenceSOC read-only investigation tools")
        self._context = context
        self._boundary_audit = boundary_audit
        self._deadline_seconds = deadline_seconds

    def mark_business_invoked(self) -> None:
        _BUSINESS_INVOKED.set(True)

    async def _audit_boundary_denial(
        self,
        *,
        tool_name: str,
        arguments: dict[str, Any],
        reason: str,
    ) -> None:
        record = ToolCallRecord(
            run_id=self._context.run_id,
            tool_name=tool_name,
            arguments=dict(arguments),
            result={"trace_id": self._context.trace_id, "reason": reason},
            started_at=datetime.now(UTC),
            finished_at=datetime.now(UTC),
            success=False,
            error_code="POLICY_DENIED",
        )
        await write_audit(self._boundary_audit, record, CALL_DEADLINE.get() or monotonic())

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        token = _BUSINESS_INVOKED.set(False)
        deadline_token = CALL_DEADLINE.set(monotonic() + self._deadline_seconds)
        try:
            if not isinstance(arguments, dict):
                arguments = {}
            expected = TOOL_ARGUMENTS.get(name)
            if name not in ALLOWED_TOOLS or expected is None:
                await self._audit_boundary_denial(
                    tool_name=name,
                    arguments=arguments,
                    reason="request denied",
                )
                return _error_result(
                    "POLICY_DENIED",
                    "request denied",
                    self._context.trace_id,
                )

            required, optional = expected
            keys = set(arguments)
            if not required <= keys or keys - required - optional:
                await self._audit_boundary_denial(
                    tool_name=name,
                    arguments=arguments,
                    reason="request denied",
                )
                return _error_result(
                    "POLICY_DENIED",
                    "request denied",
                    self._context.trace_id,
                )

            if not _valid_argument_types(name, arguments):
                await self._audit_boundary_denial(
                    tool_name=name,
                    arguments=arguments,
                    reason="request denied",
                )
                return _error_result(
                    "POLICY_DENIED",
                    "request denied",
                    self._context.trace_id,
                )

            try:
                return await super().call_tool(name, arguments)
            except Exception as exc:  # noqa: BLE001 - normalize all SDK boundary failures
                coded = _coded_error(exc)
                if coded is not None:
                    if isinstance(coded, PolicyDeniedError):
                        return _error_result(
                            coded.code,
                            "request denied",
                            self._context.trace_id,
                        )
                    return _error_result(
                        coded.code,
                        coded.public_message,
                        self._context.trace_id,
                    )
                if not _BUSINESS_INVOKED.get():
                    await self._audit_boundary_denial(
                        tool_name=name,
                        arguments=arguments,
                        reason="request denied",
                    )
                    return _error_result(
                        "POLICY_DENIED",
                        "request denied",
                        self._context.trace_id,
                    )
                return _error_result(
                    "DEPENDENCY_UNAVAILABLE",
                    "dependency unavailable",
                    self._context.trace_id,
                )
        except ToolExecutionError as exc:
            return _error_result(exc.code, exc.public_message, self._context.trace_id)
        finally:
            _BUSINESS_INVOKED.reset(token)
            CALL_DEADLINE.reset(deadline_token)
