from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, TypeVar

from evidencesoc.domain.models import EvidenceItem
from evidencesoc.tools.audit import AuditWriter, ToolCallRecord, ToolExecutionContext
from evidencesoc.tools.errors import (
    ToolDependencyError,
    ToolDependencyTimeout,
    ToolExecutionError,
)
from evidencesoc.tools.policy import PolicyDeniedError

T = TypeVar("T")


async def run_audited_tool(  # noqa: UP047 - the shared contract uses TypeVar
    *,
    context: ToolExecutionContext,
    audit: AuditWriter,
    tool_name: str,
    arguments: dict[str, Any],
    validate: Callable[[], None],
    work: Callable[[], T],
    validate_result: Callable[[T], int],
    deadline_seconds: float = 10.0,
) -> T:
    started_at = datetime.now(UTC)
    record: ToolCallRecord | None = None
    result_count: int | None = None

    def failure(error_code: str, reason: str) -> ToolCallRecord:
        result: dict[str, Any] = {"trace_id": context.trace_id, "reason": reason}
        if result_count is not None:
            result["result_count"] = result_count
        return ToolCallRecord(
            run_id=context.run_id,
            tool_name=tool_name,
            arguments=arguments,
            result=result,
            started_at=started_at,
            finished_at=datetime.now(UTC),
            success=False,
            error_code=error_code,
        )

    try:
        validate()
        async with asyncio.timeout(deadline_seconds):
            value = await asyncio.to_thread(work)
        if isinstance(value, list):
            result_count = len(value)
        result_count = validate_result(value)
    except PolicyDeniedError as exc:
        record = failure(exc.code, str(exc))
        raise
    except ToolExecutionError as exc:
        record = failure(exc.code, exc.public_message)
        raise
    except TimeoutError as exc:
        timeout_error = ToolDependencyTimeout("dependency timed out")
        record = failure(timeout_error.code, timeout_error.public_message)
        raise timeout_error from exc
    except Exception as exc:
        dependency_error = ToolDependencyError("dependency unavailable")
        record = failure(dependency_error.code, dependency_error.public_message)
        raise dependency_error from exc
    else:
        record = ToolCallRecord(
            run_id=context.run_id,
            tool_name=tool_name,
            arguments=arguments,
            result={"trace_id": context.trace_id, "result_count": result_count},
            started_at=started_at,
            finished_at=datetime.now(UTC),
            success=True,
        )
        return value
    finally:
        if record is not None:
            await asyncio.to_thread(audit.record, record)


def validate_evidence_items(value: object, *, limit: int) -> int:
    if not isinstance(value, list):
        raise ToolDependencyError("dependency returned a non-list result")
    if len(value) > limit:
        raise ToolDependencyError("dependency returned too many results")
    if any(not isinstance(item, EvidenceItem) for item in value):
        raise ToolDependencyError("dependency returned an invalid evidence item")
    return len(value)
