from __future__ import annotations

import asyncio
from collections.abc import Callable
from contextvars import copy_context
from datetime import UTC, datetime
from time import monotonic
from typing import Any, TypeVar

from evidencesoc.domain.models import EvidenceItem
from evidencesoc.execution import CALL_DEADLINE, CURRENT_BUDGET, ExecutionBudget
from evidencesoc.tools.audit import AuditWriter, ToolCallRecord, ToolExecutionContext
from evidencesoc.tools.errors import (
    ToolDependencyError,
    ToolDependencyTimeout,
    ToolExecutionError,
)
from evidencesoc.tools.policy import PolicyDeniedError

T = TypeVar("T")


async def write_audit(audit: AuditWriter, record: ToolCallRecord, deadline: float) -> None:
    # Submit exactly once. A timed-out commit is ambiguous and must never be retried.
    token = CURRENT_BUDGET.set(ExecutionBudget(deadline))
    try:
        ctx = copy_context()
        future = asyncio.get_running_loop().run_in_executor(None, ctx.run, audit.record, record)
        try:
            async with asyncio.timeout(max(0, deadline - monotonic())):
                await asyncio.shield(future)
        except TimeoutError as exc:
            raise ToolDependencyTimeout("dependency timed out") from exc
        except ToolDependencyTimeout as exc:
            raise ToolDependencyTimeout("dependency timed out") from exc
        except Exception as exc:
            raise ToolDependencyError("dependency unavailable") from exc
        finally:
            # Retrieve any eventual exception after a timeout/cancellation.
            future.add_done_callback(lambda done: done.exception() if not done.cancelled() else None)
    finally:
        CURRENT_BUDGET.reset(token)


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
    deadline = min(CALL_DEADLINE.get() or float("inf"), monotonic() + deadline_seconds)
    budget = ExecutionBudget(deadline - min(1.0, deadline_seconds * 0.1))
    token = CURRENT_BUDGET.set(budget)
    record: ToolCallRecord | None = None
    result_count: int | None = None
    externally_cancelled = False

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
        async with asyncio.timeout(budget.remaining()):
            value = await asyncio.to_thread(work)
        if isinstance(value, list):
            result_count = len(value)
        result_count = validate_result(value)
    except asyncio.CancelledError:
        externally_cancelled = True
        budget.cancelled.set()
        record = failure("DEPENDENCY_TIMEOUT", "request cancelled")
        raise
    except PolicyDeniedError as exc:
        record = failure(exc.code, str(exc))
        raise
    except ToolExecutionError as exc:
        record = failure(exc.code, exc.public_message)
        raise
    except TimeoutError as exc:
        budget.cancelled.set()
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
        try:
            if record is not None:
                try:
                    await write_audit(audit, record, deadline)
                except ToolExecutionError:
                    if not externally_cancelled:
                        raise
        finally:
            budget.cancelled.set()
            CURRENT_BUDGET.reset(token)


def validate_evidence_items(value: object, *, limit: int) -> int:
    if not isinstance(value, list):
        raise ToolDependencyError("dependency returned a non-list result")
    if len(value) > limit:
        raise ToolDependencyError("dependency returned too many results")
    if any(not isinstance(item, EvidenceItem) for item in value):
        raise ToolDependencyError("dependency returned an invalid evidence item")
    return len(value)
