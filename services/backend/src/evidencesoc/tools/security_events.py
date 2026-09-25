from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import UTC, datetime

from evidencesoc.domain.models import EvidenceItem
from evidencesoc.tools.audit import (
    AuditWriter,
    ToolCallRecord,
    ToolExecutionContext,
)
from evidencesoc.tools.policy import (
    PolicyDeniedError,
    validate_event_search,
)


class ToolDependencyError(RuntimeError):
    code = "DEPENDENCY_UNAVAILABLE"


class SecurityEventTools:
    def __init__(
        self,
        *,
        context: ToolExecutionContext,
        work: Callable[..., list[EvidenceItem]],
        audit: AuditWriter,
    ) -> None:
        self._context = context
        self._work = work
        self._audit = audit

    async def search_security_events(
        self,
        time_from: datetime,
        time_to: datetime,
        filters: dict[str, str],
        limit: int = 100,
    ) -> list[EvidenceItem]:
        started_at = datetime.now(UTC)

        try:
            validate_event_search(time_from, time_to, filters, limit)
        except PolicyDeniedError as exc:
            record = ToolCallRecord(
                run_id=self._context.run_id,
                tool_name="search_security_events",
                arguments={
                    "time_from": time_from.isoformat(),
                    "time_to": time_to.isoformat(),
                    "filters": filters,
                    "limit": limit,
                },
                result={
                    "trace_id": self._context.trace_id,
                    "reason": str(exc),
                },
                started_at=started_at,
                finished_at=datetime.now(UTC),
                success=False,
                error_code=exc.code,
            )
            await asyncio.to_thread(self._audit.record, record)
            raise

        try:
            events = await asyncio.to_thread(
                self._work,
                time_from=time_from,
                time_to=time_to,
                filters=filters,
                limit=limit,
                incident_id=self._context.incident_id,
            )
        except ToolDependencyError as exc:
            failure = ToolCallRecord(
                run_id=self._context.run_id,
                tool_name="search_security_events",
                arguments={
                    "time_from": time_from.isoformat(),
                    "time_to": time_to.isoformat(),
                    "filters": filters,
                    "limit": limit,
                },
                result={
                    "trace_id": self._context.trace_id,
                    "reason": str(exc),
                },
                started_at=started_at,
                finished_at=datetime.now(UTC),
                success=False,
                error_code=exc.code,
            )
            await asyncio.to_thread(self._audit.record, failure)
            raise
        if not isinstance(events, list):
            reason = "event search returned a non-list result"
            result_count = None
        elif len(events) > limit:
            reason = f"event search returned {len(events)} results above limit {limit}"
            result_count = len(events)
        elif any(not isinstance(event, EvidenceItem) for event in events):
            reason = "event search returned a non-EvidenceItem result"
            result_count = len(events)
        else:
            reason = None
            result_count = len(events)

        if reason is not None:
            error = ToolDependencyError(reason)
            failure = ToolCallRecord(
                run_id=self._context.run_id,
                tool_name="search_security_events",
                arguments={
                    "time_from": time_from.isoformat(),
                    "time_to": time_to.isoformat(),
                    "filters": filters,
                    "limit": limit,
                },
                result={
                    "trace_id": self._context.trace_id,
                    "reason": reason,
                    "result_count": result_count,
                },
                started_at=started_at,
                finished_at=datetime.now(UTC),
                success=False,
                error_code=error.code,
            )
            await asyncio.to_thread(self._audit.record, failure)
            raise error

        record = ToolCallRecord(
            run_id=self._context.run_id,
            tool_name="search_security_events",
            arguments={
                "time_from": time_from.isoformat(),
                "time_to": time_to.isoformat(),
                "filters": filters,
                "limit": limit,
            },
            result={
                "trace_id": self._context.trace_id,
                "result_count": len(events),
            },
            started_at=started_at,
            finished_at=datetime.now(UTC),
            success=True,
        )
        await asyncio.to_thread(self._audit.record, record)
        return [event for event in events if isinstance(event, EvidenceItem)]
