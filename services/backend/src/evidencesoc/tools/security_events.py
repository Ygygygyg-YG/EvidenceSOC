from __future__ import annotations

from collections.abc import Callable
from datetime import datetime

from evidencesoc.domain.models import EvidenceItem
from evidencesoc.tools.audit import AuditWriter, ToolExecutionContext
from evidencesoc.tools.errors import ToolDependencyError
from evidencesoc.tools.policy import validate_event_search
from evidencesoc.tools.runtime import run_audited_tool, validate_evidence_items

__all__ = ("SecurityEventTools", "ToolDependencyError")


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
        audit_arguments = {
            "time_from": time_from.isoformat(),
            "time_to": time_to.isoformat(),
            "filters": dict(filters),
            "limit": limit,
        }
        return await run_audited_tool(
            context=self._context,
            audit=self._audit,
            tool_name="search_security_events",
            arguments=audit_arguments,
            validate=lambda: validate_event_search(time_from, time_to, filters, limit),
            work=lambda: self._work(
                time_from=time_from,
                time_to=time_to,
                filters=filters,
                limit=limit,
                incident_id=self._context.incident_id,
            ),
            validate_result=lambda value: validate_evidence_items(value, limit=limit),
        )
