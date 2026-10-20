from __future__ import annotations

from collections.abc import Callable
from datetime import datetime

from evidencesoc.domain.models import EvidenceItem
from evidencesoc.tools.audit import AuditWriter, ToolExecutionContext
from evidencesoc.tools.errors import ToolDependencyError
from evidencesoc.tools.incident_scope import validate_incident_search
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
        incident_scope: dict | Callable[[], dict] | None = None,
    ) -> None:
        self._context = context
        self._work = work
        self._audit = audit
        self._incident_scope = incident_scope

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

        def validate() -> None:
            validate_event_search(time_from, time_to, filters, limit)
            if self._incident_scope is not None:
                scope = (
                    self._incident_scope()
                    if callable(self._incident_scope)
                    else self._incident_scope
                )
                validate_incident_search(audit_arguments, scope)

        return await run_audited_tool(
            context=self._context,
            audit=self._audit,
            tool_name="search_security_events",
            arguments=audit_arguments,
            validate=validate,
            work=lambda: self._work(
                time_from=time_from,
                time_to=time_to,
                filters=filters,
                limit=limit,
                incident_id=self._context.incident_id,
            ),
            validate_result=lambda value: validate_evidence_items(value, limit=limit),
        )
