from __future__ import annotations

from collections.abc import Callable

from evidencesoc.domain.models import EvidenceItem
from evidencesoc.tools.audit import AuditWriter, ToolExecutionContext
from evidencesoc.tools.policy import validate_alert_context
from evidencesoc.tools.runtime import run_audited_tool, validate_evidence_items

MAX_ALERT_CONTEXT_RESULTS = 200


class AlertContextTools:
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

    async def get_alert_context(
        self,
        alert_id: str,
        before_seconds: int = 900,
        after_seconds: int = 900,
    ) -> list[EvidenceItem]:
        arguments = {
            "alert_id": alert_id,
            "before_seconds": before_seconds,
            "after_seconds": after_seconds,
        }
        return await run_audited_tool(
            context=self._context,
            audit=self._audit,
            tool_name="get_alert_context",
            arguments=arguments,
            validate=lambda: validate_alert_context(
                alert_id,
                before_seconds,
                after_seconds,
            ),
            work=lambda: self._work(
                **arguments,
                incident_id=self._context.incident_id,
            ),
            validate_result=lambda value: validate_evidence_items(
                value,
                limit=MAX_ALERT_CONTEXT_RESULTS,
            ),
        )
