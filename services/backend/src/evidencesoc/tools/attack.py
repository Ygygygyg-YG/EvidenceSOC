from __future__ import annotations

from collections.abc import Callable
from typing import Any

from evidencesoc.tools.audit import AuditWriter, ToolExecutionContext
from evidencesoc.tools.errors import ToolDependencyError
from evidencesoc.tools.policy import validate_attack_lookup
from evidencesoc.tools.runtime import run_audited_tool

ATTACK_RESULT_FIELDS = frozenset(
    {
        "knowledge_chunk_id",
        "technique_id",
        "title",
        "summary",
        "source_uri",
        "version",
    }
)


def validate_attack_results(value: object, *, limit: int) -> int:
    if not isinstance(value, list) or len(value) > limit:
        raise ToolDependencyError("attack lookup returned invalid results")
    for item in value:
        if (
            not isinstance(item, dict)
            or set(item) != ATTACK_RESULT_FIELDS
            or any(
                not isinstance(field, str) or not field.strip()
                for field in item.values()
            )
        ):
            raise ToolDependencyError("attack lookup returned invalid results")
    return len(value)


class AttackTools:
    def __init__(
        self,
        *,
        context: ToolExecutionContext,
        work: Callable[..., list[dict[str, str]]],
        audit: AuditWriter,
    ) -> None:
        self._context = context
        self._work = work
        self._audit = audit

    async def lookup_attack_technique(
        self,
        query: str,
        limit: int = 10,
    ) -> list[dict[str, str]]:
        arguments: dict[str, Any] = {"query": query, "limit": limit}
        return await run_audited_tool(
            context=self._context,
            audit=self._audit,
            tool_name="lookup_attack_technique",
            arguments=arguments,
            validate=lambda: validate_attack_lookup(query, limit),
            work=lambda: self._work(query=query, limit=limit),
            validate_result=lambda value: validate_attack_results(
                value,
                limit=limit,
            ),
        )
