from __future__ import annotations

from collections.abc import Callable

from sqlalchemy.orm import Session

from evidencesoc.ids import new_ulid
from evidencesoc.persistence.tables import ToolCallTable
from evidencesoc.tools.audit import ToolCallRecord


def new_tool_call_id() -> str:
    return f"TC-{new_ulid()}"


class SqlAuditWriter:
    def __init__(
        self,
        *,
        session_factory: Callable[[], Session],
        tool_call_id_factory: Callable[[], str] = new_tool_call_id,
    ) -> None:
        self._session_factory = session_factory
        self._tool_call_id_factory = tool_call_id_factory

    def record(self, record: ToolCallRecord) -> None:
        with self._session_factory() as session:
            session.add(
                ToolCallTable(
                    tool_call_id=self._tool_call_id_factory(),
                    run_id=record.run_id,
                    tool_name=record.tool_name,
                    arguments=dict(record.arguments),
                    result=dict(record.result),
                    started_at=record.started_at,
                    finished_at=record.finished_at,
                    success=record.success,
                    error_code=record.error_code,
                )
            )
            session.commit()
