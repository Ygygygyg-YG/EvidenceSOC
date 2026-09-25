from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol


@dataclass(frozen=True)
class ToolCallRecord:
    run_id: str
    tool_name: str
    arguments: dict[str, Any]
    result: dict[str, Any]
    started_at: datetime
    finished_at: datetime
    success: bool
    error_code: str | None = None


class ToolExecutionContext(Protocol):
    run_id: str
    incident_id: str
    trace_id: str


class AuditWriter(Protocol):
    def record(self, record: ToolCallRecord) -> None: ...
