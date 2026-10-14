from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class RunContext:
    run_id: str
    incident_id: str
    trace_id: str

    def __post_init__(self) -> None:
        for name in ("run_id", "incident_id", "trace_id"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must not be blank")


def load_run_context(environ: Mapping[str, str]) -> RunContext:
    keys = {
        "run_id": "EVIDENCESOC_RUN_ID",
        "incident_id": "EVIDENCESOC_INCIDENT_ID",
        "trace_id": "EVIDENCESOC_TRACE_ID",
    }
    values: dict[str, str] = {}
    for field, key in keys.items():
        value = environ.get(key, "")
        if not value.strip():
            raise ValueError(f"{key} must not be blank")
        values[field] = value
    return RunContext(**values)


def tool_attempt_limit(environ: Mapping[str, str]) -> int:
    """Use one worker attempt when an outer durable ledger owns retries."""
    value = environ.get("EVIDENCESOC_MAX_TOOL_ATTEMPTS", "3")
    if value not in {"1", "2", "3"}:
        raise ValueError("EVIDENCESOC_MAX_TOOL_ATTEMPTS must be 1, 2, or 3")
    return int(value)
