from __future__ import annotations

import runpy
from collections.abc import Callable
from pathlib import Path
from types import FunctionType
from typing import Any

MIGRATION_PATH = (
    Path(__file__).resolve().parents[2]
    / "migrations"
    / "versions"
    / "f311d6238878_add_ingestion_trace_fields.py"
)


class RecordingOperations:
    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple[Any, ...], dict[str, Any]]] = []

    def __getattr__(self, name: str) -> Callable[..., None]:
        def record(*args: Any, **kwargs: Any) -> None:
            self.calls.append((name, args, kwargs))

        return record


def test_upgrade_backfills_legacy_rows_before_enforcing_constraints() -> None:
    namespace = runpy.run_path(str(MIGRATION_PATH))
    upgrade = namespace["upgrade"]
    assert isinstance(upgrade, FunctionType)
    operations = RecordingOperations()
    upgrade.__globals__["op"] = operations

    upgrade()

    evidence_column_call = next(
        call
        for call in operations.calls
        if call[0] == "add_column" and call[1][0] == "evidence_items"
    )
    deduplication_column_call = next(
        call
        for call in operations.calls
        if call[0] == "add_column"
        and call[1][0] == "security_events"
        and call[1][1].name == "deduplication_key"
    )
    assert evidence_column_call[1][1].nullable is True
    assert deduplication_column_call[1][1].nullable is True

    executed_sql = "\n".join(
        str(call[1][0]) for call in operations.calls if call[0] == "execute"
    )
    assert "ROW_NUMBER() OVER" in executed_sql
    assert "matched_event_id" in executed_sql
    assert "cannot backfill evidence_items.event_id" in executed_sql

    non_null_columns = {
        (call[1][0], call[1][1])
        for call in operations.calls
        if call[0] == "alter_column" and call[2].get("nullable") is False
    }
    assert non_null_columns == {
        ("security_events", "deduplication_key"),
        ("evidence_items", "event_id"),
    }

    evidence_non_null_index = next(
        index
        for index, call in enumerate(operations.calls)
        if call[0] == "alter_column" and call[1][:2] == ("evidence_items", "event_id")
    )
    evidence_foreign_key_index = next(
        index
        for index, call in enumerate(operations.calls)
        if call[0] == "create_foreign_key"
        and call[1][0] == "fk_evidence_items_event_id_security_events"
    )
    assert evidence_foreign_key_index > evidence_non_null_index
