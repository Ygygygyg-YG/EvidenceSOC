from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from evidencesoc.domain.models import SecurityEvent
from evidencesoc.ids import new_event_id
from evidencesoc.ingestion.jsonl import parse_log_file
from evidencesoc.ingestion.normalize import normalize_record
from evidencesoc.persistence.event_repository import (
    EventContentConflictError,
    PersistResult,
)


class EventRepositoryPort(Protocol):
    def register(self, event: SecurityEvent) -> PersistResult: ...

    def mark_indexed(
        self,
        event_id: str,
        *,
        indexed_at: datetime | None = None,
    ) -> None: ...

    def mark_index_failed(self, event_id: str, error: str) -> None: ...

    def list_indexable(self, *, limit: int = 100) -> list[SecurityEvent]: ...


class EventSearchStorePort(Protocol):
    def index_event(self, event: SecurityEvent) -> None: ...


@dataclass(frozen=True, slots=True)
class ImportReport:
    total: int
    inserted: int
    duplicated: int
    indexed: int
    failed: int
    event_ids: list[str]


class IngestionConflictError(EventContentConflictError):
    def __init__(
        self,
        conflict: EventContentConflictError,
        partial_report: ImportReport,
    ) -> None:
        self.partial_report = partial_report
        super().__init__(
            source=conflict.source,
            deduplication_key=conflict.deduplication_key,
            existing_event_id=conflict.existing_event_id,
        )


def _utc_now() -> datetime:
    return datetime.now(UTC)


class IngestionService:
    def __init__(
        self,
        repository: EventRepositoryPort,
        search_store: EventSearchStorePort,
        *,
        clock: Callable[[], datetime] = _utc_now,
        event_id_factory: Callable[[], str] = new_event_id,
    ) -> None:
        self._repository = repository
        self._search_store = search_store
        self._clock = clock
        self._event_id_factory = event_id_factory

    def import_file(self, path: Path) -> ImportReport:
        records = parse_log_file(path)
        events = [
            normalize_record(
                record,
                event_id=self._event_id_factory(),
                ingested_at=self._clock(),
            )
            for record in records
        ]

        inserted = 0
        duplicated = 0
        indexed = 0
        failed = 0
        event_ids: list[str] = []

        for event in events:
            try:
                result = self._repository.register(event)
            except EventContentConflictError as exc:
                partial_report = ImportReport(
                    total=len(events),
                    inserted=inserted,
                    duplicated=duplicated,
                    indexed=indexed,
                    failed=failed + 1,
                    event_ids=[*event_ids, exc.existing_event_id],
                )
                raise IngestionConflictError(exc, partial_report) from exc
            event_ids.append(result.event_id)
            if result.created:
                inserted += 1
            else:
                duplicated += 1

            if result.needs_indexing:
                if self._index_event(result.event):
                    indexed += 1
                else:
                    failed += 1

        return ImportReport(
            total=len(events),
            inserted=inserted,
            duplicated=duplicated,
            indexed=indexed,
            failed=failed,
            event_ids=event_ids,
        )

    def retry_pending_events(self, limit: int = 100) -> ImportReport:
        events = self._repository.list_indexable(limit=limit)
        indexed = 0
        failed = 0

        for event in events:
            if self._index_event(event):
                indexed += 1
            else:
                failed += 1

        return ImportReport(
            total=len(events),
            inserted=0,
            duplicated=0,
            indexed=indexed,
            failed=failed,
            event_ids=[event.event_id for event in events],
        )

    def _index_event(self, event: SecurityEvent) -> bool:
        try:
            self._search_store.index_event(event)
        # Indexing is an external dependency boundary. Any client/transport
        # failure must be recorded so that later events and retries can proceed.
        except Exception as exc:  # noqa: BLE001
            error = str(exc).strip() or type(exc).__name__
            self._repository.mark_index_failed(event.event_id, error)
            return False

        self._repository.mark_indexed(
            event.event_id,
            indexed_at=self._clock(),
        )
        return True
