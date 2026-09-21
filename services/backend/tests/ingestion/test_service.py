from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

import pytest
from evidencesoc.domain.models import EventIndexStatus, SecurityEvent
from evidencesoc.ingestion.normalize import NormalizationError
from evidencesoc.ingestion.service import (
    ImportReport,
    IngestionConflictError,
    IngestionService,
)
from evidencesoc.persistence.event_repository import (
    EventContentConflictError,
    PersistResult,
)

NOW = datetime(2026, 9, 21, 12, 0, tzinfo=UTC)
EVENT_ID_1 = "SE-01J8ZW4AAA0ABCDEFGHJKMNPQR"
EVENT_ID_2 = "SE-01J8ZW4AAA1ABCDEFGHJKMNPQR"
EVENT_ID_3 = "SE-01J8ZW4AAA2ABCDEFGHJKMNPQR"


class MemoryRepository:
    def __init__(self) -> None:
        self.events: dict[str, SecurityEvent] = {}
        self.event_ids_by_key: dict[tuple[str, str], str] = {}
        self.register_calls: list[SecurityEvent] = []

    def register(self, event: SecurityEvent) -> PersistResult:
        self.register_calls.append(event)
        key = (event.source, event.deduplication_key)
        existing_event_id = self.event_ids_by_key.get(key)
        if existing_event_id is not None:
            existing = self.events[existing_event_id]
            if existing.content_sha256 != event.content_sha256:
                raise EventContentConflictError(
                    source=event.source,
                    deduplication_key=event.deduplication_key,
                    existing_event_id=existing.event_id,
                )
            return PersistResult(event=existing, created=False)

        self.events[event.event_id] = event
        self.event_ids_by_key[key] = event.event_id
        return PersistResult(event=event, created=True)

    def mark_indexed(
        self,
        event_id: str,
        *,
        indexed_at: datetime | None = None,
    ) -> None:
        event = self.events[event_id]
        self.events[event_id] = event.model_copy(
            update={
                "index_status": EventIndexStatus.INDEXED,
                "indexed_at": indexed_at,
                "index_error": None,
            }
        )

    def mark_index_failed(self, event_id: str, error: str) -> None:
        event = self.events[event_id]
        self.events[event_id] = event.model_copy(
            update={
                "index_status": EventIndexStatus.FAILED,
                "indexed_at": None,
                "index_error": error,
            }
        )

    def list_indexable(self, *, limit: int = 100) -> list[SecurityEvent]:
        return [
            event
            for event in self.events.values()
            if event.index_status is not EventIndexStatus.INDEXED
        ][:limit]


class RecordingSearchStore:
    def __init__(self) -> None:
        self.events: list[SecurityEvent] = []

    def index_event(self, event: SecurityEvent) -> None:
        self.events.append(event)


def write_jsonl(path: Path, *records: dict[str, object]) -> Path:
    path.write_text(
        "".join(f"{json.dumps(record)}\n" for record in records),
        encoding="utf-8",
    )
    return path


def event_id_factory(*event_ids: str) -> Callable[[], str]:
    return iter(event_ids).__next__


def test_import_file_indexes_a_new_event_and_reports_the_persisted_id(
    tmp_path: Path,
) -> None:
    log_path = write_jsonl(
        tmp_path / "events.jsonl",
        {
            "source": "WAF",
            "external_id": "waf-1",
            "observed_at": "2026-09-21T11:59:00Z",
            "severity": "high",
            "event_type": "HTTP.REQUEST",
            "message": "SQL keyword observed",
        },
    )
    repository = MemoryRepository()
    search_store = RecordingSearchStore()
    service = IngestionService(
        repository,
        search_store,
        clock=lambda: NOW,
        event_id_factory=event_id_factory(EVENT_ID_1),
    )

    report = service.import_file(log_path)

    assert report == ImportReport(
        total=1,
        inserted=1,
        duplicated=0,
        indexed=1,
        failed=0,
        event_ids=[EVENT_ID_1],
    )
    assert search_store.events[0].event_id == EVENT_ID_1
    assert repository.events[EVENT_ID_1].index_status is EventIndexStatus.INDEXED


def test_duplicate_import_reuses_the_persisted_id_and_skips_an_indexed_event(
    tmp_path: Path,
) -> None:
    log_path = write_jsonl(
        tmp_path / "events.jsonl",
        {
            "source": "waf",
            "external_id": "waf-1",
            "observed_at": "2026-09-21T11:59:00Z",
            "event_type": "http.request",
        },
    )
    repository = MemoryRepository()
    search_store = RecordingSearchStore()
    service = IngestionService(
        repository,
        search_store,
        clock=lambda: NOW,
        event_id_factory=event_id_factory(
            EVENT_ID_1,
            "SE-01J8ZW4AAA1ABCDEFGHJKMNPQR",
        ),
    )

    first_report = service.import_file(log_path)
    duplicate_report = service.import_file(log_path)

    assert first_report.inserted == 1
    assert duplicate_report == ImportReport(
        total=1,
        inserted=0,
        duplicated=1,
        indexed=0,
        failed=0,
        event_ids=[EVENT_ID_1],
    )
    assert [event.event_id for event in search_store.events] == [EVENT_ID_1]


def test_import_file_finishes_preprocessing_before_any_persistence_write(
    tmp_path: Path,
) -> None:
    log_path = write_jsonl(
        tmp_path / "events.jsonl",
        {
            "source": "waf",
            "external_id": "waf-1",
            "observed_at": "2026-09-21T11:59:00Z",
            "event_type": "http.request",
        },
        {
            "source": "waf",
            "external_id": "waf-2",
            "observed_at": "not-a-time",
            "event_type": "http.request",
        },
    )
    repository = MemoryRepository()
    search_store = RecordingSearchStore()
    service = IngestionService(
        repository,
        search_store,
        clock=lambda: NOW,
        event_id_factory=event_id_factory(
            EVENT_ID_1,
            "SE-01J8ZW4AAA1ABCDEFGHJKMNPQR",
        ),
    )

    with pytest.raises(NormalizationError, match="INVALID_OBSERVED_AT"):
        service.import_file(log_path)

    assert repository.register_calls == []
    assert search_store.events == []


def test_import_file_propagates_a_content_conflict_for_the_same_external_id(
    tmp_path: Path,
) -> None:
    log_path = tmp_path / "events.jsonl"
    original = {
        "source": "waf",
        "external_id": "waf-1",
        "observed_at": "2026-09-21T11:59:00Z",
        "event_type": "http.request",
        "message": "original",
    }
    repository = MemoryRepository()
    search_store = RecordingSearchStore()
    service = IngestionService(
        repository,
        search_store,
        clock=lambda: NOW,
        event_id_factory=event_id_factory(
            EVENT_ID_1,
            "SE-01J8ZW4AAA1ABCDEFGHJKMNPQR",
        ),
    )
    service.import_file(write_jsonl(log_path, original))
    changed = {**original, "message": "changed"}

    with pytest.raises(EventContentConflictError) as exc_info:
        service.import_file(write_jsonl(log_path, changed))

    assert exc_info.value.existing_event_id == EVENT_ID_1
    assert [event.event_id for event in search_store.events] == [EVENT_ID_1]


def test_multi_record_conflict_exposes_the_partial_import_report(
    tmp_path: Path,
) -> None:
    repository = MemoryRepository()
    search_store = RecordingSearchStore()
    service = IngestionService(
        repository,
        search_store,
        clock=lambda: NOW,
        event_id_factory=event_id_factory(EVENT_ID_1, EVENT_ID_2, EVENT_ID_3),
    )
    service.import_file(
        write_jsonl(
            tmp_path / "existing.jsonl",
            {
                "source": "waf",
                "external_id": "existing",
                "observed_at": "2026-09-21T11:58:00Z",
                "event_type": "http.request",
                "message": "original",
            },
        )
    )

    with pytest.raises(IngestionConflictError) as exc_info:
        service.import_file(
            write_jsonl(
                tmp_path / "batch.jsonl",
                {
                    "source": "waf",
                    "external_id": "new",
                    "observed_at": "2026-09-21T11:59:00Z",
                    "event_type": "http.request",
                },
                {
                    "source": "waf",
                    "external_id": "existing",
                    "observed_at": "2026-09-21T11:58:00Z",
                    "event_type": "http.request",
                    "message": "changed",
                },
            )
        )

    assert exc_info.value.partial_report == ImportReport(
        total=2,
        inserted=1,
        duplicated=0,
        indexed=1,
        failed=1,
        event_ids=[EVENT_ID_2, EVENT_ID_1],
    )
    assert [event.event_id for event in search_store.events] == [
        EVENT_ID_1,
        EVENT_ID_2,
    ]
