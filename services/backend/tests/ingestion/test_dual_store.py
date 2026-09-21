from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from evidencesoc.domain.models import EventIndexStatus, SecurityEvent
from evidencesoc.ingestion.service import ImportReport, IngestionService
from evidencesoc.persistence.event_repository import PersistResult

NOW = datetime(2026, 9, 21, 12, 0, tzinfo=UTC)
EVENT_ID_1 = "SE-01J8ZW4AAA0ABCDEFGHJKMNPQR"
EVENT_ID_2 = "SE-01J8ZW4AAA1ABCDEFGHJKMNPQR"


class TrackingRepository:
    def __init__(self) -> None:
        self.events: dict[str, SecurityEvent] = {}
        self.marked_indexed: list[str] = []
        self.marked_failed: list[tuple[str, str]] = []
        self.requested_limits: list[int] = []

    def register(self, event: SecurityEvent) -> PersistResult:
        self.events[event.event_id] = event
        return PersistResult(event=event, created=True)

    def mark_indexed(
        self,
        event_id: str,
        *,
        indexed_at: datetime | None = None,
    ) -> None:
        self.marked_indexed.append(event_id)
        self.events[event_id] = self.events[event_id].model_copy(
            update={
                "index_status": EventIndexStatus.INDEXED,
                "indexed_at": indexed_at,
                "index_error": None,
            }
        )

    def mark_index_failed(self, event_id: str, error: str) -> None:
        self.marked_failed.append((event_id, error))
        self.events[event_id] = self.events[event_id].model_copy(
            update={
                "index_status": EventIndexStatus.FAILED,
                "indexed_at": None,
                "index_error": error,
            }
        )

    def list_indexable(self, *, limit: int = 100) -> list[SecurityEvent]:
        self.requested_limits.append(limit)
        return [
            event
            for event in self.events.values()
            if event.index_status
            in {
                EventIndexStatus.PENDING,
                EventIndexStatus.FAILED,
            }
        ][:limit]


class ControlledSearchStore:
    def __init__(self, failures_remaining: dict[str, int] | None = None) -> None:
        self.failures_remaining = dict(failures_remaining or {})
        self.attempted_ids: list[str] = []

    def index_event(self, event: SecurityEvent) -> None:
        self.attempted_ids.append(event.event_id)
        remaining = self.failures_remaining.get(event.event_id, 0)
        if remaining > 0:
            self.failures_remaining[event.event_id] = remaining - 1
            raise RuntimeError("OpenSearch unavailable")


def write_two_events(path: Path) -> Path:
    records = [
        {
            "source": "waf",
            "external_id": "waf-1",
            "observed_at": "2026-09-21T11:59:00Z",
            "event_type": "http.request",
        },
        {
            "source": "waf",
            "external_id": "waf-2",
            "observed_at": "2026-09-21T11:59:30Z",
            "event_type": "http.request",
        },
    ]
    path.write_text(
        "".join(f"{json.dumps(record)}\n" for record in records),
        encoding="utf-8",
    )
    return path


def test_index_failure_is_recorded_without_blocking_later_events(
    tmp_path: Path,
) -> None:
    repository = TrackingRepository()
    search_store = ControlledSearchStore({EVENT_ID_1: 1})
    service = IngestionService(
        repository,
        search_store,
        clock=lambda: NOW,
        event_id_factory=iter((EVENT_ID_1, EVENT_ID_2)).__next__,
    )

    report = service.import_file(write_two_events(tmp_path / "events.jsonl"))

    assert report == ImportReport(
        total=2,
        inserted=2,
        duplicated=0,
        indexed=1,
        failed=1,
        event_ids=[EVENT_ID_1, EVENT_ID_2],
    )
    assert search_store.attempted_ids == [EVENT_ID_1, EVENT_ID_2]
    assert repository.marked_failed == [(EVENT_ID_1, "OpenSearch unavailable")]
    assert repository.marked_indexed == [EVENT_ID_2]


def test_retry_pending_events_reuses_the_event_id_after_recovery(
    tmp_path: Path,
) -> None:
    repository = TrackingRepository()
    search_store = ControlledSearchStore({EVENT_ID_1: 1})
    service = IngestionService(
        repository,
        search_store,
        clock=lambda: NOW,
        event_id_factory=iter((EVENT_ID_1, EVENT_ID_2)).__next__,
    )
    service.import_file(write_two_events(tmp_path / "events.jsonl"))

    report = service.retry_pending_events(limit=5)

    assert report == ImportReport(
        total=1,
        inserted=0,
        duplicated=0,
        indexed=1,
        failed=0,
        event_ids=[EVENT_ID_1],
    )
    assert search_store.attempted_ids == [EVENT_ID_1, EVENT_ID_2, EVENT_ID_1]
    assert repository.requested_limits == [5]
    assert repository.events[EVENT_ID_1].index_status is EventIndexStatus.INDEXED
