from __future__ import annotations

import json
from collections.abc import Iterator
from contextlib import nullcontext
from copy import deepcopy
from datetime import UTC, datetime, timedelta, timezone
from importlib import import_module
from typing import Any

import pytest
from evidencesoc.domain.models import EvidenceItem, SecurityEvent, Severity
from evidencesoc.evidence.service import (
    EvidenceIntegrityError,
    EvidenceService,
    EvidenceSourceNotFoundError,
)
from evidencesoc.ingestion.normalize import calculate_content_sha256
from evidencesoc.persistence.event_repository import (
    EventNotFoundError,
    EvidenceNotFoundError,
)
from opensearchpy.exceptions import ConnectionError as OpenSearchConnectionError
from sqlalchemy.exc import SQLAlchemyError

NOW = datetime(2026, 9, 21, 12, 0, tzinfo=UTC)
EVENT_ID = "SE-01J8ZW4AAA0ABCDEFGHJKMNPQR"
OTHER_EVENT_ID = "SE-01J8ZW4AAA1ABCDEFGHJKMNPQR"
EVIDENCE_ID = "EV-01J8ZW4AAA0ABCDEFGHJKMNPQR"
OTHER_EVIDENCE_ID = "EV-01J8ZW4AAA1ABCDEFGHJKMNPQR"
INCIDENT_ID = "IN-01J8ZW4AAA0ABCDEFGHJKMNPQR"


def make_event(**changes: Any) -> SecurityEvent:
    raw = {
        "source": "nginx",
        "external_id": "nginx-1",
        "observed_at": "2026-09-21T12:00:00Z",
        "event_type": "http.request",
        "severity": "high",
        "message": "possible SQL injection",
        "http": {"method": "GET", "path": "/search?q=' OR 1=1"},
    }
    values: dict[str, Any] = {
        "event_id": EVENT_ID,
        "source": "nginx",
        "external_id": "nginx-1",
        "deduplication_key": "id:nginx-1",
        "observed_at": NOW,
        "ingested_at": NOW,
        "severity": Severity.HIGH,
        "event_type": "http.request",
        "raw": raw,
        "content_sha256": calculate_content_sha256(raw),
    }
    values.update(changes)
    return SecurityEvent(**values)


def make_document(event: SecurityEvent, **changes: Any) -> dict[str, Any]:
    document: dict[str, Any] = {
        "event_id": event.event_id,
        "source": event.source,
        "external_id": event.external_id,
        "deduplication_key": event.deduplication_key,
        "observed_at": event.observed_at.isoformat(),
        "severity": event.severity.value,
        "event_type": event.event_type,
        "content_sha256": event.content_sha256,
        "raw_event": deepcopy(event.raw),
    }
    document.update(changes)
    return document


class FakeEventRepository:
    def __init__(self, events: dict[str, SecurityEvent]) -> None:
        self.events = events
        self.calls: list[str] = []

    def get(self, event_id: str) -> SecurityEvent:
        self.calls.append(event_id)
        try:
            return self.events[event_id]
        except KeyError as exc:
            raise EventNotFoundError(event_id) from exc


class FakeEvidenceRepository:
    def __init__(self) -> None:
        self.add_calls: list[tuple[str, list[EvidenceItem]]] = []
        self.items: dict[str, EvidenceItem] = {}

    def add_many(
        self,
        incident_id: str,
        items: list[EvidenceItem],
    ) -> list[EvidenceItem]:
        stored = list(items)
        self.add_calls.append((incident_id, stored))
        self.items.update({item.evidence_id: item for item in stored})
        return stored

    def get(self, evidence_id: str) -> EvidenceItem:
        try:
            return self.items[evidence_id]
        except KeyError as exc:
            raise EvidenceNotFoundError(evidence_id) from exc


class FakeSearchStore:
    def __init__(self, documents: dict[str, dict[str, Any]]) -> None:
        self.documents = documents
        self.calls: list[str] = []

    def get_document(self, event_id: str) -> dict[str, Any] | None:
        self.calls.append(event_id)
        return self.documents.get(event_id)


def id_factory(*values: str) -> tuple[Iterator[str], Any]:
    iterator = iter(values)
    return iterator, lambda: next(iterator)


def make_service(
    *events: SecurityEvent,
    documents: dict[str, dict[str, Any]] | None = None,
    evidence_ids: tuple[str, ...] = (EVIDENCE_ID,),
) -> tuple[
    EvidenceService,
    FakeEventRepository,
    FakeEvidenceRepository,
    FakeSearchStore,
]:
    event_repository = FakeEventRepository({event.event_id: event for event in events})
    evidence_repository = FakeEvidenceRepository()
    search_store = FakeSearchStore(
        documents
        if documents is not None
        else {event.event_id: make_document(event) for event in events}
    )
    _, factory = id_factory(*evidence_ids)
    service = EvidenceService(
        event_repository=event_repository,
        evidence_repository=evidence_repository,
        search_store=search_store,
        evidence_id_factory=factory,
    )
    return service, event_repository, evidence_repository, search_store


def test_create_for_events_builds_evidence_and_persists_one_batch() -> None:
    event = make_event()
    service, _, evidence_repository, _ = make_service(event)

    result = service.create_for_events(
        INCIDENT_ID,
        [event.event_id],
        {"event_type": "http.request"},
    )

    assert result == [
        EvidenceItem(
            evidence_id=EVIDENCE_ID,
            event_id=event.event_id,
            source=event.source,
            observed_at=event.observed_at,
            query={
                "event_type": "http.request",
                "matched_event_id": event.event_id,
            },
            summary=(
                f"{event.source} event {event.event_id} observed at "
                "2026-09-21T12:00:00+00:00: http.request (high)."
            ),
            content_sha256=event.content_sha256,
        )
    ]
    assert evidence_repository.add_calls == [(INCIDENT_ID, result)]


def test_create_for_events_copies_and_json_serializes_query() -> None:
    event = make_event()
    service, _, _, _ = make_service(event)
    query = {
        "window": {
            "start": datetime(
                2026,
                9,
                21,
                20,
                0,
                tzinfo=timezone(timedelta(hours=8)),
            )
        },
        "filters": ["http.request"],
        "matched_event_id": "caller-value",
    }
    original = deepcopy(query)

    item = service.create_for_events(
        INCIDENT_ID,
        [event.event_id],
        query,
    )[0]

    assert query == original
    assert item.query == {
        "window": {"start": "2026-09-21T12:00:00+00:00"},
        "filters": ["http.request"],
        "matched_event_id": event.event_id,
    }
    assert json.loads(json.dumps(item.query)) == item.query


def test_get_delegates_to_the_evidence_repository() -> None:
    event = make_event()
    service, _, _, _ = make_service(event)
    item = service.create_for_events(
        INCIDENT_ID,
        [event.event_id],
        {},
    )[0]

    assert service.get(item.evidence_id) == item

    with pytest.raises(EvidenceNotFoundError):
        service.get(OTHER_EVIDENCE_ID)


def test_create_for_events_reports_missing_postgres_event_without_writing() -> None:
    service, _, evidence_repository, search_store = make_service()

    with pytest.raises(EvidenceSourceNotFoundError, match="PostgreSQL"):
        service.create_for_events(INCIDENT_ID, [EVENT_ID], {})

    assert search_store.calls == []
    assert evidence_repository.add_calls == []


def test_create_for_events_reports_missing_opensearch_document_without_writing() -> (
    None
):
    event = make_event()
    service, _, evidence_repository, _ = make_service(event, documents={})

    with pytest.raises(EvidenceSourceNotFoundError, match="OpenSearch"):
        service.create_for_events(INCIDENT_ID, [event.event_id], {})

    assert evidence_repository.add_calls == []


def test_create_for_events_rejects_mismatched_opensearch_event_id() -> None:
    event = make_event()
    document = make_document(event, event_id=OTHER_EVENT_ID)
    service, _, evidence_repository, _ = make_service(
        event,
        documents={event.event_id: document},
    )

    with pytest.raises(EvidenceIntegrityError, match="event_id"):
        service.create_for_events(INCIDENT_ID, [event.event_id], {})

    assert evidence_repository.add_calls == []


def test_create_for_events_rejects_tampered_postgres_raw_event() -> None:
    untampered = make_event()
    tampered = untampered.model_copy(
        update={"raw": {**untampered.raw, "message": "altered"}}
    )
    service, _, evidence_repository, _ = make_service(
        tampered,
        documents={tampered.event_id: make_document(untampered)},
    )

    with pytest.raises(EvidenceIntegrityError, match="content hash"):
        service.create_for_events(INCIDENT_ID, [tampered.event_id], {})

    assert evidence_repository.add_calls == []


def test_create_for_events_rejects_tampered_postgres_normalized_metadata() -> None:
    untampered = make_event()
    tampered = untampered.model_copy(update={"source": "attacker-controlled"})
    service, _, evidence_repository, _ = make_service(
        tampered,
        documents={tampered.event_id: make_document(untampered)},
    )

    with pytest.raises(EvidenceIntegrityError, match="normalized metadata"):
        service.create_for_events(INCIDENT_ID, [tampered.event_id], {})

    assert evidence_repository.add_calls == []


def test_create_for_events_rejects_tampered_opensearch_normalized_metadata() -> None:
    event = make_event()
    service, _, evidence_repository, _ = make_service(
        event,
        documents={event.event_id: make_document(event, source="attacker-controlled")},
    )

    with pytest.raises(EvidenceIntegrityError, match="normalized metadata"):
        service.create_for_events(INCIDENT_ID, [event.event_id], {})

    assert evidence_repository.add_calls == []


@pytest.mark.parametrize(
    "document",
    [
        {
            "event_id": EVENT_ID,
            "content_sha256": make_event().content_sha256,
            "raw_event": {"message": "tampered"},
        },
        {
            "event_id": EVENT_ID,
            "content_sha256": "f" * 64,
            "raw_event": make_event().raw,
        },
    ],
    ids=["raw-event", "stored-hash"],
)
def test_create_for_events_rejects_tampered_opensearch_content(
    document: dict[str, Any],
) -> None:
    event = make_event()
    service, _, evidence_repository, _ = make_service(
        event,
        documents={event.event_id: document},
    )

    with pytest.raises(EvidenceIntegrityError, match="content hash"):
        service.create_for_events(INCIDENT_ID, [event.event_id], {})

    assert evidence_repository.add_calls == []


def test_create_for_events_validates_the_whole_batch_before_writing() -> None:
    first = make_event()
    second = make_event(
        event_id=OTHER_EVENT_ID,
        external_id="nginx-2",
        deduplication_key="id:nginx-2",
        raw={**first.raw, "external_id": "nginx-2"},
    )
    documents = {
        first.event_id: make_document(first),
        second.event_id: make_document(second, content_sha256="f" * 64),
    }
    service, event_repository, evidence_repository, search_store = make_service(
        first,
        second,
        documents=documents,
        evidence_ids=(EVIDENCE_ID, OTHER_EVIDENCE_ID),
    )

    with pytest.raises(EvidenceIntegrityError):
        service.create_for_events(
            INCIDENT_ID,
            [first.event_id, second.event_id],
            {"event_type": "http.request"},
        )

    assert event_repository.calls == [first.event_id, second.event_id]
    assert search_store.calls == [first.event_id, second.event_id]
    assert evidence_repository.add_calls == []


def test_event_work_retries_id_query_and_persists_one_batch() -> None:
    module = import_module("evidencesoc.tools.event_work")
    event = make_event()
    service, _, evidence_repository, _ = make_service(event)

    class Query:
        def __init__(self) -> None:
            self.calls = 0

        def search_event_ids(self, **_kwargs: object) -> list[str]:
            self.calls += 1
            if self.calls < 3:
                raise OpenSearchConnectionError("N/A", "offline")
            return [event.event_id]

    query = Query()
    work = module.EventSearchWork(
        query=query,
        evidence_factory=lambda: nullcontext(service),
    )

    result = work(
        time_from=NOW,
        time_to=NOW + timedelta(minutes=5),
        filters={},
        limit=2,
        incident_id=INCIDENT_ID,
    )

    assert query.calls == 3
    assert len(evidence_repository.add_calls) == 1
    assert evidence_repository.add_calls == [(INCIDENT_ID, result)]


def test_event_work_exhausted_query_never_persists() -> None:
    module = import_module("evidencesoc.tools.event_work")
    event = make_event()
    service, _, evidence_repository, _ = make_service(event)

    class Query:
        def __init__(self) -> None:
            self.calls = 0

        def search_event_ids(self, **_kwargs: object) -> list[str]:
            self.calls += 1
            raise OpenSearchConnectionError("N/A", "offline")

    query = Query()
    work = module.EventSearchWork(
        query=query,
        evidence_factory=lambda: nullcontext(service),
    )

    with pytest.raises(module.ToolDependencyError):
        work(
            time_from=NOW,
            time_to=NOW + timedelta(minutes=5),
            filters={},
            limit=2,
            incident_id=INCIDENT_ID,
        )

    assert query.calls == 3
    assert evidence_repository.add_calls == []


def test_event_work_managed_attempt_has_no_hidden_retry() -> None:
    module = import_module("evidencesoc.tools.event_work")

    class Query:
        calls = 0

        def search_event_ids(self, **_kwargs: object) -> list[str]:
            self.calls += 1
            raise OpenSearchConnectionError("N/A", "offline")

    query = Query()
    work = module.EventSearchWork(
        query=query,
        evidence_factory=lambda: nullcontext(None),
        max_attempts=1,
    )
    with pytest.raises(module.ToolDependencyError):
        work(
            time_from=NOW,
            time_to=NOW + timedelta(minutes=5),
            filters={},
            limit=2,
            incident_id=INCIDENT_ID,
        )
    assert query.calls == 1


def test_event_work_deadline_prevents_starting_evidence_write() -> None:
    module = import_module("evidencesoc.tools.event_work")
    event = make_event()
    service, _, evidence_repository, _ = make_service(event)

    class Clock:
        def __init__(self) -> None:
            self.now = 0.0

        def __call__(self) -> float:
            return self.now

    clock = Clock()

    class Query:
        def search_event_ids(self, **_kwargs: object) -> list[str]:
            clock.now = 10.1
            return [event.event_id]

    work = module.EventSearchWork(
        query=Query(),
        evidence_factory=lambda: nullcontext(service),
        clock=clock,
    )

    with pytest.raises(module.ToolDependencyTimeout):
        work(
            time_from=NOW,
            time_to=NOW + timedelta(minutes=5),
            filters={},
            limit=2,
            incident_id=INCIDENT_ID,
        )

    assert evidence_repository.add_calls == []


def test_event_work_builder_disables_hidden_opensearch_retries(
    monkeypatch: Any,
) -> None:
    module = import_module("evidencesoc.tools.event_work")
    captured: dict[str, object] = {}

    class FakeOpenSearch:
        def __init__(self, **kwargs: object) -> None:
            captured.update(kwargs)

    monkeypatch.setattr(module, "OpenSearch", FakeOpenSearch)
    work = module.build_event_search_work(
        opensearch_url="http://127.0.0.1:9200",
        index_name="security-events-v1",
        session_factory=lambda: None,
    )

    assert isinstance(work, module.EventSearchWork)
    assert captured == {
        "hosts": ["http://127.0.0.1:9200"],
        "max_retries": 0,
        "retry_on_status": (),
        "retry_on_timeout": False,
    }


def test_event_work_retries_server_timeout_then_persists_only_complete_results() -> None:
    module = import_module("evidencesoc.tools.event_work")
    event = make_event()
    service, _, evidence_repository, _ = make_service(event)

    class SearchClient:
        calls = 0

        def search(self, **_kwargs: object) -> dict[str, Any]:
            self.calls += 1
            return {
                "timed_out": self.calls < 3,
                "_shards": {"failed": 0},
                "hits": {"hits": [{"_id": event.event_id}]},
            }

    client = SearchClient()
    work = module.EventSearchWork(
        query=module.OpenSearchEventQuery(client, index_name="security-events-v1"),
        evidence_factory=lambda: nullcontext(service),
    )
    result = work(
        time_from=NOW,
        time_to=NOW + timedelta(minutes=5),
        filters={},
        limit=2,
        incident_id=INCIDENT_ID,
    )
    assert client.calls == 3
    assert evidence_repository.add_calls == [(INCIDENT_ID, result)]


def test_event_work_exhausted_server_timeout_never_creates_evidence() -> None:
    module = import_module("evidencesoc.tools.event_work")
    event = make_event()
    service, _, evidence_repository, _ = make_service(event)

    class SearchClient:
        calls = 0

        def search(self, **_kwargs: object) -> dict[str, Any]:
            self.calls += 1
            return {
                "timed_out": True,
                "_shards": {"failed": 0},
                "hits": {"hits": [{"_id": event.event_id}]},
            }

    client = SearchClient()
    work = module.EventSearchWork(
        query=module.OpenSearchEventQuery(client, index_name="security-events-v1"),
        evidence_factory=lambda: nullcontext(service),
    )
    with pytest.raises(module.ToolDependencyTimeout) as error:
        work(
            time_from=NOW,
            time_to=NOW + timedelta(minutes=5),
            filters={},
            limit=2,
            incident_id=INCIDENT_ID,
        )
    assert error.value.code == "DEPENDENCY_TIMEOUT"
    assert client.calls == 3
    assert evidence_repository.add_calls == []


def test_event_work_does_not_retry_evidence_creation_after_healthy_search() -> None:
    module = import_module("evidencesoc.tools.event_work")

    class Query:
        calls = 0

        def search_event_ids(self, **_kwargs: object) -> list[str]:
            self.calls += 1
            return [EVENT_ID]

    class UnavailableEvidence:
        calls = 0

        def create_for_events(self, **_kwargs: object) -> list[EvidenceItem]:
            self.calls += 1
            raise SQLAlchemyError("ambiguous persistence failure")

    query, service = Query(), UnavailableEvidence()
    work = module.EventSearchWork(
        query=query,
        evidence_factory=lambda: nullcontext(service),
    )
    with pytest.raises(module.ToolDependencyError) as error:
        work(
            time_from=NOW,
            time_to=NOW + timedelta(minutes=5),
            filters={},
            limit=2,
            incident_id=INCIDENT_ID,
        )
    assert error.value.code == "DEPENDENCY_UNAVAILABLE"
    assert query.calls == 1
    assert service.calls == 1
