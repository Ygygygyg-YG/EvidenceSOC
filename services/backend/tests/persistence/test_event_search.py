from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from evidencesoc.domain.models import SecurityEvent, Severity
from evidencesoc.persistence.event_search import (
    OpenSearchEventStore,
    build_event_document,
    create_opensearch_client,
)
from opensearchpy.exceptions import NotFoundError

NOW = datetime(2026, 9, 21, 12, 0, tzinfo=UTC)
SHA256 = "a" * 64


def make_event(**changes: Any) -> SecurityEvent:
    values: dict[str, Any] = {
        "event_id": "SE-01J8ZW4AAA0ABCDEFGHJKMNPQR",
        "source": "web",
        "external_id": "event-1",
        "deduplication_key": "id:event-1",
        "observed_at": NOW,
        "ingested_at": NOW,
        "severity": Severity.HIGH,
        "event_type": "http.request",
        "raw": {
            "path": "/search",
            "nested": {"status": 500},
            "source_ip": "203.0.113.10",
            "destination_ip": "192.0.2.10",
            "source_port": 54545,
            "destination_port": 443,
            "host": "web-01",
            "service": "https",
            "message": "possible SQL injection",
            "tags": ["web", "sqli"],
            "http": {"method": "GET", "path": "/search"},
        },
        "content_sha256": SHA256,
    }
    values.update(changes)
    return SecurityEvent(**values)


class RecordingOpenSearchClient:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def index(self, **kwargs: object) -> None:
        self.calls.append(kwargs)

    def get(self, **kwargs: object) -> dict[str, object]:
        self.calls.append(kwargs)
        return {"_source": {"event_id": kwargs["id"]}}


def test_build_event_document_serializes_search_fields_and_retains_raw_event() -> None:
    event = make_event()

    document = build_event_document(event)

    assert document["event_id"] == event.event_id
    assert document["severity"] == "high"
    assert document["observed_at"] == "2026-09-21T12:00:00+00:00"
    assert document["raw_event"] == event.raw
    assert document["source_ip"] == "203.0.113.10"
    assert document["destination_ip"] == "192.0.2.10"
    assert document["source_port"] == 54545
    assert document["destination_port"] == 443
    assert document["host"] == "web-01"
    assert document["service"] == "https"
    assert document["message"] == "possible SQL injection"
    assert document["tags"] == ["web", "sqli"]
    assert document["http"] == {"method": "GET", "path": "/search"}


def test_event_store_uses_event_id_as_the_opensearch_document_id() -> None:
    client = RecordingOpenSearchClient()
    event = make_event()

    OpenSearchEventStore(client, index_name="security-events-v1").index_event(event)

    assert client.calls == [
        {
            "index": "security-events-v1",
            "id": event.event_id,
            "body": build_event_document(event),
        }
    ]


def test_event_store_get_document_returns_the_stored_source() -> None:
    client = RecordingOpenSearchClient()

    document = OpenSearchEventStore(
        client, index_name="security-events-v1"
    ).get_document("SE-01J8ZW4AAA0ABCDEFGHJKMNPQR")

    assert document == {"event_id": "SE-01J8ZW4AAA0ABCDEFGHJKMNPQR"}
    assert client.calls == [
        {
            "index": "security-events-v1",
            "id": "SE-01J8ZW4AAA0ABCDEFGHJKMNPQR",
        }
    ]


def test_event_store_get_document_returns_none_only_for_not_found() -> None:
    class NotFoundClient:
        def get(self, **kwargs: object) -> dict[str, object]:
            raise NotFoundError(404, "not_found", {})

        def index(self, **kwargs: object) -> None:
            raise AssertionError("not used")

    store = OpenSearchEventStore(NotFoundClient(), index_name="security-events-v1")

    assert store.get_document("SE-missing") is None


def test_event_store_get_document_propagates_non_not_found_errors() -> None:
    class FailingClient:
        def get(self, **kwargs: object) -> dict[str, object]:
            raise RuntimeError("transport failed")

        def index(self, **kwargs: object) -> None:
            raise AssertionError("not used")

    store = OpenSearchEventStore(FailingClient(), index_name="security-events-v1")

    with pytest.raises(RuntimeError, match="transport failed"):
        store.get_document("SE-unavailable")


def test_opensearch_client_factory_creates_an_instance_without_module_global(
    monkeypatch: Any,
) -> None:
    captured: dict[str, object] = {}

    class FakeOpenSearch:
        def __init__(self, **kwargs: object) -> None:
            captured.update(kwargs)

    monkeypatch.setattr(
        "evidencesoc.persistence.event_search.OpenSearch",
        FakeOpenSearch,
    )

    client = create_opensearch_client("http://127.0.0.1:9200")

    assert isinstance(client, FakeOpenSearch)
    assert captured == {"hosts": ["http://127.0.0.1:9200"]}
