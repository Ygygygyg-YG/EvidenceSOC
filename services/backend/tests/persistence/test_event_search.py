from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from evidencesoc.domain.models import SecurityEvent, Severity
from evidencesoc.persistence import event_search
from evidencesoc.persistence.event_search import (
    OpenSearchEventStore,
    build_event_document,
    create_opensearch_client,
)
from evidencesoc.tools.policy import PolicyDeniedError
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


def test_ait_dataset_id_is_indexed_as_an_exact_filter() -> None:
    original = make_event()
    event = make_event(raw={**original.raw, "dataset_id": "ait-v2.1:shaw"})
    document = build_event_document(event)
    template_path = (
        Path(__file__).resolve().parents[4]
        / "infra/opensearch/security-events-template.json"
    )
    properties = json.loads(template_path.read_text(encoding="utf-8"))["template"][
        "mappings"
    ]["properties"]
    assert document["dataset_id"] == "ait-v2.1:shaw"
    assert properties["dataset_id"]["type"] == "keyword"


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


def test_event_query_reads_bounded_event_ids() -> None:
    class SearchSpy:
        def __init__(self) -> None:
            self.calls: list[dict[str, object]] = []

        def search(self, **kwargs: object) -> dict[str, Any]:
            self.calls.append(kwargs)
            return {"timed_out": False, "_shards": {"failed": 0}, "hits": {"hits": [{"_id": "SE-first"}, {"_id": "SE-second"}]}}

    client = SearchSpy()
    end = datetime(2026, 9, 21, 12, 5, tzinfo=UTC)
    query = event_search.OpenSearchEventQuery(client, index_name="security-events-v1")

    event_ids = query.search_event_ids(
        time_from=NOW,
        time_to=end,
        filters={"source_ip": "203.0.113.10", "source": "web"},
        limit=2,
    )

    assert event_ids == ["SE-first", "SE-second"]
    assert client.calls == [
        {
            "index": "security-events-v1",
            "body": {
                "size": 2,
                "_source": False,
                "query": {
                    "bool": {
                        "filter": [
                            {
                                "range": {
                                    "observed_at": {
                                        "gte": NOW.isoformat(),
                                        "lt": end.isoformat(),
                                    }
                                }
                            },
                            {"term": {"source": "web"}},
                            {"term": {"source_ip": "203.0.113.10"}},
                        ]
                    }
                },
                "sort": [
                    {"observed_at": {"order": "asc"}},
                    {"event_id": {"order": "asc"}},
                ],
            },
        }
    ]


@pytest.mark.parametrize(
    "hits",
    [
        "not-a-list",
        [{"_id": "SE-1"}, {"_id": "SE-2"}, {"_id": "SE-3"}],
        [{"_id": "SE-1"}, {"_id": "SE-1"}],
        [{"_id": ""}],
    ],
    ids=["malformed", "over-limit", "duplicate", "blank-id"],
)
def test_event_query_rejects_untrusted_search_hits(hits: object) -> None:
    class SearchClient:
        def __init__(self) -> None:
            self.calls = 0

        def search(self, **_kwargs: object) -> dict[str, Any]:
            self.calls += 1
            return {"timed_out": False, "_shards": {"failed": 0}, "hits": {"hits": hits}}

    client = SearchClient()
    query = event_search.OpenSearchEventQuery(client, index_name="security-events-v1")
    end = datetime(2026, 9, 21, 12, 5, tzinfo=UTC)

    with pytest.raises(RuntimeError, match="invalid event search response") as error:
        query.search_event_ids(
            time_from=NOW,
            time_to=end,
            filters={},
            limit=2,
        )

    assert isinstance(error.value, event_search.EventSearchResponseError)
    assert client.calls == 1


@pytest.mark.parametrize(
    "changes",
    [
        {"limit": 201},
        {"filters": {"query_string": "*"}},
        {"time_to": NOW},
        {"time_from": NOW.replace(tzinfo=None)},
    ],
    ids=["limit-201", "unknown-filter", "equal-time", "naive-time"],
)
def test_event_query_rejects_invalid_args_before_search(
    changes: dict[str, Any],
) -> None:
    class SearchSpy:
        def __init__(self) -> None:
            self.calls = 0

        def search(self, **_kwargs: object) -> dict[str, Any]:
            self.calls += 1
            return {"timed_out": False, "_shards": {"failed": 0}, "hits": {"hits": []}}

    client = SearchSpy()
    query = event_search.OpenSearchEventQuery(client, index_name="security-events-v1")
    arguments: dict[str, Any] = {
        "time_from": NOW,
        "time_to": datetime(2026, 9, 21, 12, 5, tzinfo=UTC),
        "filters": {},
        "limit": 2,
    }
    arguments.update(changes)

    with pytest.raises(PolicyDeniedError) as error:
        query.search_event_ids(**arguments)

    assert error.value.code == "POLICY_DENIED"
    assert client.calls == 0


def test_event_query_forwards_request_timeout() -> None:
    class SearchSpy:
        def __init__(self) -> None:
            self.kwargs: dict[str, object] = {}

        def search(self, **kwargs: object) -> dict[str, Any]:
            self.kwargs = kwargs
            return {"timed_out": False, "_shards": {"failed": 0}, "hits": {"hits": []}}

    client = SearchSpy()
    query = event_search.OpenSearchEventQuery(client, index_name="security-events-v1")

    query.search_event_ids(
        time_from=NOW,
        time_to=datetime(2026, 9, 21, 12, 5, tzinfo=UTC),
        filters={},
        limit=2,
        request_timeout=1.5,
    )

    assert client.kwargs["request_timeout"] == 1.5


@pytest.mark.parametrize("hits", [[], [{"_id": "SE-partial"}]], ids=["empty", "partial"])
def test_event_query_rejects_server_timeout_before_returning_hits(hits: list) -> None:
    class SearchClient:
        def search(self, **_kwargs: object) -> dict[str, Any]:
            return {"timed_out": True, "_shards": {"failed": 0}, "hits": {"hits": hits}}

    query = event_search.OpenSearchEventQuery(SearchClient(), index_name="security-events-v1")
    with pytest.raises(TimeoutError, match="event search timed out"):
        query.search_event_ids(time_from=NOW, time_to=NOW.replace(minute=5), filters={})


@pytest.mark.parametrize("hits", [[], [{"_id": "SE-partial"}]], ids=["empty", "partial"])
def test_event_query_rejects_failed_shards_before_returning_hits(hits: list) -> None:
    class SearchClient:
        def search(self, **_kwargs: object) -> dict[str, Any]:
            return {"timed_out": False, "_shards": {"failed": 1}, "hits": {"hits": hits}}

    query = event_search.OpenSearchEventQuery(SearchClient(), index_name="security-events-v1")
    with pytest.raises(event_search.EventSearchResponseError):
        query.search_event_ids(time_from=NOW, time_to=NOW.replace(minute=5), filters={})


@pytest.mark.parametrize(
    "metadata",
    [
        {},
        {"_shards": {"failed": 0}},
        {"timed_out": False},
        {"timed_out": False, "_shards": {}},
        *({"timed_out": value, "_shards": {"failed": 0}} for value in (None, 0, 1, "false")),
        *({"timed_out": False, "_shards": value} for value in (None, [], "invalid")),
        *({"timed_out": False, "_shards": {"failed": value}} for value in (None, True, False, -1, 0.0, "0")),
    ],
)
def test_event_query_rejects_missing_or_invalid_completion_metadata(metadata: dict) -> None:
    class SearchClient:
        def search(self, **_kwargs: object) -> dict[str, Any]:
            return {**metadata, "hits": {"hits": [{"_id": "SE-untrusted"}]}}

    query = event_search.OpenSearchEventQuery(SearchClient(), index_name="security-events-v1")
    with pytest.raises(event_search.EventSearchResponseError):
        query.search_event_ids(time_from=NOW, time_to=NOW.replace(minute=5), filters={})


def test_event_query_accepts_healthy_empty_response() -> None:
    class SearchClient:
        def search(self, **_kwargs: object) -> dict[str, Any]:
            return {"timed_out": False, "_shards": {"failed": 0}, "hits": {"hits": []}}

    query = event_search.OpenSearchEventQuery(SearchClient(), index_name="security-events-v1")
    assert query.search_event_ids(time_from=NOW, time_to=NOW.replace(minute=5), filters={}) == []
