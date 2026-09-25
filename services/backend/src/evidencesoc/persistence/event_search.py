from __future__ import annotations

from copy import deepcopy
from datetime import datetime
from typing import Any, Protocol

from opensearchpy import OpenSearch
from opensearchpy.exceptions import NotFoundError

from evidencesoc.domain.event_search_policy import validate_event_search
from evidencesoc.domain.models import SecurityEvent


class OpenSearchIndexClient(Protocol):
    def index(self, **kwargs: object) -> object: ...

    def get(self, **kwargs: object) -> dict[str, Any]: ...


_TEMPLATE_SEARCH_FIELDS = (
    "source_ip",
    "destination_ip",
    "source_port",
    "destination_port",
    "host",
    "service",
    "message",
    "tags",
    "http",
)


def create_opensearch_client(url: str) -> OpenSearch:
    """Create an OpenSearch client without opening a module-global connection."""
    if not url.strip():
        raise ValueError("OpenSearch URL must not be blank")

    return OpenSearch(hosts=[url])


def build_event_document(event: SecurityEvent) -> dict[str, Any]:
    """Build the searchable event document while preserving its raw payload."""
    raw_event = deepcopy(event.raw)
    document: dict[str, Any] = {
        "event_id": event.event_id,
        "source": event.source,
        "external_id": event.external_id,
        "deduplication_key": event.deduplication_key,
        "observed_at": event.observed_at.isoformat(),
        "ingested_at": event.ingested_at.isoformat(),
        "severity": event.severity.value,
        "event_type": event.event_type,
        "content_sha256": event.content_sha256,
        "raw_event": raw_event,
    }
    document.update({field: raw_event.get(field) for field in _TEMPLATE_SEARCH_FIELDS})
    return document


class OpenSearchEventStore:
    def __init__(self, client: OpenSearchIndexClient, *, index_name: str) -> None:
        if not index_name.strip():
            raise ValueError("OpenSearch index name must not be blank")
        self._client = client
        self._index_name = index_name

    def index_event(self, event: SecurityEvent) -> None:
        self._client.index(
            index=self._index_name,
            id=event.event_id,
            body=build_event_document(event),
        )

    def get_document(self, event_id: str) -> dict[str, Any] | None:
        try:
            response = self._client.get(
                index=self._index_name,
                id=event_id,
            )
        except NotFoundError:
            return None

        source = response.get("_source")
        if not isinstance(source, dict):
            return None
        return source


class OpenSearchSearchClient(Protocol):
    def search(self, **kwargs: object) -> dict[str, Any]: ...


class EventSearchResponseError(RuntimeError):
    pass


class OpenSearchEventQuery:
    def __init__(
        self,
        client: OpenSearchSearchClient,
        *,
        index_name: str,
    ) -> None:
        self._client = client
        self._index_name = index_name

    def search_event_ids(
        self,
        *,
        time_from: datetime,
        time_to: datetime,
        filters: dict[str, str],
        limit: int = 100,
        request_timeout: float | None = None,
    ) -> list[str]:
        validate_event_search(time_from, time_to, filters, limit)

        clauses: list[dict[str, Any]] = [
            {
                "range": {
                    "observed_at": {
                        "gte": time_from.isoformat(),
                        "lt": time_to.isoformat(),
                    }
                }
            }
        ]
        clauses.extend(
            {"term": {field: value}} for field, value in sorted(filters.items())
        )
        response = self._client.search(
            index=self._index_name,
            body={
                "size": limit,
                "_source": False,
                "query": {"bool": {"filter": clauses}},
                "sort": [
                    {"observed_at": {"order": "asc"}},
                    {"event_id": {"order": "asc"}},
                ],
            },
            **(
                {"request_timeout": request_timeout}
                if request_timeout is not None
                else {}
            ),
        )
        container = response.get("hits")
        if not isinstance(container, dict):
            raise EventSearchResponseError("invalid event search response")

        hits = container.get("hits")
        if not isinstance(hits, list) or len(hits) > limit:
            raise EventSearchResponseError("invalid event search response")

        event_ids: list[str] = []
        seen: set[str] = set()
        for hit in hits:
            if not isinstance(hit, dict):
                raise EventSearchResponseError("invalid event search response")
            event_id = hit.get("_id")
            if (
                not isinstance(event_id, str)
                or not event_id.strip()
                or event_id in seen
            ):
                raise EventSearchResponseError("invalid event search response")
            seen.add(event_id)
            event_ids.append(event_id)

        return event_ids
