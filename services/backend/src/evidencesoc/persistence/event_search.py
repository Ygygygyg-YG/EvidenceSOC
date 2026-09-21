from __future__ import annotations

from copy import deepcopy
from typing import Any, Protocol

from opensearchpy import OpenSearch
from opensearchpy.exceptions import NotFoundError

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
