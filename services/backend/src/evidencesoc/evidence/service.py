from __future__ import annotations

import json
from collections.abc import Callable, Mapping, Sequence
from copy import deepcopy
from datetime import UTC, datetime
from typing import Any, Protocol, cast

from evidencesoc.domain.models import EvidenceItem, SecurityEvent
from evidencesoc.execution import check_execution
from evidencesoc.ids import new_evidence_id
from evidencesoc.ingestion.jsonl import ParsedLogRecord
from evidencesoc.ingestion.normalize import (
    calculate_content_sha256,
    normalize_record,
)
from evidencesoc.persistence.event_repository import EventNotFoundError


class EvidenceIntegrityError(ValueError):
    def __init__(self, event_id: str, detail: str) -> None:
        self.event_id = event_id
        self.detail = detail
        super().__init__(f"evidence integrity check failed for {event_id}: {detail}")


class EvidenceSourceNotFoundError(LookupError):
    def __init__(self, event_id: str, source: str) -> None:
        self.event_id = event_id
        self.source = source
        super().__init__(f"{source} source not found for event {event_id}")


class EventReader(Protocol):
    def get(self, event_id: str) -> SecurityEvent: ...


class EvidenceStore(Protocol):
    def add_many(
        self,
        incident_id: str,
        items: Sequence[EvidenceItem],
    ) -> list[EvidenceItem]: ...

    def get(self, evidence_id: str) -> EvidenceItem: ...


class EventSearchReader(Protocol):
    def get_document(self, event_id: str) -> dict[str, Any] | None: ...


def _datetime_to_utc_iso(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("query datetime must be timezone-aware")
    return value.astimezone(UTC).isoformat()


def _json_serializable_query(query: Mapping[str, Any]) -> dict[str, Any]:
    copied_query = deepcopy(dict(query))

    def encode(value: object) -> object:
        if isinstance(value, datetime):
            return _datetime_to_utc_iso(value)
        raise TypeError(
            f"query contains a value that is not JSON serializable: "
            f"{type(value).__name__}"
        )

    serialized = json.dumps(
        copied_query,
        default=encode,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
    )
    decoded = json.loads(serialized)
    if not isinstance(decoded, dict):
        raise TypeError("evidence query must be a JSON object")
    return cast(dict[str, Any], decoded)


def _summary(event: SecurityEvent) -> str:
    observed_at = _datetime_to_utc_iso(event.observed_at)
    return (
        f"{event.source} event {event.event_id} observed at {observed_at}: "
        f"{event.event_type} ({event.severity.value})."
    )


class EvidenceService:
    def __init__(
        self,
        event_repository: EventReader,
        evidence_repository: EvidenceStore,
        search_store: EventSearchReader,
        evidence_id_factory: Callable[[], str] = new_evidence_id,
    ) -> None:
        self._event_repository = event_repository
        self._evidence_repository = evidence_repository
        self._search_store = search_store
        self._evidence_id_factory = evidence_id_factory

    def create_for_events(
        self,
        incident_id: str,
        event_ids: Sequence[str],
        query: Mapping[str, Any],
    ) -> list[EvidenceItem]:
        verified_events = [self._verify_event(event_id) for event_id in event_ids]
        query_template = _json_serializable_query(query)

        items = [
            EvidenceItem(
                evidence_id=self._evidence_id_factory(),
                event_id=event.event_id,
                source=event.source,
                observed_at=event.observed_at,
                query={
                    **deepcopy(query_template),
                    "matched_event_id": event.event_id,
                },
                summary=_summary(event),
                content_sha256=event.content_sha256,
            )
            for event in verified_events
        ]
        check_execution()
        return self._evidence_repository.add_many(incident_id, items)

    def get(self, evidence_id: str) -> EvidenceItem:
        return self._evidence_repository.get(evidence_id)

    def _verify_event(self, event_id: str) -> SecurityEvent:
        check_execution()
        try:
            event = self._event_repository.get(event_id)
        except EventNotFoundError as exc:
            raise EvidenceSourceNotFoundError(event_id, "PostgreSQL") from exc

        document = self._search_store.get_document(event_id)
        if document is None:
            raise EvidenceSourceNotFoundError(event_id, "OpenSearch")

        if document.get("event_id") != event_id:
            raise EvidenceIntegrityError(
                event_id,
                "OpenSearch event_id does not match the requested event",
            )

        raw_document = document.get("raw_event")
        if not isinstance(raw_document, Mapping):
            raise EvidenceIntegrityError(
                event_id,
                "OpenSearch raw_event is missing or is not an object",
            )

        try:
            postgres_hash = calculate_content_sha256(event.raw)
            opensearch_hash = calculate_content_sha256(raw_document)
        except ValueError as exc:
            raise EvidenceIntegrityError(
                event_id,
                "stored event content is not canonical JSON",
            ) from exc

        opensearch_stored_hash = document.get("content_sha256")
        hashes: tuple[object, ...] = (
            postgres_hash,
            opensearch_hash,
            event.content_sha256,
            opensearch_stored_hash,
        )
        if not all(
            isinstance(value, str) and value == postgres_hash for value in hashes
        ):
            raise EvidenceIntegrityError(
                event_id,
                "PostgreSQL and OpenSearch content hashes do not match",
            )

        self._verify_normalized_metadata(event, document)

        return event

    @staticmethod
    def _verify_normalized_metadata(
        event: SecurityEvent,
        document: Mapping[str, Any],
    ) -> None:
        try:
            expected = normalize_record(
                ParsedLogRecord(
                    raw=event.raw,
                    source_path=f"postgresql:{event.event_id}",
                    line_number=1,
                ),
                event_id=event.event_id,
                ingested_at=event.ingested_at,
            )
        except ValueError as exc:
            raise EvidenceIntegrityError(
                event.event_id,
                "hashed raw event cannot be normalized",
            ) from exc

        postgres_metadata = (
            event.source,
            event.external_id,
            event.deduplication_key,
            event.observed_at,
            event.severity,
            event.event_type,
        )
        expected_postgres_metadata = (
            expected.source,
            expected.external_id,
            expected.deduplication_key,
            expected.observed_at,
            expected.severity,
            expected.event_type,
        )
        if postgres_metadata != expected_postgres_metadata:
            raise EvidenceIntegrityError(
                event.event_id,
                "PostgreSQL normalized metadata does not match hashed raw event",
            )

        expected_document_metadata = {
            "source": expected.source,
            "external_id": expected.external_id,
            "deduplication_key": expected.deduplication_key,
            "observed_at": expected.observed_at.isoformat(),
            "severity": expected.severity.value,
            "event_type": expected.event_type,
        }
        actual_document_metadata = {
            field: document.get(field) for field in expected_document_metadata
        }
        if actual_document_metadata != expected_document_metadata:
            raise EvidenceIntegrityError(
                event.event_id,
                "OpenSearch normalized metadata does not match hashed raw event",
            )
