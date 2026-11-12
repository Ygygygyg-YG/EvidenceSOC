from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any

from sqlalchemy import Select, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session

from evidencesoc.domain.models import (
    EventIndexStatus,
    EvidenceItem,
    SecurityEvent,
    Severity,
)
from evidencesoc.domain.response_action import SIMULATED_CONTROL_SOURCE
from evidencesoc.execution import check_execution
from evidencesoc.persistence.json_encoding import restore_json, safe_json
from evidencesoc.persistence.tables import (
    EvidenceItemTable,
    IncidentTable,
    SecurityEventTable,
)


class EventNotFoundError(LookupError):
    def __init__(self, event_id: str) -> None:
        self.event_id = event_id
        super().__init__(f"security event not found: {event_id}")


class EvidenceNotFoundError(LookupError):
    def __init__(self, evidence_id: str) -> None:
        self.evidence_id = evidence_id
        super().__init__(f"evidence item not found: {evidence_id}")


class IncidentNotFoundError(LookupError):
    def __init__(self, incident_id: str) -> None:
        self.incident_id = incident_id
        super().__init__(f"incident not found: {incident_id}")


class EventContentConflictError(ValueError):
    def __init__(
        self,
        *,
        source: str,
        deduplication_key: str,
        existing_event_id: str,
    ) -> None:
        self.source = source
        self.deduplication_key = deduplication_key
        self.existing_event_id = existing_event_id
        super().__init__(
            "event deduplication collision has different content: "
            f"{source}/{deduplication_key}"
        )


@dataclass(frozen=True)
class PersistResult:
    event: SecurityEvent
    created: bool

    @property
    def event_id(self) -> str:
        return self.event.event_id

    @property
    def needs_indexing(self) -> bool:
        return self.event.index_status is not EventIndexStatus.INDEXED


def _event_values(event: SecurityEvent) -> dict[str, Any]:
    return {
        "event_id": event.event_id,
        "source": event.source,
        "external_id": event.external_id,
        "deduplication_key": event.deduplication_key,
        "observed_at": event.observed_at,
        "ingested_at": event.ingested_at,
        "severity": event.severity.value,
        "event_type": event.event_type,
        "raw": event.raw,
        "content_sha256": event.content_sha256,
        "index_status": event.index_status.value,
        "indexed_at": event.indexed_at,
        "index_error": event.index_error,
    }


def _to_event(row: SecurityEventTable) -> SecurityEvent:
    return SecurityEvent(
        event_id=row.event_id,
        source=row.source,
        external_id=row.external_id,
        deduplication_key=row.deduplication_key,
        observed_at=row.observed_at,
        ingested_at=row.ingested_at,
        severity=Severity(row.severity),
        event_type=row.event_type,
        raw=row.raw,
        content_sha256=row.content_sha256,
        index_status=EventIndexStatus(row.index_status),
        indexed_at=row.indexed_at,
        index_error=row.index_error,
    )


def _to_evidence(row: EvidenceItemTable) -> EvidenceItem:
    return EvidenceItem(
        evidence_id=row.evidence_id,
        event_id=row.event_id,
        source=row.source,
        observed_at=row.observed_at,
        query=restore_json(row.query),
        summary=row.summary,
        content_sha256=row.content_sha256,
    )


class EventRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def register(self, event: SecurityEvent) -> PersistResult:
        statement = (
            insert(SecurityEventTable)
            .values(**_event_values(event))
            .on_conflict_do_nothing(
                constraint="uq_security_events_source_deduplication_key"
            )
            .returning(SecurityEventTable.event_id)
        )
        inserted_event_id = self._session.execute(statement).scalar_one_or_none()
        if inserted_event_id is not None:
            self._session.commit()
            return PersistResult(event=event, created=True)

        existing = self._session.execute(
            select(SecurityEventTable).where(
                SecurityEventTable.source == event.source,
                SecurityEventTable.deduplication_key == event.deduplication_key,
            )
        ).scalar_one_or_none()
        if existing is None:
            raise RuntimeError("event was not inserted and no conflicting event exists")

        existing_event = _to_event(existing)
        if existing_event.content_sha256 != event.content_sha256:
            raise EventContentConflictError(
                source=event.source,
                deduplication_key=event.deduplication_key,
                existing_event_id=existing_event.event_id,
            )

        return PersistResult(event=existing_event, created=False)

    def get(self, event_id: str) -> SecurityEvent:
        row = self._session.execute(
            select(SecurityEventTable).where(SecurityEventTable.event_id == event_id)
        ).scalar_one_or_none()
        if row is None:
            raise EventNotFoundError(event_id)
        return _to_event(row)

    def list_indexable(self, *, limit: int = 100) -> list[SecurityEvent]:
        if limit <= 0:
            raise ValueError("limit must be greater than zero")

        statement: Select[tuple[SecurityEventTable]] = (
            select(SecurityEventTable)
            .where(
                SecurityEventTable.index_status.in_(
                    (EventIndexStatus.PENDING.value, EventIndexStatus.FAILED.value)
                ),
                SecurityEventTable.source != SIMULATED_CONTROL_SOURCE,
            )
            .order_by(SecurityEventTable.ingested_at, SecurityEventTable.event_id)
            .limit(limit)
        )
        rows = self._session.execute(statement).scalars().all()
        return [_to_event(row) for row in rows]

    def mark_indexed(
        self,
        event_id: str,
        *,
        indexed_at: datetime | None = None,
    ) -> None:
        timestamp = indexed_at or datetime.now(UTC)
        updated_event_id = self._session.execute(
            update(SecurityEventTable)
            .where(SecurityEventTable.event_id == event_id)
            .values(
                index_status=EventIndexStatus.INDEXED.value,
                indexed_at=timestamp,
                index_error=None,
            )
            .returning(SecurityEventTable.event_id)
        ).scalar_one_or_none()
        if updated_event_id is None:
            raise EventNotFoundError(event_id)
        self._session.commit()

    def mark_index_failed(self, event_id: str, error: str) -> None:
        if not error.strip():
            raise ValueError("index error must not be blank")

        updated_event_id = self._session.execute(
            update(SecurityEventTable)
            .where(
                SecurityEventTable.event_id == event_id,
                SecurityEventTable.index_status != EventIndexStatus.INDEXED.value,
            )
            .values(
                index_status=EventIndexStatus.FAILED.value,
                indexed_at=None,
                index_error=error.strip(),
            )
            .returning(SecurityEventTable.event_id)
        ).scalar_one_or_none()
        if updated_event_id is None:
            current_status = self._session.execute(
                select(SecurityEventTable.index_status).where(
                    SecurityEventTable.event_id == event_id
                )
            ).scalar_one_or_none()
            if current_status is None:
                raise EventNotFoundError(event_id)
            if current_status != EventIndexStatus.INDEXED.value:
                raise RuntimeError(
                    f"event index status changed concurrently: {event_id}"
                )
        self._session.commit()


class EvidenceRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def add_many(
        self,
        incident_id: str,
        items: Sequence[EvidenceItem],
    ) -> list[EvidenceItem]:
        if not incident_id.strip():
            raise ValueError("incident ID must not be blank")

        incident = self._session.execute(
            select(IncidentTable.incident_id).where(
                IncidentTable.incident_id == incident_id
            )
        ).scalar_one_or_none()
        if incident is None:
            raise IncidentNotFoundError(incident_id)
        if not items:
            return []

        values_by_query: dict[tuple[str, str], dict[str, Any]] = {}
        keys: list[tuple[str, str]] = []
        for item in items:
            canonical_query = json.dumps(
                item.query,
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
            stored_query = safe_json(json.loads(canonical_query))
            fingerprint = sha256(canonical_query.encode("utf-8")).hexdigest()
            key = (item.event_id, fingerprint)
            keys.append(key)
            values_by_query.setdefault(
                key,
                {
                    "evidence_id": item.evidence_id,
                    "incident_id": incident_id,
                    "event_id": item.event_id,
                    "source": item.source,
                    "observed_at": item.observed_at,
                    "query": stored_query,
                    "query_fingerprint": fingerprint,
                    "summary": item.summary,
                    "content_sha256": item.content_sha256,
                },
            )
        dialect = self._session.get_bind().dialect.name
        statement = (sqlite_insert if dialect == "sqlite" else insert)(
            EvidenceItemTable
        ).values(list(values_by_query.values()))
        upsert_statement = statement.on_conflict_do_update(
            index_elements=["incident_id", "event_id", "query_fingerprint"],
            set_={"evidence_id": EvidenceItemTable.evidence_id},
        ).returning(
            EvidenceItemTable.event_id,
            EvidenceItemTable.query_fingerprint,
            EvidenceItemTable.evidence_id,
        )
        stored_ids = {
            (row.event_id, row.query_fingerprint): row.evidence_id
            for row in self._session.execute(upsert_statement).all()
        }
        if set(keys) != set(stored_ids):
            raise RuntimeError("evidence upsert did not return every query")
        check_execution()
        self._session.commit()
        return [
            item.model_copy(update={"evidence_id": stored_ids[key]})
            for item, key in zip(items, keys, strict=True)
        ]

    def get(self, evidence_id: str) -> EvidenceItem:
        row = self._session.execute(
            select(EvidenceItemTable).where(
                EvidenceItemTable.evidence_id == evidence_id
            )
        ).scalar_one_or_none()
        if row is None:
            raise EvidenceNotFoundError(evidence_id)
        return _to_evidence(row)
