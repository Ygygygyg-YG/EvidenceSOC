from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import pytest
from sqlalchemy.dialects import postgresql

from evidencesoc.domain.models import (
    EventIndexStatus,
    EvidenceItem,
    SecurityEvent,
    Severity,
)
from evidencesoc.persistence.database import (
    create_database_engine,
    create_session_factory,
)
from evidencesoc.persistence.event_repository import (
    EventContentConflictError,
    EventNotFoundError,
    EventRepository,
    EvidenceNotFoundError,
    EvidenceRepository,
    IncidentNotFoundError,
    PersistResult,
)

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
        "raw": {"path": "/search", "status": 500},
        "content_sha256": SHA256,
    }
    values.update(changes)
    return SecurityEvent(**values)


def make_evidence(**changes: Any) -> EvidenceItem:
    values: dict[str, Any] = {
        "evidence_id": "EV-01J8ZW4AAA0ABCDEFGHJKMNPQR",
        "event_id": "SE-01J8ZW4AAA0ABCDEFGHJKMNPQR",
        "source": "web",
        "observed_at": NOW,
        "query": {"event_id": "SE-01J8ZW4AAA0ABCDEFGHJKMNPQR"},
        "summary": "A suspicious request was observed.",
        "content_sha256": SHA256,
    }
    values.update(changes)
    return EvidenceItem(**values)


class ScalarResult:
    def __init__(self, value: object | None) -> None:
        self.value = value

    def scalar_one_or_none(self) -> object | None:
        return self.value

    def scalars(self) -> ScalarResult:
        return self

    def all(self) -> list[object]:
        assert isinstance(self.value, list)
        return self.value


class RecordingSession:
    def __init__(self, *results: object | None) -> None:
        self.results = list(results)
        self.statements: list[object] = []
        self.operations: list[tuple[str, object | None]] = []
        self.commits = 0

    def execute(self, statement: object) -> ScalarResult:
        self.statements.append(statement)
        self.operations.append(("execute", statement))
        return ScalarResult(self.results.pop(0) if self.results else None)

    def commit(self) -> None:
        self.commits += 1
        self.operations.append(("commit", None))


def as_event_row(event: SecurityEvent) -> SimpleNamespace:
    values = event.model_dump(mode="python")
    values["severity"] = event.severity.value
    values["index_status"] = event.index_status.value
    return SimpleNamespace(**values)


def as_evidence_row(item: EvidenceItem, incident_id: str) -> SimpleNamespace:
    return SimpleNamespace(
        **item.model_dump(mode="python"),
        incident_id=incident_id,
    )


def test_database_factories_configure_an_unconnected_engine() -> None:
    engine = create_database_engine("postgresql+psycopg://user:pass@db/test")
    session_factory = create_session_factory(engine)

    assert str(engine.url) == "postgresql+psycopg://user:***@db/test"
    assert session_factory.kw["expire_on_commit"] is False


def test_register_inserts_using_the_named_deduplication_constraint() -> None:
    event = make_event()
    session = RecordingSession(event.event_id)

    result = EventRepository(session).register(event)

    statement = session.statements[0]
    compiled = statement.compile(dialect=postgresql.dialect())  # type: ignore[union-attr]
    assert (
        "ON CONFLICT ON CONSTRAINT uq_security_events_source_deduplication_key"
        in str(compiled)
    )
    assert result.created is True
    assert result.event == event
    assert session.commits == 1


def test_register_returns_existing_event_for_the_same_content() -> None:
    existing = make_event(event_id="SE-01J8ZW4AAA1ABCDEFGHJKMNPQR")
    session = RecordingSession(None, as_event_row(existing))

    result = EventRepository(session).register(make_event())

    assert result.created is False
    assert result.event == existing
    assert session.commits == 0


def test_register_looks_up_duplicate_by_source_and_deduplication_key() -> None:
    event = make_event()
    session = RecordingSession(None, as_event_row(event))

    EventRepository(session).register(event)

    compiled = session.statements[1].compile(dialect=postgresql.dialect())  # type: ignore[union-attr]
    assert "security_events.source = %(source_1)s" in str(compiled)
    assert "security_events.deduplication_key = %(deduplication_key_1)s" in str(
        compiled
    )
    assert compiled.params == {
        "source_1": event.source,
        "deduplication_key_1": event.deduplication_key,
    }


def test_register_rejects_deduplication_collision_with_different_content() -> None:
    existing = make_event(content_sha256="b" * 64)
    session = RecordingSession(None, as_event_row(existing))

    with pytest.raises(EventContentConflictError) as exc_info:
        EventRepository(session).register(make_event())

    assert exc_info.value.existing_event_id == existing.event_id
    assert session.commits == 0


def test_event_repository_get_raises_when_event_does_not_exist() -> None:
    with pytest.raises(EventNotFoundError):
        EventRepository(RecordingSession(None)).get("SE-does-not-exist")


def test_list_indexable_returns_pending_and_failed_events() -> None:
    pending = make_event()
    failed = make_event(
        event_id="SE-01J8ZW4AAA2ABCDEFGHJKMNPQR",
        index_status=EventIndexStatus.FAILED,
        index_error="OpenSearch unavailable",
    )
    session = RecordingSession([as_event_row(pending), as_event_row(failed)])

    events = EventRepository(session).list_indexable(limit=2)

    assert events == [pending, failed]
    compiled = session.statements[0].compile(dialect=postgresql.dialect())  # type: ignore[union-attr]
    assert (
        "WHERE security_events.index_status "
        "IN (__[POSTCOMPILE_index_status_1])" in str(compiled)
    )
    assert compiled.params["index_status_1"] == ["pending", "failed"]


def test_mark_indexed_updates_status_and_clears_the_previous_error() -> None:
    event = make_event()
    session = RecordingSession(event.event_id)

    EventRepository(session).mark_indexed(event.event_id, indexed_at=NOW)

    compiled = session.statements[0].compile(  # type: ignore[union-attr]
        dialect=postgresql.dialect()
    )
    assert "index_status=%(index_status)s" in str(compiled)
    assert "index_error=%(index_error)s" in str(compiled)
    assert session.commits == 1


def test_mark_index_failed_records_an_error() -> None:
    event = make_event()
    session = RecordingSession(event.event_id)

    EventRepository(session).mark_index_failed(event.event_id, "OpenSearch timed out")

    compiled = session.statements[0].compile(  # type: ignore[union-attr]
        dialect=postgresql.dialect()
    )
    assert "index_status=%(index_status)s" in str(compiled)
    assert session.commits == 1


def test_stale_index_failure_cannot_overwrite_an_indexed_event() -> None:
    event = make_event(index_status=EventIndexStatus.INDEXED, indexed_at=NOW)
    session = RecordingSession(None, EventIndexStatus.INDEXED.value)

    EventRepository(session).mark_index_failed(event.event_id, "late timeout")

    update_statement = session.statements[0].compile(  # type: ignore[union-attr]
        dialect=postgresql.dialect()
    )
    assert "security_events.index_status !=" in str(update_statement)
    assert EventIndexStatus.INDEXED.value in update_statement.params.values()
    assert len(session.statements) == 2
    assert session.commits == 1


def test_add_many_persists_evidence_for_an_incident() -> None:
    incident_id = "IN-01J8ZW4AAA0ABCDEFGHJKMNPQR"
    item = make_evidence()
    session = RecordingSession(SimpleNamespace(incident_id=incident_id), None)

    added = EvidenceRepository(session).add_many(incident_id, [item])

    assert added == [item]
    assert session.commits == 1
    assert [operation[0] for operation in session.operations] == [
        "execute",
        "execute",
        "commit",
    ]
    incident_statement = session.operations[0][1]
    evidence_statement = session.operations[1][1]
    assert incident_statement is not None
    assert evidence_statement is not None
    incident_query = incident_statement.compile(dialect=postgresql.dialect())  # type: ignore[union-attr]
    evidence_insert = evidence_statement.compile(dialect=postgresql.dialect())  # type: ignore[union-attr]
    assert "SELECT incidents.incident_id" in str(incident_query)
    assert "WHERE incidents.incident_id = %(incident_id_1)s" in str(incident_query)
    assert incident_query.params == {"incident_id_1": incident_id}
    assert "INSERT INTO evidence_items" in str(evidence_insert)
    assert evidence_insert.params["incident_id_m0"] == incident_id


def test_add_many_rejects_a_missing_incident_without_inserting() -> None:
    item = make_evidence()
    session = RecordingSession(None)

    with pytest.raises(IncidentNotFoundError):
        EvidenceRepository(session).add_many("IN-missing", [item])

    assert len(session.statements) == 1
    assert session.commits == 0


def test_evidence_repository_get_returns_item_and_raises_when_missing() -> None:
    incident_id = "IN-01J8ZW4AAA0ABCDEFGHJKMNPQR"
    item = make_evidence()

    assert (
        EvidenceRepository(RecordingSession(as_evidence_row(item, incident_id))).get(
            item.evidence_id
        )
        == item
    )

    with pytest.raises(EvidenceNotFoundError):
        EvidenceRepository(RecordingSession(None)).get("EV-missing")


def test_persist_result_needs_indexing_unless_event_is_already_indexed() -> None:
    pending = make_event()
    indexed = make_event(index_status=EventIndexStatus.INDEXED, indexed_at=NOW)

    assert PersistResult(event=pending, created=False).needs_indexing is True
    assert PersistResult(event=indexed, created=True).needs_indexing is False
