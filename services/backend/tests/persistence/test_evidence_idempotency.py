from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest
from evidencesoc.domain.models import EvidenceItem
from evidencesoc.ids import new_evidence_id
from evidencesoc.persistence.event_repository import EvidenceRepository
from evidencesoc.persistence.tables import EvidenceItemTable
from sqlalchemy import (
    JSON,
    CheckConstraint,
    Column,
    MetaData,
    String,
    Table,
    create_engine,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import sessionmaker


@pytest.fixture
def sessions():
    path = Path.cwd() / f".evidence-idempotency-{uuid4().hex}.db"
    engine = create_engine(f"sqlite+pysqlite:///{path}", connect_args={"timeout": 30})
    metadata = MetaData()
    Table("incidents", metadata, Column("incident_id", String(64), primary_key=True))
    Table("security_events", metadata, Column("event_id", String(64), primary_key=True))
    evidence = EvidenceItemTable.__table__.to_metadata(metadata)
    for column in evidence.columns:
        if isinstance(column.type, JSONB):
            column.type = JSON()
    for constraint in list(evidence.constraints):
        if isinstance(constraint, CheckConstraint):
            evidence.constraints.remove(constraint)
    metadata.create_all(engine)
    with engine.begin() as connection:
        connection.execute(
            metadata.tables["incidents"].insert(),
            [{"incident_id": "IN-1"}, {"incident_id": "IN-2"}],
        )
        connection.execute(
            metadata.tables["security_events"].insert(),
            [{"event_id": "SE-1"}, {"event_id": "SE-2"}],
        )
    yield sessionmaker(engine, expire_on_commit=False)
    engine.dispose()
    path.unlink(missing_ok=True)


def item(event_id: str = "SE-1", *, query: dict | None = None) -> EvidenceItem:
    return EvidenceItem(
        evidence_id=new_evidence_id(),
        event_id=event_id,
        source="test",
        observed_at=datetime(2026, 9, 21, tzinfo=UTC),
        query=query or {"filters": {"host": "one"}, "matched_event_id": event_id},
        summary="A verified event.",
        content_sha256="a" * 64,
    )


def add(sessions, incident_id: str, evidence: EvidenceItem) -> EvidenceItem:
    with sessions() as session:
        return EvidenceRepository(session).add_many(incident_id, [evidence])[0]


def test_retry_reuses_evidence_id_but_distinct_queries_keep_their_source(sessions):
    first = add(sessions, "IN-1", item())
    retried = add(
        sessions,
        "IN-1",
        item(query={"matched_event_id": "SE-1", "filters": {"host": "one"}}),
    )
    other_query = add(
        sessions,
        "IN-1",
        item(query={"filters": {"host": "two"}, "matched_event_id": "SE-1"}),
    )
    other_event = add(sessions, "IN-1", item("SE-2"))
    other_incident = add(sessions, "IN-2", item())
    assert retried.evidence_id == first.evidence_id
    assert other_query.evidence_id != first.evidence_id
    assert other_event.evidence_id != first.evidence_id
    assert other_incident.evidence_id != first.evidence_id
    with sessions() as session:
        assert session.query(EvidenceItemTable).count() == 4


def test_concurrent_retry_creates_one_evidence_row(sessions):
    with ThreadPoolExecutor(max_workers=6) as pool:
        futures = [pool.submit(add, sessions, "IN-1", item()) for _ in range(6)]
        results = [future.result() for future in futures]
    assert len({result.evidence_id for result in results}) == 1
    with sessions() as session:
        assert session.query(EvidenceItemTable).count() == 1


def test_encoded_query_retries_ignore_mapping_order(sessions):
    first = add(sessions, "IN-1", item(query={"path": "/x\u0000", "host": "one"}))
    retried = add(sessions, "IN-1", item(query={"host": "one", "path": "/x\u0000"}))
    assert retried.evidence_id == first.evidence_id
    with sessions() as session:
        assert session.query(EvidenceItemTable).count() == 1


def test_one_batch_can_repeat_a_source_event_query(sessions):
    first, repeated = (item(), item())
    with sessions() as session:
        result = EvidenceRepository(session).add_many("IN-1", [first, repeated])
    assert result[0].evidence_id == result[1].evidence_id
    with sessions() as session:
        assert session.query(EvidenceItemTable).count() == 1
