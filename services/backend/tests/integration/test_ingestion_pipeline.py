from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from evidencesoc.config import Settings
from evidencesoc.evidence.service import EvidenceService
from evidencesoc.ids import new_event_id, new_ulid
from evidencesoc.ingestion.service import IngestionService
from evidencesoc.persistence.database import (
    create_database_engine,
    create_session_factory,
)
from evidencesoc.persistence.event_repository import (
    EventRepository,
    EvidenceRepository,
)
from evidencesoc.persistence.event_search import (
    OpenSearchEventStore,
    create_opensearch_client,
)
from evidencesoc.persistence.tables import (
    AlertTable,
    EvidenceItemTable,
    IncidentTable,
    SecurityEventTable,
)
from sqlalchemy import delete


def test_event_can_be_traced_from_both_stores_to_evidence(
    tmp_path: Path,
) -> None:
    settings = Settings()
    run_id = new_ulid()
    event_id = new_event_id()
    discarded_duplicate_id = new_event_id()
    evidence_id = f"EV-{new_ulid()}"
    alert_id = f"AL-{run_id}"
    incident_id = f"IN-{run_id}"
    index_name = f"security-events-task5-{run_id.lower()}"
    source = f"task5-smoke-{run_id.lower()}"
    observed_at = datetime(2026, 9, 21, 12, 0, tzinfo=UTC)
    log_path = tmp_path / "event.jsonl"
    log_path.write_text(
        json.dumps(
            {
                "source": source,
                "external_id": f"request-{run_id}",
                "observed_at": observed_at.isoformat(),
                "severity": "high",
                "event_type": "web.request",
                "message": "Task 5 integration probe",
                "http": {
                    "method": "GET",
                    "path": "/task5-smoke",
                    "status_code": 403,
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )

    engine = create_database_engine(settings.database_url)
    session_factory = create_session_factory(engine)
    search_client = create_opensearch_client(settings.opensearch_url)
    session = session_factory()

    try:
        event_repository = EventRepository(session)
        search_store = OpenSearchEventStore(
            search_client,
            index_name=index_name,
        )
        generated_ids = iter((event_id, discarded_duplicate_id))
        ingestion = IngestionService(
            event_repository,
            search_store,
            clock=lambda: datetime(2026, 9, 21, 12, 1, tzinfo=UTC),
            event_id_factory=generated_ids.__next__,
        )

        first_report = ingestion.import_file(log_path)
        duplicate_report = ingestion.import_file(log_path)

        assert first_report.inserted == 1
        assert first_report.indexed == 1
        assert first_report.event_ids == [event_id]
        assert duplicate_report.duplicated == 1
        assert duplicate_report.indexed == 0
        assert duplicate_report.event_ids == [event_id]

        stored_event = event_repository.get(event_id)
        indexed_document = search_store.get_document(event_id)
        assert stored_event.index_status.value == "indexed"
        assert indexed_document is not None
        assert indexed_document["event_id"] == event_id
        assert indexed_document["raw_event"] == stored_event.raw

        session.add(
            AlertTable(
                alert_id=alert_id,
                title="Task 5 integration alert",
                severity="high",
                created_at=observed_at,
                event_ids=[event_id],
            )
        )
        session.add(
            IncidentTable(
                incident_id=incident_id,
                alert_id=alert_id,
                status="received",
                created_at=observed_at,
            )
        )
        session.commit()

        evidence_repository = EvidenceRepository(session)
        evidence_service = EvidenceService(
            event_repository,
            evidence_repository,
            search_store,
            evidence_id_factory=lambda: evidence_id,
        )
        evidence = evidence_service.create_for_events(
            incident_id,
            [event_id],
            {"event_type": "web.request"},
        )[0]

        restored = evidence_service.get(evidence.evidence_id)
        assert restored.event_id == event_id
        assert restored.query == {
            "event_type": "web.request",
            "matched_event_id": event_id,
        }
        assert restored.content_sha256 == stored_event.content_sha256
    finally:
        session.rollback()
        session.execute(
            delete(EvidenceItemTable).where(
                EvidenceItemTable.evidence_id == evidence_id
            )
        )
        session.execute(
            delete(IncidentTable).where(IncidentTable.incident_id == incident_id)
        )
        session.execute(delete(AlertTable).where(AlertTable.alert_id == alert_id))
        session.execute(
            delete(SecurityEventTable).where(SecurityEventTable.event_id == event_id)
        )
        session.commit()
        session.close()
        engine.dispose()
        search_client.indices.delete(
            index=index_name,
            ignore_unavailable=True,
        )
        search_client.close()
