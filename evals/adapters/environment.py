"""Per-case PostgreSQL and OpenSearch resources for the original product services."""

from __future__ import annotations

import json
import os
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from evidencesoc.config import Settings
from evidencesoc.domain.models import EventIndexStatus, SecurityEvent
from evidencesoc.persistence.database import (
    create_database_engine,
    create_session_factory,
)
from evidencesoc.persistence.event_search import (
    OpenSearchEventStore,
    create_opensearch_client,
)
from evidencesoc.persistence.tables import (
    AlertTable,
    Base,
    EvidenceItemTable,
    IncidentTable,
    KnowledgeChunkTable,
    SecurityEventTable,
)
from sqlalchemy import create_engine, insert, select, text
from sqlalchemy.engine import make_url

from evals.contracts import canonical_hash


@dataclass
class CaseResources:
    settings: Settings
    sessions: object
    incident_id: str
    database_name: str
    index_name: str
    run_id: str
    case_id: str
    retained: bool = False

    def __iter__(self):
        return iter((self.settings, self.sessions, self.incident_id))

    def retain(self) -> dict:
        self.retained = True
        return self.reference()

    def reference(self) -> dict:
        return {
            "schema_version": "task13-case-resource-v1",
            "database_name": self.database_name,
            "index_name": self.index_name,
            "incident_id": self.incident_id,
            "run_id": self.run_id,
            "case_id": self.case_id,
            "source_commit": os.environ.get("TASK13_SOURCE_COMMIT"),
            "status": "retained_for_human_approval",
        }


def export_knowledge(settings: Settings, destination: Path) -> dict:
    """Control-side export; snapshot is local, immutable and contains only public KB."""
    from evidencesoc.rag.embeddings import MODEL_DIMENSIONS, MODEL_ID, validate_vectors
    from evidencesoc.rag.ingest_attack import parse_attack
    from evidencesoc.rag.models import SourceManifest

    source = settings.rag_data_directory / "enterprise-attack-19.2.json"
    manifest = SourceManifest.model_validate_json(
        (
            settings.rag_data_directory / "enterprise-attack-19.2.manifest.json"
        ).read_text(encoding="utf-8")
    )
    expected = {
        chunk.knowledge_chunk_id: chunk
        for chunk in parse_attack(
            source.read_bytes(), manifest=manifest, embedding_model=MODEL_ID
        )
    }
    destination = Path(destination)
    engine = create_database_engine(settings.database_url)
    try:
        with (
            create_session_factory(engine)() as session,
            destination.open("x", encoding="utf-8") as out,
        ):
            count = 0
            for row in session.scalars(
                select(KnowledgeChunkTable).order_by(
                    KnowledgeChunkTable.knowledge_chunk_id
                )
            ):
                chunk = expected.get(row.knowledge_chunk_id)
                if chunk is None:
                    continue  # unregistered manual/test rows never enter this frozen corpus
                if (
                    row.source != chunk.source_uri
                    or row.content != chunk.content
                    or row.chunk_metadata != chunk.metadata
                ):
                    raise ValueError(
                        "knowledge database differs from pinned public source"
                    )
                embedding = row.embedding
                if embedding is not None:
                    embedding = [float(x) for x in embedding]
                validate_vectors(
                    [embedding], expected_count=1, dimensions=MODEL_DIMENSIONS
                )
                out.write(
                    json.dumps(
                        {
                            "knowledge_chunk_id": row.knowledge_chunk_id,
                            "source": row.source,
                            "content": row.content,
                            "chunk_metadata": row.chunk_metadata,
                            "embedding": embedding,
                        },
                        ensure_ascii=False,
                    )
                    + "\n"
                )
                count += 1
        if count != len(expected):
            raise ValueError("frozen knowledge source is incomplete")
        import hashlib

        return {
            "rows": count,
            "sha256": hashlib.sha256(destination.read_bytes()).hexdigest(),
            "source_sha256": manifest.sha256,
            "embedding_model": MODEL_ID,
        }
    finally:
        engine.dispose()


@contextmanager
def case_environment(spec, seed):
    """Only freshly named resources are created/dropped; no existing data is edited."""
    base = Settings(_env_file=None)
    url = make_url(base.database_url)
    if url.get_backend_name() != "postgresql":
        raise ValueError("Task13 real worker requires PostgreSQL")
    suffix = uuid.uuid4().hex
    db_name = "task13_" + suffix
    index = "security-events-task13-" + suffix
    admin = create_engine(url.set(database="postgres"), isolation_level="AUTOCOMMIT")
    engine = None
    search = create_opensearch_client(base.opensearch_url)
    database_created = index_created = False
    resources = None
    previous_db = os.environ.get("DATABASE_URL")
    previous_index = os.environ.get("OPENSEARCH_INDEX")
    try:
        with admin.connect() as connection:
            connection.exec_driver_sql(f'CREATE DATABASE "{db_name}"')
        database_created = True
        isolated_url = url.set(database=db_name).render_as_string(hide_password=False)
        settings = Settings(
            _env_file=None,
            database_url=isolated_url,
            opensearch_url=base.opensearch_url,
            opensearch_index=index,
            rag_data_directory=base.rag_data_directory,
            llm_mode="deepseek",
        )
        engine = create_database_engine(isolated_url)
        with engine.begin() as connection:
            connection.execute(text("CREATE EXTENSION IF NOT EXISTS vector"))
        Base.metadata.create_all(engine)
        sessions = create_session_factory(engine)
        knowledge = base.rag_data_directory / "knowledge_chunks.jsonl"
        if not knowledge.is_file():
            raise ValueError("hash-bound public knowledge snapshot is required")
        with knowledge.open(encoding="utf-8") as stream, sessions() as session:
            batch = []
            for line in stream:
                batch.append(json.loads(line))
                if len(batch) >= 200:
                    session.execute(insert(KnowledgeChunkTable), batch)
                    batch = []
            if batch:
                session.execute(insert(KnowledgeChunkTable), batch)
            session.commit()
        # The global template is frozen by Task12; no template mutation here.
        search.indices.create(
            index=index,
            body={"settings": {"number_of_shards": 1, "number_of_replicas": 0}},
        )
        index_created = True
        store = OpenSearchEventStore(search, index_name=index)
        incident_id = (
            "IN-" + canonical_hash([spec.run_id, spec.case_id, spec.group])[:26]
        )
        with sessions() as session:
            for document in seed["events"]:
                event = SecurityEvent.model_validate(document)
                event.index_status = EventIndexStatus.INDEXED
                row = event.model_dump(mode="python")
                session.add(SecurityEventTable(**row))
                store.index_event(event)
            session.commit()
            alert = {**seed["alerts"][0]}
            # Full case anchor stays in the service DB; model-facing alert remains
            # bounded to the identical mechanical seed in every group.
            alert["event_ids"] = [item["event_id"] for item in seed["events"]]
            alert["created_at"] = datetime.fromisoformat(alert["created_at"])
            session.add(AlertTable(**alert))
            session.flush()
            session.add(
                IncidentTable(
                    incident_id=incident_id,
                    alert_id=alert["alert_id"],
                    status="received",
                    created_at=alert["created_at"],
                )
            )
            session.flush()
            for item in seed["evidence"]:
                values = {key: value for key, value in item.items() if key != "raw"}
                values["observed_at"] = datetime.fromisoformat(values["observed_at"])
                session.add(EvidenceItemTable(**values, incident_id=incident_id))
            session.commit()
        search.indices.refresh(index=index)
        # Child MCP gets only this case database and index, never the base DB.
        os.environ["DATABASE_URL"] = isolated_url
        os.environ["OPENSEARCH_INDEX"] = index
        resources = CaseResources(
            settings, sessions, incident_id, db_name, index, spec.run_id, spec.case_id
        )
        yield resources
    finally:
        if previous_db is None:
            os.environ.pop("DATABASE_URL", None)
        else:
            os.environ["DATABASE_URL"] = previous_db
        if previous_index is None:
            os.environ.pop("OPENSEARCH_INDEX", None)
        else:
            os.environ["OPENSEARCH_INDEX"] = previous_index
        if engine is not None:
            engine.dispose()
        if index_created and not (resources and resources.retained):
            search.indices.delete(index=index)
        if database_created and not (resources and resources.retained):
            with admin.connect() as connection:
                connection.exec_driver_sql(f'DROP DATABASE "{db_name}" WITH (FORCE)')
        search.close()
        admin.dispose()
