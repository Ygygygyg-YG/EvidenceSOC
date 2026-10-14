from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from evidencesoc.config import Settings
from evidencesoc.ids import new_ulid
from evidencesoc.persistence.database import (
    create_database_engine,
    create_session_factory,
)
from evidencesoc.persistence.tables import KnowledgeChunkTable
from evidencesoc.rag.ingest_attack import PINNED_STIX_SHA256
from evidencesoc.rag.retriever import PostgresKnowledgeRepository
from sqlalchemy import delete


@contextmanager
def seeded_repository() -> Iterator[
    tuple[PostgresKnowledgeRepository, str, dict[str, str]]
]:
    token = f"taskseven{new_ulid().lower()}"
    kinds = (
        "dns",
        "other",
        "wrong-model",
        "wrong-dimension",
        "revoked",
        "deprecated",
        "untrusted",
        "old-version",
        "manual",
        "untrusted-manual",
        "wrong-hash",
        "invalid-revoked",
        "string-trusted-manual",
        "retired-manual",
    )
    ids = {kind: f"KC-{token}-{kind}" for kind in kinds}
    engine = create_database_engine(Settings().database_url)
    sessions = create_session_factory(engine)
    try:
        with sessions() as session:
            try:
                rows = []
                for kind in kinds:
                    metadata: dict[str, object] = {
                        "object_type": "attack-pattern",
                        "technique_id": "T1048.003",
                        "title": token + " DNS exfiltration",
                        "version": "19.2",
                        "embedding_model": token,
                        "source_type": "mitre_attack",
                        "stix_hash": PINNED_STIX_SHA256,
                        "revoked": kind == "revoked",
                        "deprecated": kind == "deprecated",
                    }
                    source = "https://attack.mitre.org/techniques/T1048/003/"
                    vector = [1.0, 0.0] if kind != "other" else [0.0, 1.0]
                    if kind == "wrong-model":
                        metadata["embedding_model"] = "different-model"
                    if kind == "wrong-dimension":
                        vector = [1.0, 0.0, 0.0]
                    if kind == "untrusted":
                        source = "https://untrusted.invalid/"
                    if kind == "old-version":
                        metadata["version"] = "18.0"
                    if kind == "wrong-hash":
                        metadata["stix_hash"] = "0" * 64
                    if kind == "invalid-revoked":
                        metadata["revoked"] = "malformed"
                    if "manual" in kind:
                        metadata.update(
                            object_type="manual",
                            technique_id=None,
                            source_type="internal_manual",
                            trusted=kind in {"manual", "retired-manual"},
                        )
                        source = "internal://knowledge/test-manual"
                    if kind == "string-trusted-manual":
                        metadata["trusted"] = "true"
                    if kind == "retired-manual":
                        metadata["deprecated"] = True
                    rows.append(
                        KnowledgeChunkTable(
                            knowledge_chunk_id=ids[kind],
                            source=source,
                            content=token + " DNS data exfiltration via name lookups",
                            chunk_metadata=metadata,
                            embedding=vector,
                        )
                    )
                session.add_all(rows)
                session.commit()
                yield (
                    PostgresKnowledgeRepository(session, embedding_model=token),
                    token,
                    ids,
                )
            finally:
                session.rollback()
                session.execute(
                    delete(KnowledgeChunkTable).where(
                        KnowledgeChunkTable.knowledge_chunk_id.in_(ids.values())
                    )
                )
                session.commit()
    finally:
        engine.dispose()


def test_pgvector_cosine_sort_filters_model_dimension_version_and_untrusted_rows() -> (
    None
):
    with seeded_repository() as (repository, _, ids):
        results = repository.semantic([1.0, 0.0], 10)
        assert {item["knowledge_chunk_id"] for item in results} == {
            ids["dns"],
            ids["manual"],
            ids["other"],
        }
        assert results[-1]["knowledge_chunk_id"] == ids["other"]


def test_keyword_full_text_search_and_trusted_manual_ingestion_shape() -> None:
    with seeded_repository() as (repository, token, ids):
        results = repository.keyword(token, 20)
        assert {item["knowledge_chunk_id"] for item in results} == {
            ids["dns"],
            ids["other"],
            ids["wrong-dimension"],
            ids["manual"],
        }
        assert repository.keyword("%_'", 20) == []
        assert ids["dns"] in {
            item["knowledge_chunk_id"]
            for item in repository.keyword(token + " 数据外泄", 10)
        }


def test_mcp_attack_only_repository_excludes_response_manuals() -> None:
    with seeded_repository() as (repository, token, ids):
        repository._attack_only = True
        assert ids["manual"] not in {
            item["knowledge_chunk_id"] for item in repository.keyword(token, 20)
        }


def test_exact_lookup_excludes_unverified_provenance_and_wrong_model() -> None:
    with seeded_repository() as (repository, _, ids):
        hits = {
            item["knowledge_chunk_id"] for item in repository.exact("T1048.003", 50)
        }
        assert ids["wrong-hash"] not in hits
        assert ids["wrong-model"] not in hits
        assert ids["dns"] in hits
