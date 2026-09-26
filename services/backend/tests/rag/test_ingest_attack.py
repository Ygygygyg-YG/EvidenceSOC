from __future__ import annotations

import copy
import hashlib
import importlib
import json
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy import delete, func, select
from sqlalchemy.dialects import postgresql
from sqlalchemy.exc import StatementError

from evidencesoc.config import Settings
from evidencesoc.ids import new_ulid
from evidencesoc.persistence.database import (
    create_database_engine,
    create_session_factory,
)
from evidencesoc.persistence.tables import KnowledgeChunkTable


def ingestion_module() -> Any:
    try:
        return importlib.import_module("evidencesoc.rag.ingest_attack")
    except ModuleNotFoundError as error:
        if error.name not in {"evidencesoc.rag", "evidencesoc.rag.ingest_attack"}:
            raise
        pytest.fail("ATT&CK ingestion is not implemented")


def bundle() -> dict[str, Any]:
    technique = {
        "type": "attack-pattern",
        "id": "attack-pattern--00000000-0000-4000-8000-000000000001",
        "name": "Exfiltration Over Alternative Protocol",
        "description": "Adversaries may exfiltrate data over DNS. Detection rules flag DNS abuse.",
        "external_references": [
            {
                "source_name": "mitre-attack",
                "external_id": "T1048.003",
                "url": "https://attack.mitre.org/techniques/T1048/003/",
            }
        ],
    }
    revoked = copy.deepcopy(technique)
    revoked["revoked"] = True
    deprecated = copy.deepcopy(technique)
    deprecated["x_mitre_deprecated"] = True
    return {
        "type": "bundle",
        "objects": [
            {"type": "x-mitre-collection", "x_mitre_version": "19.2"},
            technique,
            revoked,
            deprecated,
            {
                "type": "malware",
                "name": "Ignore software",
                "description": "Not a technique",
            },
        ],
    }


def fixture_source(
    monkeypatch: pytest.MonkeyPatch, payload: dict[str, Any] | None = None
) -> tuple[Any, bytes, Any]:
    module = ingestion_module()
    raw = json.dumps(payload or bundle()).encode()
    digest = hashlib.sha256(raw).hexdigest()
    monkeypatch.setattr(module, "PINNED_STIX_SHA256", digest)
    manifest = module.SourceManifest(
        version="19.2",
        sha256=digest,
        downloaded_at=datetime(2026, 9, 26, tzinfo=UTC),
        source_uri=module.PINNED_STIX_URL,
    )
    return module, raw, manifest


def test_active_techniques_have_verified_provenance_and_content_ids(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module, raw, manifest = fixture_source(monkeypatch)
    chunks = module.parse_attack(raw, manifest=manifest, embedding_model="local/test")
    assert len(chunks) == 1
    chunk = chunks[0]
    assert chunk.technique_id == "T1048.003"
    assert chunk.source_uri == "https://attack.mitre.org/techniques/T1048/003/"
    assert chunk.version == "19.2"
    assert (
        chunk.knowledge_chunk_id.startswith("KC-")
        and len(chunk.knowledge_chunk_id) <= 64
    )
    assert chunk.source_hash == manifest.sha256
    assert chunk.body_hash == hashlib.sha256(chunk.content.encode()).hexdigest()
    assert chunk.metadata["embedding_model"] == "local/test"
    assert chunk.metadata["downloaded_at"] == "2026-09-26T00:00:00Z"
    assert chunk.metadata["revoked"] is False
    assert chunk.metadata["deprecated"] is False
    assert chunks == module.parse_attack(
        raw, manifest=manifest, embedding_model="local/test"
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("version", "19.1"),
        ("sha256", "a" * 64),
        ("source_uri", "https://attacker.invalid/enterprise-attack.json"),
    ],
)
def test_manifest_rejected_before_embedding(
    monkeypatch: pytest.MonkeyPatch, field: str, value: str
) -> None:
    module, raw, manifest = fixture_source(monkeypatch)
    embedder = RecordingEmbedder()
    bad_manifest = manifest.model_copy(update={field: value})
    with pytest.raises(ValueError):
        module.ingest_attack(
            raw, manifest=bad_manifest, embedder=embedder, session=RecordingSession()
        )
    assert embedder.calls == []


def test_manifest_raw_hash_verified_before_json_decode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module, _, manifest = fixture_source(monkeypatch)
    with pytest.raises(ValueError, match="hash"):
        module.parse_attack(
            b"not valid JSON", manifest=manifest, embedding_model="local/test"
        )


@pytest.mark.parametrize(
    "change",
    [
        "collection_version",
        "missing_collection",
        "technique_id",
        "source_uri",
        "revoked_type",
    ],
)
def test_invalid_bundle_rejected(monkeypatch: pytest.MonkeyPatch, change: str) -> None:
    payload = bundle()
    if change == "collection_version":
        payload["objects"][0]["x_mitre_version"] = "19.1"
    elif change == "missing_collection":
        payload["objects"].pop(0)
    elif change == "technique_id":
        payload["objects"][1]["external_references"][0]["external_id"] = "T1"
    elif change == "source_uri":
        payload["objects"][1]["external_references"][0]["url"] = (
            "https://attack.mitre.org.evil/techniques/T1048/003/"
        )
    else:
        payload["objects"][1]["revoked"] = "false"
    module, raw, manifest = fixture_source(monkeypatch, payload)
    with pytest.raises(ValueError):
        module.parse_attack(raw, manifest=manifest, embedding_model="local/test")


@pytest.mark.parametrize(
    "forbidden",
    ["labels", "ground_truth", "attacker_truth", "evaluation_labels", "attacks.log"],
)
def test_recursive_evaluation_truth_fields_rejected(
    monkeypatch: pytest.MonkeyPatch, forbidden: str
) -> None:
    payload = bundle()
    payload["objects"][1]["extra"] = {"nested": [{forbidden: "secret answer"}]}
    module, raw, manifest = fixture_source(monkeypatch, payload)
    with pytest.raises(ValueError, match="evaluation|truth|forbidden"):
        module.parse_attack(raw, manifest=manifest, embedding_model="local/test")


def test_stix_official_labels_allowed_as_descriptive_taxonomy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = bundle()
    payload["objects"].append({"type": "malware", "labels": ["malware"]})
    module, raw, manifest = fixture_source(monkeypatch, payload)
    # ATT&CK techniques may not take benchmark labels, while other STIX object
    # types legitimately carry the standard descriptive taxonomy field.
    assert (
        len(module.parse_attack(raw, manifest=manifest, embedding_model="local/test"))
        == 1
    )


def test_official_source_uri_without_trailing_slash_normalized(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = bundle()
    payload["objects"][1]["external_references"][0]["url"] = (
        "https://attack.mitre.org/techniques/T1048/003"
    )
    module, raw, manifest = fixture_source(monkeypatch, payload)
    chunks = module.parse_attack(raw, manifest=manifest, embedding_model="local/test")
    assert chunks[0].source_uri == "https://attack.mitre.org/techniques/T1048/003/"


def test_long_bodies_bounded_without_content_loss(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = bundle()
    description = "DNS exfiltration detection. " * 200
    payload["objects"][1]["description"] = description
    module, raw, manifest = fixture_source(monkeypatch, payload)
    chunks = module.parse_attack(raw, manifest=manifest, embedding_model="local/test")
    assert len(chunks) > 1
    assert all(len(chunk.content) <= 1500 for chunk in chunks)
    assert "".join(chunk.content for chunk in chunks) == description
    assert len({chunk.knowledge_chunk_id for chunk in chunks}) == len(chunks)


def test_semantic_title_and_embedding_model_participate_in_chunk_identity() -> None:
    module, raw, manifest = manual_fixture()
    first = module.parse_manual(
        raw,
        manifest=manifest,
        title="DNS response",
        trusted=True,
        embedding_model="local/test",
    )[0]
    changed_title = module.parse_manual(
        raw,
        manifest=manifest,
        title="Alternative rule",
        trusted=True,
        embedding_model="local/test",
    )[0]
    changed_model = module.parse_manual(
        raw,
        manifest=manifest,
        title="DNS response",
        trusted=True,
        embedding_model="local/other",
    )[0]
    assert (
        len(
            {
                first.knowledge_chunk_id,
                changed_title.knowledge_chunk_id,
                changed_model.knowledge_chunk_id,
            }
        )
        == 3
    )
    assert first.body_hash == changed_title.body_hash == changed_model.body_hash


class RecordingEmbedder:
    model_id = "local/test"

    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        self.calls.append(texts)
        return [[0.2, 0.8] for _ in texts]


class RecordingSession:
    def __init__(self) -> None:
        self.statements: list[Any] = []
        self.completed = False
        self.rolled_back = False

    def in_transaction(self) -> bool:
        return False

    @contextmanager
    def begin(self) -> Any:
        try:
            yield self
            self.completed = True
        except Exception:
            self.rolled_back = True
            raise

    def execute(self, statement: Any) -> None:
        self.statements.append(statement)


def test_ingestion_uses_bound_atomic_idempotent_postgres_upsert(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module, raw, manifest = fixture_source(monkeypatch)
    session = RecordingSession()
    embedder = RecordingEmbedder()
    chunks = module.ingest_attack(
        raw, manifest=manifest, embedder=embedder, session=session
    )
    assert len(embedder.calls) == 1
    assert embedder.calls[0] == [chunk.title + "\n" + chunk.content for chunk in chunks]
    assert session.completed and len(session.statements) == 1
    statement = session.statements[0].compile(dialect=postgresql.dialect())
    assert "ON CONFLICT (knowledge_chunk_id) DO UPDATE" in str(statement)
    assert chunks[0].content not in str(statement)
    values = list(statement.params.values())
    assert chunks[0].source_uri in values
    assert chunks[0].content in values
    assert any(
        isinstance(value, dict) and value.get("source_hash") == manifest.sha256
        for value in values
    )


@pytest.mark.parametrize(
    "vectors", [[], [[float("nan"), 1.0]], [[0.0, 0.0]], [[1.0], [1.0]]]
)
def test_bad_embedding_rejected_before_database_writes(
    monkeypatch: pytest.MonkeyPatch, vectors: list[list[float]]
) -> None:
    module, raw, manifest = fixture_source(monkeypatch)
    embedder = RecordingEmbedder()
    monkeypatch.setattr(embedder, "embed_documents", lambda texts: vectors)
    session = RecordingSession()
    with pytest.raises(ValueError, match="embedding|vector"):
        module.ingest_attack(raw, manifest=manifest, embedder=embedder, session=session)
    assert session.statements == []


def test_verified_inline_manual_requires_explicit_trust(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = ingestion_module()
    raw = (
        b"Internal DNS rule: inspect unusual query volumes and review packet captures."
    )
    manifest = module.SourceManifest(
        version="manual-1",
        sha256=hashlib.sha256(raw).hexdigest(),
        downloaded_at=datetime(2026, 9, 26, tzinfo=UTC),
        source_uri="internal://knowledge/dns-rule",
    )
    with pytest.raises(ValueError, match="trusted"):
        module.parse_manual(
            raw,
            manifest=manifest,
            title="DNS response",
            embedding_model="local/test",
            trusted=False,
        )
    chunks = module.parse_manual(
        raw,
        manifest=manifest,
        title="DNS response",
        embedding_model="local/test",
        trusted=True,
    )
    assert chunks[0].object_type == "manual"
    assert chunks[0].metadata["trusted"] is True
    assert chunks[0].metadata["source_type"] == "internal_manual"
    assert chunks[0].source_hash == manifest.sha256


@pytest.mark.parametrize(
    "source",
    [
        "internal://knowledge/evaluation/answers",
        "internal://knowledge/labels/x",
        "internal://knowledge/attacks.log",
        "file:///evaluation/truth.json",
    ],
)
def test_manual_forbids_evaluation_source_provenance(source: str) -> None:
    module = ingestion_module()
    raw = b"Internal response manual"
    manifest = module.SourceManifest(
        version="1",
        sha256=hashlib.sha256(raw).hexdigest(),
        downloaded_at=datetime(2026, 9, 26, tzinfo=UTC),
        source_uri=source,
    )
    with pytest.raises(ValueError):
        module.parse_manual(
            raw,
            manifest=manifest,
            title="Manual",
            embedding_model="local/test",
            trusted=True,
        )


def test_manifest_requires_timezone_aware_download_date() -> None:
    module = ingestion_module()
    with pytest.raises(ValueError):
        module.SourceManifest(
            version="19.2",
            sha256="a" * 64,
            downloaded_at=datetime(2026, 9, 26, tzinfo=UTC).replace(tzinfo=None),
            source_uri=module.PINNED_STIX_URL,
        )


@pytest.mark.parametrize(
    "marker", ["attacker_0", "attacks.log", "evaluation/labels.json", "ground_truth:"]
)
def test_manual_rejects_known_evaluation_truth_markers(marker: str) -> None:
    module = ingestion_module()
    raw = f"Known evaluation truth: {marker}".encode()
    manifest = module.SourceManifest(
        version="1",
        sha256=hashlib.sha256(raw).hexdigest(),
        downloaded_at=datetime(2026, 9, 26, tzinfo=UTC),
        source_uri="internal://knowledge/rule",
    )
    with pytest.raises(ValueError, match="evaluation|truth"):
        module.parse_manual(
            raw,
            manifest=manifest,
            title="Rule",
            embedding_model="local/test",
            trusted=True,
        )


def manual_fixture() -> tuple[Any, bytes, Any]:
    module = ingestion_module()
    raw = b"Review DNS query volumes and preserve resolver telemetry before response."
    manifest = module.SourceManifest(
        version="test-1",
        sha256=hashlib.sha256(raw).hexdigest(),
        downloaded_at=datetime(2026, 9, 26, tzinfo=UTC),
        source_uri=f"internal://knowledge/test-{new_ulid()}",
    )
    return module, raw, manifest


def test_manual_ingestion_is_idempotent_against_live_postgresql() -> None:
    module, raw, manifest = manual_fixture()
    engine = create_database_engine(Settings().database_url)
    sessions = create_session_factory(engine)
    chunks = module.parse_manual(
        raw,
        manifest=manifest,
        title="DNS response",
        trusted=True,
        embedding_model="local/test",
    )
    ids = [chunk.knowledge_chunk_id for chunk in chunks]
    try:
        with sessions() as session:
            for _ in range(2):
                result = module.ingest_manual(
                    raw,
                    manifest=manifest,
                    title="DNS response",
                    trusted=True,
                    embedder=RecordingEmbedder(),
                    session=session,
                )
                assert result == chunks
        with sessions() as session:
            rows = (
                session.execute(
                    select(KnowledgeChunkTable).where(
                        KnowledgeChunkTable.knowledge_chunk_id.in_(ids)
                    )
                )
                .scalars()
                .all()
            )
            assert len(rows) == 1
            assert rows[0].chunk_metadata == chunks[0].metadata
            assert list(rows[0].embedding) == pytest.approx([0.2, 0.8])
    finally:
        with sessions() as session:
            session.execute(
                delete(KnowledgeChunkTable).where(
                    KnowledgeChunkTable.knowledge_chunk_id.in_(ids)
                )
            )
            session.commit()
        engine.dispose()


def test_second_batch_failure_rolls_back_all_chunks_in_live_postgresql() -> None:
    module, raw, manifest = manual_fixture()
    chunk = module.parse_manual(
        raw,
        manifest=manifest,
        title="DNS response",
        trusted=True,
        embedding_model="local/test",
    )[0]
    chunks = [
        chunk.model_copy(
            update={
                "knowledge_chunk_id": "KC-"
                + hashlib.sha256(f"{manifest.source_uri}/{index}".encode()).hexdigest()[
                    :60
                ],
            }
        )
        for index in range(501)
    ]
    # PostgreSQL rejects NUL in text. Put it in the second SQL batch to prove
    # the earlier 500 inserts are part of the same atomic transaction.
    chunks[-1] = chunks[-1].model_copy(update={"content": "bad\x00text"})
    ids = [item.knowledge_chunk_id for item in chunks]
    engine = create_database_engine(Settings().database_url)
    sessions = create_session_factory(engine)
    try:
        with (
            sessions() as session,
            pytest.raises(StatementError, match="NUL|0x00|zero byte"),
        ):
            module.upsert_chunks(session, chunks, [[0.2, 0.8] for _ in chunks])
        with sessions() as session:
            count = session.execute(
                select(func.count())
                .select_from(KnowledgeChunkTable)
                .where(KnowledgeChunkTable.knowledge_chunk_id.in_(ids))
            ).scalar_one()
            assert count == 0
    finally:
        with sessions() as session:
            session.execute(
                delete(KnowledgeChunkTable).where(
                    KnowledgeChunkTable.knowledge_chunk_id.in_(ids)
                )
            )
            session.commit()
        engine.dispose()


def test_manual_new_revision_deprecates_old_chunks_but_preserves_history() -> None:
    module, raw, manifest = manual_fixture()
    revised_raw = b"Review DNS query volumes, resolver telemetry, and packet captures."
    revised_manifest = manifest.model_copy(
        update={"version": "test-2", "sha256": hashlib.sha256(revised_raw).hexdigest()}
    )
    engine = create_database_engine(Settings().database_url)
    sessions = create_session_factory(engine)
    try:
        with sessions() as session:
            old = module.ingest_manual(
                raw,
                manifest=manifest,
                title="DNS response",
                trusted=True,
                embedder=RecordingEmbedder(),
                session=session,
            )
            new = module.ingest_manual(
                revised_raw,
                manifest=revised_manifest,
                title="DNS response",
                trusted=True,
                embedder=RecordingEmbedder(),
                session=session,
            )
            module.ingest_manual(
                revised_raw,
                manifest=revised_manifest,
                title="DNS response",
                trusted=True,
                embedder=RecordingEmbedder(),
                session=session,
            )
        with sessions() as session:
            rows = (
                session.execute(
                    select(KnowledgeChunkTable).where(
                        KnowledgeChunkTable.source == manifest.source_uri
                    )
                )
                .scalars()
                .all()
            )
            assert len(rows) == 2
            indexed = {row.knowledge_chunk_id: row for row in rows}
            assert indexed[old[0].knowledge_chunk_id].content == old[0].content
            assert (
                indexed[old[0].knowledge_chunk_id].chunk_metadata["deprecated"] is True
            )
            assert (
                indexed[new[0].knowledge_chunk_id].chunk_metadata["deprecated"] is False
            )
            assert (
                indexed[new[0].knowledge_chunk_id].chunk_metadata["version"] == "test-2"
            )
    finally:
        with sessions() as session:
            session.execute(
                delete(KnowledgeChunkTable).where(
                    KnowledgeChunkTable.source == manifest.source_uri
                )
            )
            session.commit()
        engine.dispose()


@pytest.mark.parametrize("caller_transaction", [False, True])
def test_failed_manual_replacement_keeps_previous_revision_active(
    caller_transaction: bool,
) -> None:
    module, raw, manifest = manual_fixture()
    revised_raw = b"Revision fails PostgreSQL text validation\x00here."
    revised_manifest = manifest.model_copy(
        update={"version": "test-2", "sha256": hashlib.sha256(revised_raw).hexdigest()}
    )
    engine = create_database_engine(Settings().database_url)
    sessions = create_session_factory(engine)
    try:
        with sessions() as session:
            old = module.ingest_manual(
                raw,
                manifest=manifest,
                title="DNS response",
                trusted=True,
                embedder=RecordingEmbedder(),
                session=session,
            )
        with sessions() as session:
            if caller_transaction:
                session.begin()
            with pytest.raises(StatementError, match="NUL|0x00|zero byte"):
                module.ingest_manual(
                    revised_raw,
                    manifest=revised_manifest,
                    title="DNS response",
                    trusted=True,
                    embedder=RecordingEmbedder(),
                    session=session,
                )
            if caller_transaction:
                assert session.in_transaction()
                session.commit()
        with sessions() as session:
            rows = (
                session.execute(
                    select(KnowledgeChunkTable).where(
                        KnowledgeChunkTable.source == manifest.source_uri
                    )
                )
                .scalars()
                .all()
            )
            assert len(rows) == 1
            assert rows[0].knowledge_chunk_id == old[0].knowledge_chunk_id
            assert rows[0].chunk_metadata["deprecated"] is False
    finally:
        with sessions() as session:
            session.execute(
                delete(KnowledgeChunkTable).where(
                    KnowledgeChunkTable.source == manifest.source_uri
                )
            )
            session.commit()
        engine.dispose()


def test_invalid_replacement_embeddings_do_not_retire_existing_manual(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module, raw, manifest = manual_fixture()
    embedder = RecordingEmbedder()
    monkeypatch.setattr(embedder, "embed_documents", lambda texts: [[0.0, 0.0]])
    session = RecordingSession()
    with pytest.raises(ValueError, match="embedding"):
        module.ingest_manual(
            raw,
            manifest=manifest,
            title="DNS response",
            trusted=True,
            embedder=embedder,
            session=session,
        )
    assert session.statements == []
