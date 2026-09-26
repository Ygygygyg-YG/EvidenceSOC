from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Iterator, Sequence
from typing import Any, cast
from urllib.parse import unquote, urlsplit

from sqlalchemy import Table, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from evidencesoc.persistence.tables import KnowledgeChunkTable
from evidencesoc.rag.models import EmbeddingProvider, KnowledgeChunk, SourceManifest

PINNED_ATTACK_VERSION = "19.2"
PINNED_STIX_COMMIT = "6cda5ad8462c79e14fbb872f4e09059b18e0cfc4"
PINNED_STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    f"{PINNED_STIX_COMMIT}/enterprise-attack/enterprise-attack-19.2.json"
)
PINNED_STIX_SHA256 = "dc1639caa5501d720e280cf1cbd8fbe009884a0c9b3e6e9ed9d0c25166c3d8f4"
MAX_CHUNK_CHARACTERS = 1500
_TECHNIQUE_ID = re.compile(r"T\d{4}(?:\.\d{3})?\Z")
_FORBIDDEN_PARTS = {
    "label",
    "labels",
    "truth",
    "evaluation",
    "benchmark",
    "attacker",
    "attacks.log",
}
_MANUAL_TRUTH_MARKERS = re.compile(
    r"attacker_\d+|attacks\.log|(?:evaluation|benchmark)[/\\]|"
    r"ground[_ -]?truth|attacker[_ -]?truth|evaluation[_ -]?labels",
    re.IGNORECASE,
)


def _verify_hash(raw: bytes, manifest: SourceManifest) -> None:
    # Revalidate even if a caller used model_construct/model_copy to bypass validation.
    SourceManifest.model_validate(manifest.model_dump())
    if hashlib.sha256(raw).hexdigest() != manifest.sha256:
        raise ValueError("source hash does not match raw input bytes")


def _reject_truth_fields(value: Any, *, standard_labels: bool = False) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = (
                re.sub(r"([a-z])([A-Z])", r"\1_\2", str(key))
                .casefold()
                .replace("-", "_")
            )
            parts = set(re.split(r"[^a-z0-9.]+", normalized))
            if (
                parts & _FORBIDDEN_PARTS
                or normalized in {"ground_truth", "evaluation_labels"}
            ) and not (standard_labels and normalized == "labels"):
                raise ValueError(f"forbidden evaluation or truth field: {key}")
            _reject_truth_fields(child)
    elif isinstance(value, list):
        for child in value:
            _reject_truth_fields(child)


def _split_body(content: str) -> Iterator[str]:
    while content:
        end = min(MAX_CHUNK_CHARACTERS, len(content))
        if end < len(content):
            # Keep sentences/words together when there is a nearby boundary;
            # preserve every character so provenance can reconstruct the body.
            boundary = max(content.rfind("\n", 0, end), content.rfind(". ", 0, end))
            if boundary >= end // 2:
                end = boundary + (2 if content[boundary : boundary + 2] == ". " else 1)
            else:
                space = content.rfind(" ", 0, end)
                if space >= end // 2:
                    end = space + 1
        yield content[:end]
        content = content[end:]


def _make_chunks(
    *,
    content: str,
    title: str,
    source_uri: str,
    manifest: SourceManifest,
    embedding_model: str,
    object_type: str,
    technique_id: str | None = None,
    stix_id: str | None = None,
    trusted: bool = False,
) -> list[KnowledgeChunk]:
    if not content.strip() or not title.strip():
        raise ValueError("knowledge title and body must not be blank")
    chunks = []
    for index, body in enumerate(_split_body(content)):
        body_hash = hashlib.sha256(body.encode("utf-8")).hexdigest()
        identity = json.dumps(
            [
                source_uri,
                manifest.version,
                stix_id,
                title,
                index,
                body_hash,
                embedding_model,
            ],
            ensure_ascii=False,
            separators=(",", ":"),
        )
        chunk_id = "KC-" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:60]
        chunks.append(
            KnowledgeChunk(
                knowledge_chunk_id=chunk_id,
                source_uri=source_uri,
                version=manifest.version,
                title=title,
                content=body,
                technique_id=technique_id,
                object_type=object_type,  # type: ignore[arg-type]
                source_hash=manifest.sha256,
                body_hash=body_hash,
                downloaded_at=manifest.downloaded_at,
                embedding_model=embedding_model,
                stix_id=stix_id,
                trusted=trusted,
            )
        )
    return chunks


def parse_attack(
    raw: bytes,
    *,
    manifest: SourceManifest,
    embedding_model: str,
) -> list[KnowledgeChunk]:
    """Parse only the hash-pinned official Enterprise ATT&CK release, offline."""
    _verify_hash(raw, manifest)
    if manifest.version != PINNED_ATTACK_VERSION:
        raise ValueError("ATT&CK manifest version must be 19.2")
    if manifest.source_uri != PINNED_STIX_URL or manifest.sha256 != PINNED_STIX_SHA256:
        raise ValueError(
            "ATT&CK manifest must identify the pinned official source and hash"
        )
    document = json.loads(raw)
    if not isinstance(document, dict) or document.get("type") != "bundle":
        raise ValueError("ATT&CK source must be a STIX bundle")
    objects = document.get("objects")
    if not isinstance(objects, list) or not all(
        isinstance(obj, dict) for obj in objects
    ):
        raise ValueError("STIX bundle objects must be a list of objects")
    _reject_truth_fields(
        {key: value for key, value in document.items() if key != "objects"}
    )
    collections = [obj for obj in objects if obj.get("type") == "x-mitre-collection"]
    if (
        len(collections) != 1
        or collections[0].get("x_mitre_version") != PINNED_ATTACK_VERSION
    ):
        raise ValueError("STIX collection must declare ATT&CK version 19.2")
    chunks: list[KnowledgeChunk] = []
    for obj in objects:
        _reject_truth_fields(
            obj, standard_labels=obj.get("type") in {"malware", "tool", "indicator"}
        )
        if obj.get("type") != "attack-pattern":
            continue
        for flag in ("revoked", "x_mitre_deprecated"):
            if flag in obj and not isinstance(obj[flag], bool):
                raise ValueError(f"STIX {flag} must be a boolean")
        if obj.get("revoked", False) or obj.get("x_mitre_deprecated", False):
            continue
        refs = obj.get("external_references", [])
        if not isinstance(refs, list) or not all(isinstance(ref, dict) for ref in refs):
            raise ValueError("STIX external_references must be a list")
        attack_refs = [
            ref
            for ref in refs
            if isinstance(ref, dict) and ref.get("source_name") == "mitre-attack"
        ]
        if len(attack_refs) != 1:
            raise ValueError("technique must have exactly one MITRE ATT&CK reference")
        ref = attack_refs[0]
        technique_id = ref.get("external_id")
        if not isinstance(technique_id, str) or not _TECHNIQUE_ID.fullmatch(
            technique_id
        ):
            raise ValueError("invalid MITRE Technique ID")
        canonical_uri = (
            "https://attack.mitre.org/techniques/"
            + technique_id.replace(".", "/")
            + "/"
        )
        if ref.get("url") not in {canonical_uri, canonical_uri.rstrip("/")}:
            raise ValueError("technique source_uri must be the canonical MITRE URI")
        title, content, stix_id = obj.get("name"), obj.get("description"), obj.get("id")
        if (
            not isinstance(title, str)
            or not title.strip()
            or not isinstance(content, str)
            or not content.strip()
        ):
            raise ValueError("STIX technique must have a title and description")
        if not isinstance(stix_id, str) or not stix_id.startswith("attack-pattern--"):
            raise ValueError("STIX technique must have an attack-pattern id")
        chunks.extend(
            _make_chunks(
                content=content,
                title=title,
                source_uri=canonical_uri,
                manifest=manifest,
                embedding_model=embedding_model,
                object_type="attack-pattern",
                technique_id=technique_id,
                stix_id=stix_id,
            )
        )
    return chunks


def parse_manual(
    raw: bytes,
    *,
    manifest: SourceManifest,
    title: str,
    embedding_model: str,
    trusted: bool,
) -> list[KnowledgeChunk]:
    """Load operator-approved inline internal manual bytes with verified provenance."""
    _verify_hash(raw, manifest)
    if trusted is not True:
        raise ValueError("internal manual must be explicitly trusted")
    uri = urlsplit(manifest.source_uri)
    path = unquote(uri.path).casefold()
    parts = set(re.split(r"[^a-z0-9.]+", path))
    if (
        uri.scheme != "internal"
        or uri.netloc != "knowledge"
        or not uri.path.strip("/")
        or uri.query
        or uri.fragment
    ):
        raise ValueError(
            "manual source must use canonical internal://knowledge provenance"
        )
    if parts & _FORBIDDEN_PARTS or ".." in path or "%" in path:
        raise ValueError("evaluation, labels and attacker truth sources are forbidden")
    content = raw.decode("utf-8")
    if _MANUAL_TRUTH_MARKERS.search(content):
        raise ValueError(
            "manual contains forbidden evaluation or attacker truth markers"
        )
    if content.lstrip().startswith(("{", "[")):
        _reject_truth_fields(json.loads(content))
    return _make_chunks(
        content=content,
        title=title,
        source_uri=manifest.source_uri,
        manifest=manifest,
        embedding_model=embedding_model,
        object_type="manual",
        trusted=True,
    )


def _validated_vectors(
    vectors: list[list[float]], expected_count: int
) -> list[list[float]]:
    if len(vectors) != expected_count:
        raise ValueError("embedding count does not match chunk count")
    dimensions: int | None = None
    for vector in vectors:
        if not vector or (dimensions is not None and len(vector) != dimensions):
            raise ValueError(
                "embedding vector dimensions must be nonzero and consistent"
            )
        if any(
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
            for value in vector
        ):
            raise ValueError("embedding vectors must contain finite numbers")
        if not any(value != 0 for value in vector):
            raise ValueError("embedding vectors must have nonzero magnitude")
        dimensions = len(vector)
    return vectors


def upsert_chunks(
    session: Session, chunks: Sequence[KnowledgeChunk], vectors: list[list[float]]
) -> None:
    """Atomically write metadata and vectors without replacing caller transactions."""
    _validated_vectors(vectors, len(chunks))
    if not chunks:
        return
    transaction = (
        session.begin_nested() if session.in_transaction() else session.begin()
    )
    with transaction:
        # Bounded batches keep PostgreSQL's parameter count below its limit.
        for offset in range(0, len(chunks), 500):
            values = [
                {
                    "knowledge_chunk_id": chunk.knowledge_chunk_id,
                    "source": chunk.source_uri,
                    "content": chunk.content,
                    "metadata": chunk.metadata,
                    "embedding": vector,
                }
                for chunk, vector in zip(
                    chunks[offset : offset + 500],
                    vectors[offset : offset + 500],
                    strict=True,
                )
            ]
            statement = insert(cast(Table, KnowledgeChunkTable.__table__)).values(
                values
            )
            statement = statement.on_conflict_do_update(
                index_elements=[KnowledgeChunkTable.knowledge_chunk_id],
                set_={
                    "source": statement.excluded.source,
                    "content": statement.excluded.content,
                    "metadata": statement.excluded.metadata,
                    "embedding": statement.excluded.embedding,
                },
            )
            session.execute(statement)


def ingest_attack(
    raw: bytes,
    *,
    manifest: SourceManifest,
    embedder: EmbeddingProvider,
    session: Session,
) -> list[KnowledgeChunk]:
    chunks = parse_attack(raw, manifest=manifest, embedding_model=embedder.model_id)
    vectors = (
        embedder.embed_documents(
            [chunk.title + "\n" + chunk.content for chunk in chunks]
        )
        if chunks
        else []
    )
    upsert_chunks(session, chunks, vectors)
    return chunks


def ingest_manual(
    raw: bytes,
    *,
    manifest: SourceManifest,
    title: str,
    trusted: bool,
    embedder: EmbeddingProvider,
    session: Session,
) -> list[KnowledgeChunk]:
    chunks = parse_manual(
        raw,
        manifest=manifest,
        title=title,
        trusted=trusted,
        embedding_model=embedder.model_id,
    )
    vectors = embedder.embed_documents(
        [chunk.title + "\n" + chunk.content for chunk in chunks]
    )
    _validated_vectors(vectors, len(chunks))
    transaction = (
        session.begin_nested() if session.in_transaction() else session.begin()
    )
    with transaction:
        # Keep older revisions addressable for existing citations while removing
        # them from subsequent retrieval. Retirement and replacement share one
        # transaction, including the upsert's savepoint when called by a job.
        session.execute(
            update(KnowledgeChunkTable)
            .where(
                KnowledgeChunkTable.source == manifest.source_uri,
                KnowledgeChunkTable.chunk_metadata["object_type"].astext == "manual",
                KnowledgeChunkTable.knowledge_chunk_id.not_in(
                    [chunk.knowledge_chunk_id for chunk in chunks]
                ),
            )
            .values(
                chunk_metadata=KnowledgeChunkTable.chunk_metadata.concat(
                    {"deprecated": True}
                )
            )
        )
        upsert_chunks(session, chunks, vectors)
    return chunks
