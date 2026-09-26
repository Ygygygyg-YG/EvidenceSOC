"""Explicit operator preparation: python -m evidencesoc.rag.cli prepare."""

from __future__ import annotations

import argparse
import hashlib
from datetime import UTC, datetime
from pathlib import Path

import httpx

from evidencesoc.config import REPOSITORY_ROOT, Settings
from evidencesoc.persistence.database import (
    create_database_engine,
    create_session_factory,
)
from evidencesoc.rag.embeddings import LocalEmbeddingProvider, prepare_embedding_model
from evidencesoc.rag.ingest_attack import (
    PINNED_ATTACK_VERSION,
    PINNED_STIX_SHA256,
    PINNED_STIX_URL,
    ingest_attack,
    ingest_manual,
    parse_attack,
)
from evidencesoc.rag.models import SourceManifest

DEFAULT_DATA_DIRECTORY = REPOSITORY_ROOT / "data" / "knowledge"


def prepare_attack_source(
    directory: Path = DEFAULT_DATA_DIRECTORY,
    *,
    client: httpx.Client | None = None,
) -> tuple[Path, SourceManifest]:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "enterprise-attack-19.2.json"
    manifest_path = directory / "enterprise-attack-19.2.manifest.json"
    if path.exists():
        if hashlib.sha256(path.read_bytes()).hexdigest() != PINNED_STIX_SHA256:
            raise ValueError("existing ATT&CK source hash mismatch")
        if manifest_path.exists():
            manifest = SourceManifest.model_validate_json(
                manifest_path.read_text(encoding="utf-8")
            )
            if (
                manifest.version != PINNED_ATTACK_VERSION
                or manifest.sha256 != PINNED_STIX_SHA256
                or manifest.source_uri != PINNED_STIX_URL
            ):
                raise ValueError("existing ATT&CK source manifest mismatch")
            return path, manifest
        raise ValueError("existing ATT&CK source has no download manifest")
    if client is None:
        with httpx.Client(timeout=120, follow_redirects=False) as download_client:
            return prepare_attack_source(directory, client=download_client)
    temporary = directory / "enterprise-attack-19.2.download"
    try:
        digest = hashlib.sha256()
        size = 0
        with client.stream("GET", PINNED_STIX_URL) as response:
            response.raise_for_status()
            with temporary.open("wb") as destination:
                for chunk in response.iter_bytes():
                    size += len(chunk)
                    if size > 64 * 1024 * 1024:
                        raise ValueError("ATT&CK source exceeds size limit")
                    digest.update(chunk)
                    destination.write(chunk)
        if digest.hexdigest() != PINNED_STIX_SHA256:
            raise ValueError("downloaded ATT&CK source hash mismatch")
        manifest = SourceManifest(
            version=PINNED_ATTACK_VERSION,
            sha256=digest.hexdigest(),
            downloaded_at=datetime.now(UTC),
            source_uri=PINNED_STIX_URL,
        )
        temporary.replace(path)
        manifest_path.write_text(
            manifest.model_dump_json(indent=2) + "\n", encoding="utf-8"
        )
        return path, manifest
    finally:
        temporary.unlink(missing_ok=True)


def prepare_knowledge(directory: Path | None = None) -> int:
    directory = directory if directory is not None else Settings().rag_data_directory
    path, manifest = prepare_attack_source(directory)
    print(f"ATT&CK {manifest.version}: SHA-256 verified", flush=True)
    provider = LocalEmbeddingProvider(model_path=directory / "model")
    raw = path.read_bytes()
    chunks = parse_attack(raw, manifest=manifest, embedding_model=provider.model_id)
    print(
        f"Validated {len(chunks)} ATT&CK chunks; preparing pinned local model",
        flush=True,
    )
    prepare_embedding_model(directory / "model")
    engine = create_database_engine(Settings().database_url)
    try:
        with create_session_factory(engine)() as session:
            print("Embedding and storing ATT&CK chunks", flush=True)
            stored = ingest_attack(
                raw, manifest=manifest, embedder=provider, session=session
            )
            manual_path = REPOSITORY_ROOT / "data" / "samples" / "response-manual.txt"
            manual = manual_path.read_bytes()
            ingest_manual(
                manual,
                manifest=SourceManifest(
                    version="1.0",
                    sha256=hashlib.sha256(manual).hexdigest(),
                    downloaded_at=datetime.now(UTC),
                    source_uri="internal://knowledge/simulated-response",
                ),
                title="Internal simulated response playbook",
                trusted=True,
                embedder=provider,
                session=session,
            )
            print(
                f"Stored {len(stored)} ATT&CK chunks and the internal response playbook",
                flush=True,
            )
            return len(stored)
    finally:
        engine.dispose()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Prepare verified local ATT&CK knowledge and embeddings"
    )
    parser.add_argument("command", choices=["prepare"])
    parser.add_argument(
        "--data-directory",
        type=Path,
        default=None,
        help="Must match RAG_DATA_DIRECTORY; use that setting for setup and runtime",
    )
    args = parser.parse_args()
    if (
        args.data_directory is not None
        and args.data_directory.resolve() != Settings().rag_data_directory.resolve()
    ):
        parser.error(
            "--data-directory must match RAG_DATA_DIRECTORY; set it for setup and runtime"
        )
    prepare_knowledge(args.data_directory)


if __name__ == "__main__":
    main()
