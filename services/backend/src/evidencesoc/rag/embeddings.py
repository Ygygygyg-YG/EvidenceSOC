"""Pinned multilingual CPU embeddings with strictly offline runtime loading."""

from __future__ import annotations

import hashlib
import json
import math
import tempfile
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from threading import Lock
from typing import Any, TypedDict

import httpx

MODEL_NAME = "sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2"
MODEL_REVISION = "faf4aa4225822f3bc6376869cb1164e8e3feedd0"
MODEL_ID = f"{MODEL_NAME}@{MODEL_REVISION}"
MODEL_DIMENSIONS = 384
MODEL_DOWNLOAD_BASE = (
    "https://huggingface.co/Qdrant/paraphrase-multilingual-MiniLM-L12-v2-onnx-Q/resolve/"
    f"{MODEL_REVISION}"
)
DEFAULT_MODEL_PATH = (
    Path(__file__).resolve().parents[5] / "data" / "knowledge" / "model"
)


class ModelFile(TypedDict):
    size: int
    sha256: str


MODEL_FILES: dict[str, ModelFile] = {
    "model_optimized.onnx": {
        "size": 235052644,
        "sha256": "634d0f66c29dc934c8fa72b8a4fe91dd4d420a22f1d82a241058d4316e659a99",
    },
    "tokenizer.json": {
        "size": 17083009,
        "sha256": "fa685fc160bbdbab64058d4fc91b60e62d207e8dc60b9af5c002c5ab946ded00",
    },
    "config.json": {
        "size": 673,
        "sha256": "c8ec081fdad2df991bf5abbf18418fec7a5cdaa421f60ffb060a30040b8c376f",
    },
    "special_tokens_map.json": {
        "size": 964,
        "sha256": "8c785abebea9ae3257b61681b4e6fd8365ceafde980c21970d001e834cf10835",
    },
    "tokenizer_config.json": {
        "size": 1416,
        "sha256": "0666eebf692422757e1dddf3c9fb1ded73ba3dc726c5828671fc89e45bf3609f",
    },
}


def _file_matches(path: Path, expected: ModelFile) -> bool:
    if not path.is_file() or path.stat().st_size != expected["size"]:
        return False
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest() == expected["sha256"]


def _verify_model(path: Path) -> None:
    try:
        manifest = json.loads((path / "manifest.json").read_text(encoding="utf-8"))
        if (
            not isinstance(manifest, dict)
            or manifest.get("model_id") != MODEL_ID
            or manifest.get("revision") != MODEL_REVISION
            or manifest.get("dimension") != MODEL_DIMENSIONS
            or manifest.get("files") != MODEL_FILES
            or not isinstance(manifest.get("downloaded_at"), str)
        ):
            raise ValueError("model manifest does not match the pinned profile")
        for filename, expected in MODEL_FILES.items():
            if not _file_matches(path / filename, expected):
                raise ValueError(f"model artifact verification failed: {filename}")
    except (OSError, ValueError, TypeError) as exc:
        raise RuntimeError(
            "Pinned local embedding model is unavailable or unverified; "
            "run the knowledge preparation command before retrieval"
        ) from exc


def prepare_embedding_model(model_path: Path = DEFAULT_MODEL_PATH) -> Path:
    """Explicit setup only: obtain and verify immutable public model artifacts."""
    model_path = Path(model_path)
    try:
        _verify_model(model_path)
    except RuntimeError:
        pass
    else:
        return model_path

    model_path.mkdir(parents=True, exist_ok=True)
    with httpx.Client(
        follow_redirects=True, timeout=httpx.Timeout(180.0, connect=20.0)
    ) as client:
        for filename, expected in MODEL_FILES.items():
            destination = model_path / filename
            if _file_matches(destination, expected):
                continue
            temporary: Path | None = None
            try:
                with tempfile.NamedTemporaryFile(
                    dir=model_path, suffix=".download", delete=False
                ) as out:
                    temporary = Path(out.name)
                    with client.stream(
                        "GET", f"{MODEL_DOWNLOAD_BASE}/{filename}"
                    ) as response:
                        response.raise_for_status()
                        count = 0
                        for block in response.iter_bytes(chunk_size=1024 * 1024):
                            count += len(block)
                            if count > expected["size"]:
                                raise ValueError(
                                    f"model artifact size exceeds pinned value: {filename}"
                                )
                            out.write(block)
                if not _file_matches(temporary, expected):
                    raise ValueError(
                        f"model artifact SHA-256 or size mismatch: {filename}"
                    )
                temporary.replace(destination)
            finally:
                if temporary is not None:
                    temporary.unlink(missing_ok=True)

    manifest = {
        "model_id": MODEL_ID,
        "revision": MODEL_REVISION,
        "dimension": MODEL_DIMENSIONS,
        "files": MODEL_FILES,
        "downloaded_at": datetime.now(UTC).isoformat(),
    }
    with tempfile.NamedTemporaryFile(
        dir=model_path, suffix=".manifest", delete=False, mode="w", encoding="utf-8"
    ) as out:
        json.dump(manifest, out, ensure_ascii=False, indent=2)
        temporary_manifest = Path(out.name)
    try:
        temporary_manifest.replace(model_path / "manifest.json")
    finally:
        temporary_manifest.unlink(missing_ok=True)
    _verify_model(model_path)
    return model_path


def validate_vectors(
    vectors: Iterable[Iterable[float]],
    *,
    expected_count: int,
    dimensions: int = MODEL_DIMENSIONS,
) -> list[list[float]]:
    """Reject malformed and zero vectors before cosine similarity reaches PostgreSQL."""
    if expected_count < 0 or dimensions < 1:
        raise ValueError("invalid expected embedding count or dimensions")
    try:
        result = [[float(value) for value in vector] for vector in vectors]
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError("embedding contains invalid numeric values") from exc
    if len(result) != expected_count:
        raise ValueError("embedding count does not match the requested texts")
    for vector in result:
        if len(vector) != dimensions:
            raise ValueError("embedding dimensions do not match the model profile")
        if not all(math.isfinite(value) for value in vector):
            raise ValueError("embedding must contain only finite numbers")
        if not any(value != 0.0 for value in vector):
            raise ValueError("zero embedding cannot be used with cosine similarity")
    return result


class LocalEmbeddingProvider:
    """Load the verified local ONNX model once; runtime never downloads assets."""

    model_id = MODEL_ID
    dimensions = MODEL_DIMENSIONS

    def __init__(self, model_path: Path = DEFAULT_MODEL_PATH) -> None:
        self.model_path = Path(model_path)
        self._model: Any = None
        self._load_lock = Lock()

    def _load_model(self) -> Any:
        if self._model is None:
            with self._load_lock:
                if self._model is None:
                    _verify_model(self.model_path)
                    from fastembed import TextEmbedding

                    self._model = TextEmbedding(
                        model_name=MODEL_NAME,
                        specific_model_path=str(self.model_path),
                        local_files_only=True,
                        providers=["CPUExecutionProvider"],
                        threads=2,
                    )
        return self._model

    def embed_documents(self, documents: list[str]) -> list[list[float]]:
        if not documents:
            return []
        if any(not isinstance(text, str) or not text.strip() for text in documents):
            raise ValueError("embedding documents must be nonblank strings")
        vectors = self._load_model().embed(documents, batch_size=16, parallel=None)
        return validate_vectors(vectors, expected_count=len(documents))

    def embed_query(self, query: str) -> list[float]:
        if not isinstance(query, str) or not query.strip():
            raise ValueError("embedding query must be a nonblank string")
        vectors = self._load_model().query_embed(query)
        return validate_vectors(vectors, expected_count=1)[0]
