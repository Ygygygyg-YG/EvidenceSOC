"""Offline model provenance and embedding result validation."""

import hashlib
import json
import sys
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Self

import pytest
from evidencesoc.rag import embeddings


@pytest.fixture
def model_files(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    files = {
        name: {
            "size": len(name.encode()),
            "sha256": hashlib.sha256(name.encode()).hexdigest(),
        }
        for name in ("model_optimized.onnx", "tokenizer.json", "config.json")
    }
    monkeypatch.setattr(embeddings, "MODEL_FILES", files)
    for name in files:
        (tmp_path / name).write_bytes(name.encode())
    (tmp_path / "manifest.json").write_text(
        json.dumps(
            {
                "model_id": embeddings.MODEL_ID,
                "revision": embeddings.MODEL_REVISION,
                "dimension": 384,
                "files": files,
                "downloaded_at": "2026-09-26T00:00:00+00:00",
            }
        ),
        encoding="utf-8",
    )
    return tmp_path


def fake_model(
    monkeypatch: pytest.MonkeyPatch, vectors: list[Any]
) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []

    class FakeModel:
        def __init__(self, **kwargs: Any) -> None:
            calls.append(kwargs)

        def embed(self, documents: list[str], **kwargs: Any) -> list[Any]:
            return vectors

        def query_embed(self, query: str, **kwargs: Any) -> list[Any]:
            return vectors

    monkeypatch.setitem(
        sys.modules, "fastembed", SimpleNamespace(TextEmbedding=FakeModel)
    )
    return calls


def test_construction_and_empty_batch_never_load_or_download(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = fake_model(monkeypatch, [])
    provider = embeddings.LocalEmbeddingProvider(tmp_path / "absent")
    assert provider.model_id == embeddings.MODEL_ID
    assert embeddings.MODEL_REVISION in provider.model_id
    assert provider.embed_documents([]) == []
    assert calls == []
    assert not (tmp_path / "absent").exists()


def test_validated_local_model_is_reused_with_network_disabled(
    model_files: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = fake_model(monkeypatch, [[1.0] + [0.0] * 383])
    provider = embeddings.LocalEmbeddingProvider(model_files)
    assert provider.embed_documents(["DNS data exfiltration"])[0][0] == 1.0
    assert provider.embed_query("DNS 数据外泄")[0] == 1.0
    assert len(calls) == 1
    assert calls[0]["local_files_only"] is True
    assert calls[0]["specific_model_path"] == str(model_files)
    assert calls[0]["providers"] == ["CPUExecutionProvider"]
    assert calls[0]["threads"] == 2


def test_explicit_runtime_prepare_loads_once_without_embedding_a_query(
    model_files: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = fake_model(monkeypatch, [[1.0] + [0.0] * 383])
    queries = []
    original = sys.modules["fastembed"].TextEmbedding.query_embed

    def query(model: Any, text: str) -> Any:
        queries.append((model, text))
        return original(model, text)

    monkeypatch.setattr(sys.modules["fastembed"].TextEmbedding, "query_embed", query)
    provider = embeddings.LocalEmbeddingProvider(model_files)
    assert calls == []
    provider.prepare()
    provider.prepare()
    prepared = provider._model
    assert len(calls) == 1 and queries == []
    assert provider.embed_query("same actual query")[0] == 1.0
    assert len(calls) == 1 and queries == [(prepared, "same actual query")]


def test_runtime_prepare_rejects_missing_model_without_download(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = fake_model(monkeypatch, [])
    with pytest.raises(RuntimeError, match="unavailable or unverified"):
        embeddings.LocalEmbeddingProvider(tmp_path / "absent").prepare()
    assert calls == [] and not (tmp_path / "absent").exists()


@pytest.mark.parametrize("change", ["missing", "corrupt", "manifest", "revision"])
def test_unverified_model_is_rejected_before_loading(
    model_files: Path, monkeypatch: pytest.MonkeyPatch, change: str
) -> None:
    calls = fake_model(monkeypatch, [[1.0] * 384])
    if change == "missing":
        (model_files / "config.json").unlink()
    elif change == "corrupt":
        (model_files / "config.json").write_bytes(b"corrupted")
    elif change == "manifest":
        (model_files / "manifest.json").write_text("{}", encoding="utf-8")
    else:
        manifest = json.loads(
            (model_files / "manifest.json").read_text(encoding="utf-8")
        )
        manifest["revision"] = "master"
        (model_files / "manifest.json").write_text(
            json.dumps(manifest), encoding="utf-8"
        )
    with pytest.raises(RuntimeError, match="model"):
        embeddings.LocalEmbeddingProvider(model_files).embed_query("DNS")
    assert calls == []


@pytest.mark.parametrize(
    "vectors",
    [[], [[1.0] * 383], [[float("nan")] * 384], [[float("inf")] * 384], [[0.0] * 384]],
)
def test_invalid_embedding_output_is_not_returned(
    model_files: Path, monkeypatch: pytest.MonkeyPatch, vectors: list[Any]
) -> None:
    fake_model(monkeypatch, vectors)
    with pytest.raises(ValueError, match="embedding"):
        embeddings.LocalEmbeddingProvider(model_files).embed_query("DNS")


def test_batch_cardinality_is_verified(
    model_files: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_model(monkeypatch, [[1.0] * 384])
    with pytest.raises(ValueError, match="embedding"):
        embeddings.LocalEmbeddingProvider(model_files).embed_documents(["one", "two"])


@pytest.mark.parametrize("query", ["", "  "])
def test_blank_input_does_not_load_model(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, query: str
) -> None:
    calls = fake_model(monkeypatch, [])
    provider = embeddings.LocalEmbeddingProvider(tmp_path)
    with pytest.raises(ValueError):
        provider.embed_query(query)
    with pytest.raises(ValueError):
        provider.embed_documents([query])
    assert calls == []


def test_prepare_verified_model_is_idempotent_without_network(
    model_files: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def unexpected_network(*args: Any, **kwargs: Any) -> Any:
        pytest.fail("already verified artifacts must not access the network")

    monkeypatch.setattr(embeddings.httpx, "Client", unexpected_network)
    assert embeddings.prepare_embedding_model(model_files) == model_files


def test_prepare_downloads_only_pinned_files_and_writes_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload = b"model artifact"
    sha256 = hashlib.sha256(payload).hexdigest()
    monkeypatch.setattr(
        embeddings,
        "MODEL_FILES",
        {"model_optimized.onnx": {"size": len(payload), "sha256": sha256}},
    )
    urls: list[str] = []

    class Client:
        def __init__(self, **kwargs: Any) -> None:
            pass

        def __enter__(self) -> Self:
            return self

        def __exit__(self, *args: object) -> None:
            pass

        def stream(self, method: str, url: str) -> Any:
            urls.append(url)
            return nullcontext(
                httpx.Response(200, content=payload, request=httpx.Request(method, url))
            )

    import httpx

    monkeypatch.setattr(embeddings.httpx, "Client", Client)
    assert embeddings.prepare_embedding_model(tmp_path) == tmp_path
    assert urls == [f"{embeddings.MODEL_DOWNLOAD_BASE}/model_optimized.onnx"]
    assert embeddings.MODEL_REVISION in urls[0]
    manifest = json.loads((tmp_path / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["model_id"] == embeddings.MODEL_ID
    assert manifest["files"]["model_optimized.onnx"]["sha256"] == sha256
    assert (tmp_path / "model_optimized.onnx").read_bytes() == payload


def test_prepare_refuses_download_hash_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import httpx

    monkeypatch.setattr(
        embeddings,
        "MODEL_FILES",
        {
            "model_optimized.onnx": {
                "size": 3,
                "sha256": hashlib.sha256(b"yes").hexdigest(),
            }
        },
    )

    class Client:
        def __init__(self, **kwargs: Any) -> None:
            pass

        def __enter__(self) -> Self:
            return self

        def __exit__(self, *args: object) -> None:
            pass

        def stream(self, method: str, url: str) -> Any:
            return nullcontext(
                httpx.Response(200, content=b"bad", request=httpx.Request(method, url))
            )

    monkeypatch.setattr(embeddings.httpx, "Client", Client)
    with pytest.raises(ValueError, match="SHA-256"):
        embeddings.prepare_embedding_model(tmp_path)
    assert not (tmp_path / "model_optimized.onnx").exists()
    assert not (tmp_path / "manifest.json").exists()


@pytest.mark.parametrize(
    ("vectors", "expected_count", "dimensions"),
    [([[1.0]], -1, 1), ([[1.0]], 1, 0), ([[None]], 1, 1), ([["invalid"]], 1, 1)],
)
def test_public_vector_validator_rejects_invalid_profile_or_values(
    vectors: Any, expected_count: int, dimensions: int
) -> None:
    with pytest.raises(ValueError, match="embedding"):
        embeddings.validate_vectors(
            vectors, expected_count=expected_count, dimensions=dimensions
        )


def test_public_vector_validator_accepts_requested_dimension() -> None:
    assert embeddings.validate_vectors([[1, 2]], expected_count=1, dimensions=2) == [
        [1.0, 2.0]
    ]
