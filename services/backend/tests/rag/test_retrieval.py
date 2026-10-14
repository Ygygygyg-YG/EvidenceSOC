from __future__ import annotations

from pathlib import Path

import pytest
from evidencesoc.rag.retriever import HybridRetriever, reciprocal_rank_fusion


def result(chunk: str, technique: str = "T1048.003") -> dict[str, str]:
    return {
        "knowledge_chunk_id": chunk,
        "technique_id": technique,
        "title": "Exfiltration Over Unencrypted Non-C2 Protocol",
        "summary": "Adversaries may exfiltrate data using DNS.",
        "source_uri": "https://attack.mitre.org/techniques/T1048/003/",
        "version": "19.2",
    }


class Repository:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def exact(self, technique_id: str, limit: int) -> list[dict[str, str]]:
        self.calls.append("exact")
        return [result("KC-DNS")] if technique_id == "T1048.003" else []

    def keyword(self, query: str, limit: int) -> list[dict[str, str]]:
        self.calls.append("keyword")
        return [result("KC-DNS"), result("KC-C2", "T1071.004")]

    def semantic(self, vector: list[float], limit: int) -> list[dict[str, str]]:
        self.calls.append("semantic")
        return [result("KC-OTHER"), result("KC-DNS")]


class Embedder:
    model_id = "test-embedding-v1"

    def __init__(self) -> None:
        self.calls: list[str] = []

    def embed_query(self, query: str) -> list[float]:
        self.calls.append(query)
        return [0.1, 0.2, 0.3]


def test_rrf_merges_ranks_deduplicates_and_breaks_ties_deterministically() -> None:
    lexical = [result("KC-B"), result("KC-A"), result("KC-B")]
    semantic = [result("KC-C"), result("KC-A")]
    assert [
        r["knowledge_chunk_id"]
        for r in reciprocal_rank_fusion([lexical, semantic], top_k=8)
    ] == ["KC-A", "KC-B", "KC-C"]


def test_dns_exfiltration_uses_both_retrieval_channels() -> None:
    repository, embedder = Repository(), Embedder()
    retrieved = HybridRetriever(repository, embedder).retrieve_knowledge("DNS 数据外泄")
    assert retrieved[0]["knowledge_chunk_id"] == "KC-DNS"
    assert repository.calls == ["keyword", "semantic"]
    assert embedder.calls == ["DNS 数据外泄"]
    assert len(retrieved) == 3


def test_nonexistent_technique_is_not_replaced_with_semantically_similar_results() -> (
    None
):
    repository, embedder = Repository(), Embedder()
    assert HybridRetriever(repository, embedder).retrieve_knowledge("t9999") == []
    assert repository.calls == ["exact"]
    assert embedder.calls == []


def test_existing_technique_lookup_does_not_need_an_embedding_model() -> None:
    assert HybridRetriever(Repository(), Embedder()).retrieve_knowledge(
        "t1048.003"
    ) == [result("KC-DNS")]


@pytest.mark.parametrize("query", ["", " ", "%", "_", "\x00", "hello\x00world"])
def test_empty_or_nonsearchable_queries_never_touch_dependencies(query: str) -> None:
    repository, embedder = Repository(), Embedder()
    assert HybridRetriever(repository, embedder).retrieve_knowledge(query) == []
    assert repository.calls == []
    assert embedder.calls == []


@pytest.mark.parametrize("limit", [0, -1, 51, True, 1.5])
def test_invalid_result_limits_are_rejected_before_dependencies(limit: int) -> None:
    repository, embedder = Repository(), Embedder()
    with pytest.raises(ValueError, match="top_k"):
        HybridRetriever(repository, embedder).retrieve_knowledge("dns", limit)
    assert repository.calls == []
    assert embedder.calls == []


def test_default_top_eight_and_requested_limit_are_enforced() -> None:
    class ManyRepository(Repository):
        def keyword(self, query: str, limit: int) -> list[dict[str, str]]:
            return [result(f"KC-{i:02}") for i in range(40)]

        def semantic(self, vector: list[float], limit: int) -> list[dict[str, str]]:
            return []

    retriever = HybridRetriever(ManyRepository(), Embedder())
    assert len(retriever.retrieve_knowledge("dns")) == 8
    assert len(retriever.retrieve_knowledge("dns", 2)) == 2


def test_dependency_error_does_not_fabricate_a_successful_empty_result() -> None:
    class Unavailable(Repository):
        def semantic(self, vector: list[float], limit: int) -> list[dict[str, str]]:
            raise ConnectionError("unavailable")

    with pytest.raises(ConnectionError):
        HybridRetriever(Unavailable(), Embedder()).retrieve_knowledge("dns")


def test_public_retrieval_reuses_a_lazy_model_for_the_same_directory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from evidencesoc.rag import embeddings, retriever

    created: list[Path] = []

    def provider(model_path: Path) -> Embedder:
        created.append(model_path)
        return Embedder()

    monkeypatch.setattr(embeddings, "LocalEmbeddingProvider", provider)
    retriever._embedding_provider.cache_clear()
    try:
        directory = Path("test-model")
        assert retriever._embedding_provider(
            directory
        ) is retriever._embedding_provider(directory)
        assert created == [directory]
    finally:
        retriever._embedding_provider.cache_clear()
