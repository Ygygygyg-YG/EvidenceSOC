from __future__ import annotations

import os

import pytest
from evidencesoc.config import Settings
from evidencesoc.evidence.citations import validate_citations
from evidencesoc.persistence.database import (
    create_database_engine,
    create_session_factory,
)
from evidencesoc.persistence.tables import KnowledgeChunkTable
from evidencesoc.rag.embeddings import MODEL_ID, LocalEmbeddingProvider
from evidencesoc.rag.ingest_attack import PINNED_STIX_SHA256
from evidencesoc.rag.retriever import HybridRetriever, PostgresKnowledgeRepository
from evidencesoc.tools.attack import validate_attack_results
from evidencesoc.tools.attack_work import build_attack_lookup_work
from sqlalchemy import func, select

# Fixed before executing the full corpus acceptance run. This is a developer
# retrieval benchmark, never ingested into the knowledge corpus.
RECALL_AT_8_BASELINE = 0.80
QUERIES = (
    ("DNS 数据外泄", {"T1048.003"}),
    ("SQL injection against a public facing application", {"T1190"}),
    ("spearphishing email with a malicious attachment", {"T1566.001"}),
    ("password guessing brute force authentication", {"T1110.001"}),
    ("dump credentials from LSASS memory", {"T1003.001"}),
    ("execute commands using PowerShell", {"T1059.001"}),
    ("persistence using a Windows scheduled task", {"T1053.005"}),
    ("clear Windows event logs", {"T1685.001"}),
    ("encrypt files for ransomware impact", {"T1486"}),
    ("lateral movement using Remote Desktop Protocol", {"T1021.001"}),
    ("lateral movement using SSH", {"T1021.004"}),
    ("use stolen valid accounts to access systems", {"T1078"}),
)


@pytest.mark.skipif(
    os.getenv("RUN_RAG_ACCEPTANCE") != "1",
    reason="explicit full pinned corpus/model acceptance",
)
def test_pinned_official_corpus_recall_at_eight_and_citation_validation() -> None:
    engine = create_database_engine(Settings().database_url)
    embedder = LocalEmbeddingProvider(
        model_path=Settings().rag_data_directory / "model"
    )
    try:
        with create_session_factory(engine)() as session:
            count = session.scalar(
                select(func.count())
                .select_from(KnowledgeChunkTable)
                .where(
                    KnowledgeChunkTable.chunk_metadata["stix_hash"].as_string()
                    == PINNED_STIX_SHA256,
                    KnowledgeChunkTable.chunk_metadata["embedding_model"].as_string()
                    == MODEL_ID,
                    KnowledgeChunkTable.embedding.is_not(None),
                )
            )
            assert count is not None and count > 500, (
                "prepare the full pinned official corpus first"
            )
            retriever = HybridRetriever(
                PostgresKnowledgeRepository(session, embedding_model=MODEL_ID), embedder
            )
            for _, relevant in QUERIES:
                for technique in relevant:
                    assert retriever.retrieve_knowledge(technique), (
                        f"benchmark uses a revoked or missing technique: {technique}"
                    )
            recalls = []
            for query, relevant in QUERIES:
                hits = retriever.retrieve_knowledge(query)
                returned = {hit["technique_id"] for hit in hits}
                recall = len(relevant & returned) / len(relevant)
                recalls.append(recall)
                print(f"{query}: Recall@8={recall:.2f}, techniques={sorted(returned)}")
                assert len(hits) <= 8
            recall_at_eight = sum(recalls) / len(recalls)
            print(
                f"Full ATT&CK v19.2 chunks={count}, Recall@8={recall_at_eight:.3f}, baseline={RECALL_AT_8_BASELINE}"
            )
            assert recall_at_eight >= RECALL_AT_8_BASELINE
            assert retriever.retrieve_knowledge("T9999") == []
            dns = retriever.retrieve_knowledge("DNS 数据外泄")
            assert "T1048.003" in {hit["technique_id"] for hit in dns}
            checked = validate_citations(
                [
                    {
                        "claim_id": "dns",
                        "text": "DNS can carry exfiltrated data.",
                        "knowledge_chunk_ids": [dns[0]["knowledge_chunk_id"]],
                    },
                    {
                        "claim_id": "unsupported",
                        "text": "An invalid source.",
                        "knowledge_chunk_ids": ["KC-does-not-exist"],
                    },
                ],
                [],
                [hit["knowledge_chunk_id"] for hit in dns],
            )
            assert [claim.status for claim in checked] == ["supported", "unsupported"]
    finally:
        engine.dispose()


@pytest.mark.skipif(
    os.getenv("RUN_RAG_ACCEPTANCE") != "1",
    reason="explicit full pinned corpus/model acceptance",
)
def test_real_mcp_lookup_adapter_keeps_attack_only_bounded_result_contract() -> None:
    settings = Settings()
    engine = create_database_engine(
        settings.database_url, bounded_tool_connections=True
    )
    try:
        work = build_attack_lookup_work(
            session_factory=create_session_factory(engine),
            model_path=settings.rag_data_directory / "model",
        )
        hits = work(query="DNS 数据外泄", limit=10)
        assert validate_attack_results(hits, limit=10) <= 10
        assert "T1048.003" in {hit["technique_id"] for hit in hits}
        assert all(
            hit["source_uri"].startswith("https://attack.mitre.org/techniques/")
            for hit in hits
        )
        assert work(query="T9999", limit=10) == []
    finally:
        engine.dispose()


@pytest.mark.skipif(
    os.getenv("RUN_RAG_ACCEPTANCE") != "1",
    reason="explicit full pinned corpus/model acceptance",
)
def test_public_retrieval_loads_its_local_model_only_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from evidencesoc.rag import embeddings, retriever

    provider = embeddings.LocalEmbeddingProvider
    constructed: list[object] = []

    def create_provider(model_path: object) -> embeddings.LocalEmbeddingProvider:
        instance = provider(model_path=model_path)  # type: ignore[arg-type]
        constructed.append(instance)
        return instance

    monkeypatch.setattr(embeddings, "LocalEmbeddingProvider", create_provider)
    retriever._embedding_provider.cache_clear()
    try:
        first = retriever.retrieve_knowledge("DNS 数据外泄")
        second = retriever.retrieve_knowledge("DNS 数据外泄")
        assert first == second
        assert "T1048.003" in {hit["technique_id"] for hit in first}
        assert len(constructed) == 1
    finally:
        retriever._embedding_provider.cache_clear()
