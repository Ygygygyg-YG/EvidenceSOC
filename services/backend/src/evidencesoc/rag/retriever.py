from __future__ import annotations

import re
from collections.abc import Sequence
from functools import lru_cache
from pathlib import Path
from typing import Any, Protocol

from sqlalchemy import func, literal, literal_column, or_, select
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Session

from evidencesoc.execution import check_execution
from evidencesoc.persistence.tables import KnowledgeChunkTable
from evidencesoc.rag.ingest_attack import PINNED_STIX_SHA256
from evidencesoc.tools.attack_work import (
    TECHNIQUE_ID_PATTERN,
    _set_statement_timeout,
)
from evidencesoc.tools.errors import ToolDependencyError

KnowledgeResult = dict[str, str]


class QueryEmbedder(Protocol):
    model_id: str

    def embed_query(self, query: str) -> list[float]: ...


class RetrievalRepository(Protocol):
    def exact(self, technique_id: str, limit: int) -> list[KnowledgeResult]: ...

    def keyword(self, query: str, limit: int) -> list[KnowledgeResult]: ...

    def semantic(self, vector: list[float], limit: int) -> list[KnowledgeResult]: ...


def reciprocal_rank_fusion(
    rankings: Sequence[Sequence[KnowledgeResult]],
    *,
    top_k: int = 8,
    rank_constant: int = 60,
) -> list[KnowledgeResult]:
    if type(top_k) is not int or not 1 <= top_k <= 50:
        raise ValueError("top_k must be an integer between 1 and 50")
    if type(rank_constant) is not int or rank_constant < 1:
        raise ValueError("rank_constant must be positive")
    scores: dict[str, float] = {}
    items: dict[str, KnowledgeResult] = {}
    for ranking in rankings:
        seen: set[str] = set()
        rank = 0
        for item in ranking:
            chunk_id = item["knowledge_chunk_id"]
            if chunk_id in seen:
                continue
            seen.add(chunk_id)
            rank += 1
            scores[chunk_id] = scores.get(chunk_id, 0.0) + 1 / (rank_constant + rank)
            items.setdefault(chunk_id, item)
    ordered = sorted(scores, key=lambda chunk_id: (-scores[chunk_id], chunk_id))
    return [dict(items[chunk_id]) for chunk_id in ordered[:top_k]]


class HybridRetriever:
    def __init__(
        self, repository: RetrievalRepository, embedder: QueryEmbedder
    ) -> None:
        self._repository = repository
        self._embedder = embedder

    def retrieve_knowledge(self, query: str, top_k: int = 8) -> list[KnowledgeResult]:
        if type(top_k) is not int or not 1 <= top_k <= 50:
            raise ValueError("top_k must be an integer between 1 and 50")
        if not isinstance(query, str) or len(query) > 4096:
            raise ValueError("query must be a string of at most 4096 characters")
        query = query.strip()
        if "\x00" in query or not any(character.isalnum() for character in query):
            return []
        check_execution()
        if TECHNIQUE_ID_PATTERN.fullmatch(query):
            return self._repository.exact(query.upper(), top_k)
        candidates = min(100, max(32, top_k * 4))
        keywords = self._repository.keyword(query, candidates)
        check_execution()
        vector = self._embedder.embed_query(query)
        check_execution()
        semantic = self._repository.semantic(vector, candidates)
        return reciprocal_rank_fusion([keywords, semantic], top_k=top_k)


class PostgresKnowledgeRepository:
    def __init__(
        self,
        session: Session,
        *,
        embedding_model: str,
        attack_only: bool = False,
        version: str = "19.2",
    ) -> None:
        self._session = session
        self._model = embedding_model
        self._attack_only = attack_only
        self._version = version

    @staticmethod
    def _metadata(key: str) -> Any:
        return KnowledgeChunkTable.chunk_metadata[key].as_string()

    def _eligible(self) -> Any:
        metadata = KnowledgeChunkTable.chunk_metadata
        technique_id = self._metadata("technique_id")
        attack = (
            (self._metadata("object_type") == "attack-pattern")
            & (self._metadata("version") == self._version)
            & (self._metadata("source_type") == "mitre_attack")
            & (self._metadata("stix_hash") == PINNED_STIX_SHA256)
            & technique_id.regexp_match(r"^T[0-9]{4}(\.[0-9]{3})?$")
            & (
                KnowledgeChunkTable.source
                == (
                    "https://attack.mitre.org/techniques/"
                    + func.replace(technique_id, ".", "/")
                    + "/"
                )
            )
        )
        active = (
            (self._metadata("embedding_model") == self._model)
            & (metadata["revoked"] == literal(False, type_=JSONB))
            & (metadata["deprecated"] == literal(False, type_=JSONB))
        )
        if self._attack_only:
            return attack & active
        manual = (
            (self._metadata("object_type") == "manual")
            & (self._metadata("source_type") == "internal_manual")
            & (metadata["trusted"] == literal(True, type_=JSONB))
            & KnowledgeChunkTable.source.like("internal://knowledge/%")
        )
        return or_(attack, manual) & active

    def _rows(
        self, filters: list[Any], order: list[Any], limit: int
    ) -> list[KnowledgeResult]:
        remaining = check_execution()
        if remaining is not None:
            _set_statement_timeout(self._session, remaining)
        rows = (
            self._session.execute(
                select(KnowledgeChunkTable)
                .where(self._eligible(), *filters)
                .order_by(*order, KnowledgeChunkTable.knowledge_chunk_id)
                .limit(limit)
            )
            .scalars()
            .all()
        )
        results: list[KnowledgeResult] = []
        for row in rows:
            metadata = row.chunk_metadata
            required = (metadata.get("title"), metadata.get("version"))
            if any(
                not isinstance(value, str) or not value.strip() for value in required
            ):
                raise ToolDependencyError("knowledge metadata is invalid")
            results.append(
                {
                    "knowledge_chunk_id": row.knowledge_chunk_id,
                    "technique_id": metadata.get("technique_id") or "",
                    "title": metadata["title"],
                    "summary": row.content,
                    "source_uri": row.source,
                    "version": metadata["version"],
                }
            )
        return results

    def exact(self, technique_id: str, limit: int) -> list[KnowledgeResult]:
        return self._rows(
            [
                self._metadata("object_type") == "attack-pattern",
                self._metadata("technique_id") == technique_id,
            ],
            [],
            limit,
        )

    def keyword(self, query: str, limit: int) -> list[KnowledgeResult]:
        # Domain terms let the lexical channel retain the intent of mixed
        # Chinese/English SOC queries as well as entities such as DNS or SSH.
        translations = {
            "数据外泄": "data exfiltration",
            "数据外传": "data exfiltration",
            "数据泄露": "data exfiltration",
            "命令执行": "command execution",
            "凭据窃取": "credential theft",
            "密码猜测": "password guessing",
            "横向移动": "lateral movement",
            "持久化": "persistence",
            "清除日志": "clear logs",
            "勒索软件": "ransomware",
            "钓鱼邮件": "phishing email",
            "注入": "injection",
        }
        for term, translation in translations.items():
            query = query.replace(term, translation)
        tokens = re.findall(r"[A-Za-z0-9][A-Za-z0-9.-]*", query)[:32]
        if not tokens:
            return []
        title = self._metadata("title")
        document = func.setweight(
            func.to_tsvector("english", title), literal_column("'A'")
        ).op("||")(
            func.setweight(
                func.to_tsvector("english", KnowledgeChunkTable.content),
                literal_column("'B'"),
            )
        )
        search = func.websearch_to_tsquery("english", " OR ".join(tokens))
        complete = func.plainto_tsquery("english", " ".join(tokens))
        return self._rows(
            [document.op("@@")(search)],
            [
                document.op("@@")(complete).desc(),
                func.ts_rank_cd(document, search, 32).desc(),
            ],
            limit,
        )

    def semantic(self, vector: list[float], limit: int) -> list[KnowledgeResult]:
        from evidencesoc.rag.embeddings import validate_vectors

        validate_vectors([vector], expected_count=1, dimensions=len(vector))
        embedding = KnowledgeChunkTable.embedding
        return self._rows(
            [
                embedding.is_not(None),
                self._metadata("embedding_model") == self._model,
                func.vector_dims(embedding) == len(vector),
            ],
            [embedding.cosine_distance(vector)],
            limit,
        )


class HybridAttackKnowledgeRepository:
    """Preserve the audited MCP work contract while using hybrid retrieval."""

    def __init__(self, session: Session, embedder: QueryEmbedder) -> None:
        self._session = session
        self._retriever = HybridRetriever(
            PostgresKnowledgeRepository(
                session,
                embedding_model=embedder.model_id,
                attack_only=True,
            ),
            embedder,
        )

    def lookup(
        self,
        *,
        query: str,
        limit: int,
        timeout_seconds: float | None = None,
    ) -> list[KnowledgeResult]:
        if timeout_seconds is not None:
            _set_statement_timeout(self._session, timeout_seconds)
        return self._retriever.retrieve_knowledge(query, limit)


@lru_cache(maxsize=4)
def _embedding_provider(model_path: Path) -> QueryEmbedder:
    from evidencesoc.rag.embeddings import LocalEmbeddingProvider

    return LocalEmbeddingProvider(model_path=model_path)


def retrieve_knowledge(query: str, top_k: int = 8) -> list[KnowledgeResult]:
    """Retrieve pinned local knowledge. Runtime never downloads data or models."""
    from evidencesoc.config import Settings
    from evidencesoc.persistence.database import (
        create_database_engine,
        create_session_factory,
    )

    settings = Settings()
    embedder = _embedding_provider(settings.rag_data_directory / "model")
    engine = create_database_engine(
        settings.database_url, bounded_tool_connections=True
    )
    try:
        with create_session_factory(engine)() as session:
            return HybridRetriever(
                PostgresKnowledgeRepository(
                    session,
                    embedding_model=embedder.model_id,
                ),
                embedder,
            ).retrieve_knowledge(query, top_k)
    finally:
        engine.dispose()
