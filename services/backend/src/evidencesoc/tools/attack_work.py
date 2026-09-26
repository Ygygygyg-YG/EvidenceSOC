from __future__ import annotations

import re
from collections.abc import Callable
from pathlib import Path
from time import monotonic
from typing import Any, Protocol

from sqlalchemy import case, func, or_, select, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session, sessionmaker

from evidencesoc.execution import check_execution
from evidencesoc.persistence.tables import KnowledgeChunkTable
from evidencesoc.tools.errors import ToolDependencyError, ToolDependencyTimeout

TECHNIQUE_ID_PATTERN = re.compile(r"T\d{4}(?:\.\d{3})?", re.IGNORECASE)


def _escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _set_statement_timeout(session: Session, timeout_seconds: float) -> None:
    bind = session.get_bind()
    if bind.dialect.name != "postgresql":
        return
    milliseconds = max(1, int(timeout_seconds * 1000))
    session.execute(
        text("SELECT set_config('statement_timeout', :timeout, true)"),
        {"timeout": f"{milliseconds}ms"},
    )


def _metadata_text(key: str) -> Any:
    return KnowledgeChunkTable.chunk_metadata[key].as_string()


class AttackKnowledgeRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def lookup(
        self,
        *,
        query: str,
        limit: int,
        timeout_seconds: float | None = None,
    ) -> list[dict[str, str]]:
        if timeout_seconds is not None:
            _set_statement_timeout(self._session, timeout_seconds)

        object_type = _metadata_text("object_type")
        technique_id = _metadata_text("technique_id")
        title = _metadata_text("title")
        revoked = KnowledgeChunkTable.chunk_metadata["revoked"].as_boolean()
        deprecated = KnowledgeChunkTable.chunk_metadata["deprecated"].as_boolean()
        eligible = [
            object_type == "attack-pattern",
            technique_id.regexp_match(r"^T[0-9]{4}(\.[0-9]{3})?$"),
            KnowledgeChunkTable.source
            == (
                "https://attack.mitre.org/techniques/"
                + func.replace(technique_id, ".", "/")
                + "/"
            ),
            or_(revoked.is_(None), revoked.is_(False)),
            or_(deprecated.is_(None), deprecated.is_(False)),
        ]

        cleaned_query = query.strip()
        if "\x00" in cleaned_query:
            return []
        exact_id = TECHNIQUE_ID_PATTERN.fullmatch(cleaned_query)
        order_by: list[Any]
        if exact_id is not None:
            filters = [
                *eligible,
                func.lower(technique_id) == cleaned_query.casefold(),
            ]
            order_by = [KnowledgeChunkTable.knowledge_chunk_id]
        else:
            pattern = f"%{_escape_like(cleaned_query)}%"
            title_match = title.ilike(pattern, escape="\\")
            content_match = KnowledgeChunkTable.content.ilike(
                pattern,
                escape="\\",
            )
            filters = [
                *eligible,
                or_(
                    technique_id.ilike(pattern, escape="\\"),
                    title_match,
                    content_match,
                ),
            ]
            rank = case((title_match, 0), (content_match, 1), else_=2)
            order_by = [rank, KnowledgeChunkTable.knowledge_chunk_id]

        rows = self._session.execute(
            select(
                KnowledgeChunkTable.knowledge_chunk_id,
                KnowledgeChunkTable.source,
                KnowledgeChunkTable.content,
                KnowledgeChunkTable.chunk_metadata,
            )
            .where(*filters)
            .order_by(*order_by)
            .limit(limit)
        ).all()

        results: list[dict[str, str]] = []
        for knowledge_chunk_id, source, content, metadata in rows:
            if not isinstance(metadata, dict):
                raise ToolDependencyError("attack knowledge metadata is invalid")
            values = {
                "knowledge_chunk_id": knowledge_chunk_id,
                "technique_id": metadata.get("technique_id"),
                "title": metadata.get("title"),
                "summary": content,
                "source_uri": source,
                "version": metadata.get("version"),
            }
            if any(
                not isinstance(value, str) or not value.strip()
                for value in values.values()
            ):
                raise ToolDependencyError("attack knowledge metadata is invalid")
            results.append({key: value for key, value in values.items()})
        return results


class AttackKnowledgeLookup(Protocol):
    def lookup(
        self,
        *,
        query: str,
        limit: int,
        timeout_seconds: float | None = None,
    ) -> list[dict[str, str]]: ...


class AttackLookupWork:
    def __init__(
        self,
        *,
        session_factory: sessionmaker[Session],
        clock: Callable[[], float] = monotonic,
        repository_factory: Callable[
            [Session], AttackKnowledgeLookup
        ] = AttackKnowledgeRepository,
    ) -> None:
        self._session_factory = session_factory
        self._clock = clock
        self._repository_factory = repository_factory

    def __call__(self, *, query: str, limit: int) -> list[dict[str, str]]:
        deadline = self._clock() + 10.0
        for attempt in range(3):
            remaining = min(deadline - self._clock(), check_execution() or 10.0)
            if remaining <= 0:
                raise ToolDependencyTimeout("attack lookup deadline exceeded")
            try:
                with self._session_factory() as session:
                    return self._repository_factory(session).lookup(
                        query=query,
                        limit=limit,
                        timeout_seconds=remaining,
                    )
            except OperationalError as exc:
                if self._clock() >= deadline:
                    raise ToolDependencyTimeout("attack lookup timed out") from exc
                if attempt == 2:
                    raise ToolDependencyError("attack lookup unavailable") from exc
        raise AssertionError("unreachable retry state")


def build_attack_lookup_work(
    *,
    session_factory: sessionmaker[Session],
    model_path: Path | None = None,
) -> AttackLookupWork:
    from evidencesoc.rag.embeddings import LocalEmbeddingProvider
    from evidencesoc.rag.retriever import HybridAttackKnowledgeRepository

    # The provider is lazy and offline: discovery opens neither the model nor DB.
    embedder = (
        LocalEmbeddingProvider(model_path=model_path)
        if model_path is not None
        else LocalEmbeddingProvider()
    )
    return AttackLookupWork(
        session_factory=session_factory,
        repository_factory=lambda session: HybridAttackKnowledgeRepository(
            session, embedder
        ),
    )
