from __future__ import annotations

from contextlib import nullcontext

import pytest
from sqlalchemy.dialects import postgresql
from sqlalchemy.exc import OperationalError

from evidencesoc.tools.attack_work import (
    AttackKnowledgeRepository,
    AttackLookupWork,
    _escape_like,
)
from evidencesoc.tools.errors import ToolDependencyError


def test_escape_like_quotes_wildcards_and_backslashes() -> None:
    value = "T1190%_" + "\\"
    expected = "T1190\\%\\_" + "\\\\"
    assert _escape_like(value) == expected


def test_attack_work_retries_operational_errors() -> None:
    class FlakyFactory:
        def __init__(self) -> None:
            self.calls = 0

        def __call__(self) -> object:
            self.calls += 1
            raise OperationalError("SELECT", {}, RuntimeError("temporary"))

    factory = FlakyFactory()
    work = AttackLookupWork(session_factory=factory)  # type: ignore[arg-type]
    with pytest.raises(ToolDependencyError, match="unavailable"):
        work(query="dns", limit=3)
    assert factory.calls == 3


def test_repository_uses_bound_escaped_keyword_query() -> None:
    class Result:
        def all(self) -> list[tuple[object, ...]]:
            return [
                (
                    "KC-1",
                    "https://attack.example/T1190",
                    "public-facing application",
                    {
                        "object_type": "attack-pattern",
                        "technique_id": "T1190",
                        "title": "Exploit Public-Facing Application",
                        "version": "19.2",
                    },
                )
            ]

    class SessionSpy:
        def __init__(self) -> None:
            self.statement = None

        def execute(self, statement: object) -> Result:
            self.statement = statement
            return Result()

    session = SessionSpy()
    repository = AttackKnowledgeRepository(session)  # type: ignore[arg-type]
    value = repository.lookup(query="dns%_", limit=10)

    assert value[0]["technique_id"] == "T1190"
    compiled = session.statement.compile(dialect=postgresql.dialect())
    assert "dns%_" not in str(compiled)
    assert any("dns\\%\\_" in str(parameter) for parameter in compiled.params.values())


def test_repository_unknown_exact_technique_does_not_use_keyword_fallback() -> None:
    class Result:
        def all(self) -> list[tuple[object, ...]]:
            return []

    class SessionSpy:
        def __init__(self) -> None:
            self.statement = None

        def execute(self, statement: object) -> Result:
            self.statement = statement
            return Result()

    session = SessionSpy()
    assert (
        AttackKnowledgeRepository(session).lookup(query="T9999", limit=10) == []  # type: ignore[arg-type]
    )
    compiled = session.statement.compile(dialect=postgresql.dialect())
    assert "ILIKE" not in str(compiled).upper()


def test_attack_lookup_work_builder_does_not_query_during_construction() -> None:
    class SessionFactory:
        calls = 0

        def __call__(self) -> object:
            self.calls += 1
            return nullcontext()

    factory = SessionFactory()
    AttackLookupWork(session_factory=factory)  # type: ignore[arg-type]
    assert factory.calls == 0


def test_repository_symbol_is_importable() -> None:
    assert AttackKnowledgeRepository.__name__ == "AttackKnowledgeRepository"


def test_production_builder_uses_hybrid_repository_without_loading_model_or_querying() -> (
    None
):
    from evidencesoc.rag.retriever import HybridAttackKnowledgeRepository
    from evidencesoc.tools.attack_work import build_attack_lookup_work

    class SessionFactory:
        def __call__(self) -> object:
            raise AssertionError("construction must not open a database session")

    work = build_attack_lookup_work(session_factory=SessionFactory())  # type: ignore[arg-type]
    repository = work._repository_factory(None)
    assert isinstance(repository, HybridAttackKnowledgeRepository)
