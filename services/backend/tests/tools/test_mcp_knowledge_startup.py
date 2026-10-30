"""Keep offline embedding startup outside the unchanged tool execution deadline."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from evidencesoc.mcp_server import main
from evidencesoc.mcp_server.context import RunContext


def configure_builder(monkeypatch, *, context_error=False, prepare_error=False):
    steps = []

    def validate(*_args):
        steps.append("context")
        if context_error:
            raise PermissionError("invalid context")

    class Work:
        def prepare(self):
            steps.append("prepare")
            if prepare_error:
                raise RuntimeError("unverified offline model")

    work = Work()
    monkeypatch.setattr(main, "validate_run_context", validate)
    monkeypatch.setattr(main, "SqlAuditWriter", lambda **_kw: object())
    monkeypatch.setattr(main, "build_event_search_work", lambda **_kw: object())
    monkeypatch.setattr(main, "build_alert_context_work", lambda **_kw: object())
    monkeypatch.setattr(main, "build_attack_lookup_work", lambda **_kw: work)

    def create(**kwargs):
        assert kwargs["attack_tools"]._work is work
        steps.append("server")
        return "server"

    monkeypatch.setattr(main, "create_server", create)
    args = {
        "context": RunContext("AR-test", "IN-test", "TRACE-test"),
        "settings": SimpleNamespace(
            opensearch_url="http://unused",
            opensearch_index="unused",
            rag_data_directory=Path("unused"),
        ),
        "session_factory": object(),
    }
    return steps, args


def test_discovery_builder_stays_lazy_by_default(monkeypatch):
    steps, args = configure_builder(monkeypatch)
    assert main.build_server(**args) == "server"
    assert steps == ["context", "server"]


def test_explicit_startup_validates_context_then_prepares_same_tool_work(monkeypatch):
    steps, args = configure_builder(monkeypatch)
    assert main.build_server(**args, prepare_knowledge=True) == "server"
    assert steps == ["context", "prepare", "server"]


@pytest.mark.parametrize(
    "context_error,prepare_error,expected",
    [
        (True, False, ["context"]),
        (False, True, ["context", "prepare"]),
    ],
)
def test_startup_validation_or_model_failure_never_creates_server(
    monkeypatch, context_error, prepare_error, expected
):
    steps, args = configure_builder(
        monkeypatch, context_error=context_error, prepare_error=prepare_error
    )
    with pytest.raises((PermissionError, RuntimeError)):
        main.build_server(**args, prepare_knowledge=True)
    assert steps == expected


@pytest.mark.parametrize(
    "mode,tools,expected",
    [
        ("hybrid", ["lookup_attack_technique"], True),
        ("semantic_only", ["lookup_attack_technique"], True),
        ("disabled", ["lookup_attack_technique"], False),
        ("hybrid", ["get_alert_context"], False),
    ],
)
def test_actual_stdio_startup_prepares_only_permitted_knowledge(
    monkeypatch, mode, tools, expected
):
    steps = []
    monkeypatch.setenv("EVIDENCESOC_RAG_MODE", mode)
    monkeypatch.setenv("EVIDENCESOC_ALLOWED_TOOLS", json.dumps(tools))
    monkeypatch.setattr(
        main,
        "load_run_context",
        lambda _env: RunContext("AR-test", "IN-test", "TRACE-test"),
    )
    monkeypatch.setattr(
        main, "Settings", lambda **_kw: SimpleNamespace(database_url="unused")
    )
    monkeypatch.setattr(
        main,
        "create_database_engine",
        lambda *_a, **_kw: SimpleNamespace(dispose=lambda: steps.append("dispose")),
    )
    monkeypatch.setattr(main, "create_session_factory", lambda _engine: object())

    def build(**kwargs):
        assert kwargs.get("prepare_knowledge") is expected
        steps.append("build")
        return SimpleNamespace(run=lambda **kw: steps.append(("run", kw)))

    monkeypatch.setattr(main, "build_server", build)
    main.main()
    assert steps == ["build", ("run", {"transport": "stdio"}), "dispose"]


def test_actual_stdio_startup_disposes_engine_when_model_preparation_fails(monkeypatch):
    steps = []
    monkeypatch.setenv("EVIDENCESOC_RAG_MODE", "hybrid")
    monkeypatch.setenv("EVIDENCESOC_ALLOWED_TOOLS", '["lookup_attack_technique"]')
    monkeypatch.setattr(
        main,
        "load_run_context",
        lambda _env: RunContext("AR-test", "IN-test", "TRACE-test"),
    )
    monkeypatch.setattr(
        main, "Settings", lambda **_kw: SimpleNamespace(database_url="unused")
    )
    monkeypatch.setattr(
        main,
        "create_database_engine",
        lambda *_a, **_kw: SimpleNamespace(dispose=lambda: steps.append("dispose")),
    )
    monkeypatch.setattr(main, "create_session_factory", lambda _engine: object())

    def build(**kwargs):
        assert kwargs.get("prepare_knowledge") is True
        raise RuntimeError("unverified offline model")

    monkeypatch.setattr(main, "build_server", build)
    with pytest.raises(RuntimeError, match="unverified offline model"):
        main.main()
    assert steps == ["dispose"]
