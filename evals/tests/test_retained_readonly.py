"""Read-only retained factories with synthetic connections; never opens PostgreSQL."""

import os
from contextlib import asynccontextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy.engine import make_url


@pytest.mark.asyncio
@pytest.mark.parametrize("readonly", [False, True])
async def test_checkpointer_readonly_skips_setup_and_forces_connection_readonly(
    monkeypatch, readonly
):
    from evidencesoc.agents import checkpoint

    seen = []

    class Pool:
        @staticmethod
        def check_connection(connection):
            raise AssertionError("synthetic pool must not open a real connection")

        def __init__(self, url, **kwargs):
            seen.append(("pool", url, kwargs))

        def open(self, **kwargs):
            seen.append(("open", kwargs))

        def close(self):
            seen.append(("close",))

    class Saver:
        def __init__(self, pool):
            self.pool = pool

        def setup(self):
            seen.append(("setup",))

    monkeypatch.setattr(checkpoint, "ConnectionPool", Pool)
    monkeypatch.setattr(checkpoint, "ThreadedPostgresSaver", Saver)
    async with checkpoint.open_checkpointer(
        "postgresql://synthetic@localhost/task13_" + "a" * 32,
        **({"readonly": True} if readonly else {}),
    ) as saver:
        assert isinstance(saver, Saver)
    options = seen[0][2]["kwargs"]["options"]
    assert "statement_timeout=3000" in options
    assert ("default_transaction_read_only=on" in options) is readonly
    assert (("setup",) in seen) is not readonly
    assert seen[-1] == ("close",)


@pytest.fixture
def retained_factory(monkeypatch):
    from evals.adapters import retained_workflow as retained

    original_url = (
        "postgresql+psycopg://synthetic@localhost/base"
        "?options=-c%20application_name%3Dtask13-read"
    )
    monkeypatch.setenv("DATABASE_URL", original_url)
    monkeypatch.setenv("OPENSEARCH_INDEX", "original-index")
    seen = {}

    def settings(*, _env_file, **values):
        return SimpleNamespace(
            database_url=values.get("database_url", os.environ["DATABASE_URL"]),
            opensearch_url=values.get("opensearch_url", "http://synthetic:9200"),
            opensearch_index=values.get("opensearch_index", "original-index"),
            rag_data_directory=values.get("rag_data_directory", Path("synthetic")),
            llm_mode=values.get("llm_mode", "fixture"),
        )

    def engine(url):
        seen["engine_url"] = url
        return SimpleNamespace(dispose=lambda: seen.update(disposed=True))

    class Services:
        def __init__(self, settings, **kwargs):
            self.settings = settings
            self._sessions = kwargs["session_factory"]

        async def aclose(self):
            seen["closed"] = True

    @asynccontextmanager
    async def checkpointer(url, **kwargs):
        seen["checkpoint_url"] = url
        seen["checkpoint_options"] = kwargs
        yield object()

    def workflow(**kwargs):
        seen["workflow"] = kwargs
        return SimpleNamespace(**kwargs)

    monkeypatch.setattr(retained, "Settings", settings)
    monkeypatch.setattr(retained, "create_database_engine", engine)
    monkeypatch.setattr(retained, "create_session_factory", lambda engine: object())
    monkeypatch.setattr(retained, "PostgresWorkflowServices", Services)
    monkeypatch.setattr(retained, "open_checkpointer", checkpointer)
    monkeypatch.setattr(retained, "NodeHandlers", lambda *args, **kwargs: object())
    monkeypatch.setattr(retained, "InvestigationWorkflow", workflow)
    reference = {
        "database_name": "task13_" + "a" * 32,
        "index_name": "security-events-task13-" + "a" * 32,
        "incident_id": "IN-synthetic",
        "source_commit": "b" * 40,
    }
    return retained, reference, original_url, seen


@pytest.mark.asyncio
@pytest.mark.parametrize("readonly", [False, True])
async def test_retained_readonly_preserves_factory_defaults_and_avoids_global_env(
    retained_factory, readonly
):
    retained, reference, original_url, seen = retained_factory
    async with retained.open_retained_workflow(
        reference,
        model=None,
        verification_enabled=False,
        **({"readonly": True} if readonly else {}),
    ) as workflow:
        assert workflow.model is None
        assert workflow.settings.llm_mode == "fixture"
        assert workflow.services.planner_model is None
        selected = make_url(seen["engine_url"])
        assert selected.database == reference["database_name"]
        if readonly:
            assert os.environ["DATABASE_URL"] == original_url
            assert os.environ["OPENSEARCH_INDEX"] == "original-index"
            assert "application_name=task13-read" in selected.query["options"]
            assert "default_transaction_read_only=on" in selected.query["options"]
            assert "statement_timeout=3000" in selected.query["options"]
            assert seen["checkpoint_options"] == {"readonly": True}
        else:
            assert os.environ["DATABASE_URL"] == seen["engine_url"]
            assert os.environ["OPENSEARCH_INDEX"] == reference["index_name"]
            assert "default_transaction_read_only" not in selected.query["options"]
            assert seen["checkpoint_options"] == {}
        assert seen["checkpoint_url"] == seen["engine_url"]
    assert seen["closed"] and seen["disposed"]
    assert os.environ["DATABASE_URL"] == original_url
    assert os.environ["OPENSEARCH_INDEX"] == "original-index"


@pytest.mark.asyncio
async def test_retained_readonly_rejects_model_before_connection_or_model_admission(
    retained_factory, monkeypatch
):
    retained, reference, _, seen = retained_factory

    def forbidden(*args):
        raise AssertionError("read-only factory must reject the model first")

    monkeypatch.setattr(retained, "_require_inspected_renewal_model", forbidden)
    with pytest.raises(PermissionError, match="read-only.*model"):
        async with retained.open_retained_workflow(
            reference, readonly=True, model=object()
        ):
            pass
    assert seen == {}
