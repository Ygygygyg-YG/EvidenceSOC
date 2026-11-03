"""Container routing boundary tests; no Docker, services or provider calls."""

from __future__ import annotations

import asyncio
import json
import os
from urllib.parse import urlsplit

import pytest
from sqlalchemy.engine import make_url

from scripts import task13_worker_runtime as runtime


def test_formal_epoch_launch_maps_services_at_docker_boundary(tmp_path, monkeypatch):
    from evals.tests.test_epoch_runtime import request as regression_request

    request = regression_request()
    agent = tmp_path / "agent"
    agent.mkdir()
    (agent / "events.jsonl").write_text("{}\n", encoding="utf-8")
    source = tmp_path / "source"
    source.mkdir()
    dependencies = tmp_path / "deps"
    dependencies.mkdir()
    for name in (
        "mcp",
        "langgraph",
        "langchain_openai",
        "fastembed",
        "pydantic",
        "sqlalchemy",
        "httpx",
    ):
        (dependencies / name).mkdir()
    (dependencies / "task13_dependencies.json").write_text(
        json.dumps(
            {
                "lock_sha256": "2" * 64,
                "tree_sha256": "3" * 64,
                "platform": "linux-amd64",
            }
        ),
        encoding="utf-8",
    )
    knowledge = tmp_path / "knowledge"
    knowledge.mkdir()
    controller = tmp_path / "controller.json"
    controller.write_text('{"synthetic":true}', encoding="utf-8")
    monkeypatch.setattr(runtime, "_validate_source", lambda *args: None)
    monkeypatch.setattr(runtime, "dependency_tree_hash", lambda *args: "3" * 64)
    monkeypatch.setattr(
        "evals.adapters.remediation_worker.validate_binding", lambda *args, **kw: None
    )
    monkeypatch.setattr(
        "evals.adapters.remediation_worker.require_existing_budget", lambda *args: None
    )
    validations = []

    def validate_epoch(*args, **kwargs):
        validations.append("epoch-before-container")
        return {"budget_path": str(tmp_path / "budget/campaign.sqlite")}

    monkeypatch.setattr(
        "evals.adapters.epoch_remediation.validate_epoch_runtime", validate_epoch
    )
    database = "postgresql+psycopg://unit_user:unit_fixture@127.0.0.1:5432/evidencesoc"
    search = "http://unit_user:unit_fixture@127.0.0.1:9201"
    monkeypatch.setenv("DATABASE_URL", database)
    monkeypatch.setenv("OPENSEARCH_URL", search)
    monkeypatch.setenv("DEEPSEEK_API_KEY", "unit-no-provider")
    captured = {}

    class BeforeDocker(Exception):
        pass

    def capture(**kwargs):
        assert validations == ["epoch-before-container"]
        captured.update(kwargs)
        raise BeforeDocker

    monkeypatch.setattr(runtime, "docker_run_arguments", capture)
    options = {
        "source_dir": str(source),
        "source_commit": request.source_commit,
        "dependencies_dir": str(dependencies),
        "dependencies_lock_sha256": "2" * 64,
        "knowledge_dir": str(knowledge),
        "knowledge_sha256": "3" * 64,
        "budget_dir": str(tmp_path / "budget"),
        "budget_identity": request.budget_identity,
        "output_dir": str(tmp_path / "output"),
        "temporary_root": str(tmp_path / "tmp"),
        "controller_manifest_path": str(controller),
        "phase": "formal",
        "image_id": "sha256:" + "5" * 64,
        "network": "unit-owned-network",
    }
    with pytest.raises(BeforeDocker):
        asyncio.run(
            runtime.run_container(request.model_dump(mode="json"), agent, options)
        )
    actual_database = make_url(captured["environment"]["DATABASE_URL"])
    actual_search = urlsplit(captured["environment"]["OPENSEARCH_URL"])
    assert (actual_database.host, actual_database.port) == (
        "evidencesoc-postgres-1",
        5432,
    )
    assert (actual_search.hostname, actual_search.port) == (
        "evidencesoc-opensearch-1",
        9200,
    )
    assert (
        actual_database.username,
        actual_database.password,
        actual_database.database,
    ) == ("unit_user", "unit_fixture", "evidencesoc")
    assert (actual_search.username, actual_search.password) == (
        "unit_user",
        "unit_fixture",
    )
    assert os.environ["DATABASE_URL"] == database
    assert os.environ["OPENSEARCH_URL"] == search
    assert captured["network"] == "unit-owned-network"
    assert captured["environment"]["TASK13_PHASE"] == "formal"


@pytest.mark.parametrize(
    "override",
    [
        {"DATABASE_URL": "postgresql://unit:fixture@remote.invalid:5432/evidencesoc"},
        {"DATABASE_URL": "postgresql://unit:fixture@127.0.0.1:5433/evidencesoc"},
        {
            "DATABASE_URL": "postgresql://unit:fixture@127.0.0.1:5432/evidencesoc?host=remote.invalid"
        },
        {"DATABASE_URL": "sqlite:///unapproved.db"},
        {"OPENSEARCH_URL": "http://remote.invalid:9201"},
        {"OPENSEARCH_URL": "http://127.0.0.1:9201/index"},
        {"OPENSEARCH_URL": "http://127.0.0.1:9201?host=remote.invalid"},
        {"OPENSEARCH_URL": "http://127.0.0.1:9201/#fragment"},
        {"DEEPSEEK_API_KEY": "unit-must-not-enter-service-parser"},
    ],
)
def test_formal_service_mapper_rejects_destination_or_context_override(override):
    values = {
        "DATABASE_URL": "postgresql://unit:fixture@127.0.0.1:5432/evidencesoc",
        "OPENSEARCH_URL": "http://127.0.0.1:9201",
    }
    values.update(override)
    mapper = getattr(runtime, "container_service_environment", None)
    assert callable(mapper), "reviewed container service mapper is required"
    with pytest.raises(PermissionError):
        mapper(values)


def test_formal_service_mapper_is_idempotent_and_does_not_mutate_host_values():
    values = {
        "DATABASE_URL": "postgresql+psycopg://unit:fixture@127.0.0.1:5432/evidencesoc",
        "OPENSEARCH_URL": "http://127.0.0.1:9201",
    }
    original = dict(values)
    mapper = getattr(runtime, "container_service_environment", None)
    assert callable(mapper), "reviewed container service mapper is required"
    mapped = mapper(values)
    assert values == original
    assert mapper(mapped) == mapped
    assert set(mapped) == {"DATABASE_URL", "OPENSEARCH_URL"}
