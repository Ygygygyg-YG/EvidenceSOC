"""Regression-v3 routing keeps the legacy boundary and has no paid transport."""

import pytest

from evals.adapters.epoch_remediation import EpochRemediationRequest
from evals.tests.test_remediation import request_values
from scripts import task13_worker_runtime as runtime


def request():
    return EpochRemediationRequest(
        **request_values("regression"),
        epoch_id="synthetic-epoch-1",
        epoch_manifest_sha256="e" * 64,
    )


def test_runtime_parses_explicit_epoch_schema_and_rejects_unregistered_extras():
    value = request()
    assert runtime._worker_request(value.model_dump(mode="json")) == value
    with pytest.raises(ValueError):
        runtime._worker_request({**value.model_dump(mode="json"), "auto_replay": True})


@pytest.mark.asyncio
async def test_runtime_routes_epoch_to_dedicated_adapter_without_legacy_fallthrough(
    monkeypatch, tmp_path
):
    from evals.adapters import epoch_remediation

    called = []

    async def run(value, agent):
        called.append((value, agent))
        return {"synthetic": True}

    monkeypatch.setattr(epoch_remediation, "run_epoch_remediation", run)
    assert await runtime._invoke_adapter(request(), tmp_path) == {"synthetic": True}
    assert called == [(request(), tmp_path)]


@pytest.mark.asyncio
async def test_public_remediation_wrapper_preserves_explicit_v3_schema(
    monkeypatch, tmp_path
):
    value = request().model_dump(mode="json")
    calls = []

    async def run(spec, agent, options):
        calls.append(spec)
        return {"execution_status": "failed", "synthetic": True}

    monkeypatch.setattr(runtime, "run_container", run)
    assert (await runtime.run_remediation_container(value, tmp_path, {}))[
        "synthetic"
    ] is True
    assert calls == [value]


@pytest.mark.asyncio
async def test_controller_checks_registered_epoch_before_key_or_container(
    tmp_path, monkeypatch
):
    import json

    from evals.tests.test_epoch_remediation import epoch_inputs

    module, value, agent, source, budget, _manifest = epoch_inputs(
        tmp_path, monkeypatch
    )
    dependencies = tmp_path / "deps"
    for name in [
        "mcp",
        "langgraph",
        "langchain_openai",
        "fastembed",
        "pydantic",
        "sqlalchemy",
        "httpx",
    ]:
        (dependencies / name).mkdir(parents=True)
    receipt = {
        "lock_sha256": "5" * 64,
        "tree_sha256": "6" * 64,
        "platform": "linux-amd64",
        "python_version": "3.12.14",
    }
    (dependencies / "task13_dependencies.json").write_text(json.dumps(receipt))
    controller = tmp_path / "controller-manifest.json"
    controller.write_text('{"synthetic":true}')
    options = {
        "source_dir": str(source),
        "source_commit": value.source_commit,
        "phase": "formal",
        "dependencies_dir": str(dependencies),
        "dependencies_lock_sha256": "5" * 64,
        "knowledge_dir": str(tmp_path / "knowledge"),
        "knowledge_sha256": "7" * 64,
        "budget_dir": str(budget.parent),
        "budget_identity": value.budget_identity,
        "output_dir": str(tmp_path / "output"),
        "image_id": "sha256:" + "4" * 64,
        "network": "synthetic",
        "controller_manifest_path": str(controller),
    }
    monkeypatch.setattr(runtime, "_validate_source", lambda *a: None)
    monkeypatch.setattr(
        runtime,
        "dependency_tree_hash",
        lambda path: "6" * 64 if path == dependencies else "7" * 64,
    )
    checked = []

    def reject(*args, **kwargs):
        checked.append(True)
        raise PermissionError("synthetic missing registered epoch")

    monkeypatch.setattr(module, "validate_epoch_runtime", reject)

    async def forbidden(*a, **k):
        pytest.fail("container started before epoch rejection")

    monkeypatch.setattr(runtime.asyncio, "create_subprocess_exec", forbidden)

    class Secrets(dict):
        def __getitem__(self, key):
            if key == "DEEPSEEK_API_KEY":
                pytest.fail("credential read before epoch rejection")
            return super().__getitem__(key)

    monkeypatch.setattr(
        runtime.os, "environ", Secrets({"DEEPSEEK_API_KEY": "synthetic-never-read"})
    )
    with pytest.raises(PermissionError, match="registered epoch"):
        await runtime.run_container(value.model_dump(mode="json"), agent, options)
    assert checked == [True]
