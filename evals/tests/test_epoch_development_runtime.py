"""v4 controller routing has development-only scope and no planning mounts."""

import json
from hashlib import sha256

import pytest

from evals.tests.test_epoch_development import (
    development_inputs,
    development_module,
    request_data,
)
from scripts import task13_worker_runtime as runtime


def request():
    return development_module().EpochDevelopmentRequest(**request_data())


def test_runtime_parses_v4_without_changing_immutable_mount_policy():
    value = request()
    assert runtime._worker_request(value.model_dump(mode="json")) == value
    assert runtime.mount_policy(value.schema_version) == runtime.mount_policy(
        "task13-remediation-worker-v2"
    )
    readonly, writable = runtime.mount_policy(value.schema_version)
    assert "/app/import-source" not in readonly | writable
    with pytest.raises(ValueError):
        runtime._worker_request(
            {**value.model_dump(mode="json"), "planning_slot_id": "forged"}
        )


@pytest.mark.asyncio
async def test_public_remediation_wrapper_preserves_explicit_v4(monkeypatch, tmp_path):
    calls = []

    async def run(spec, agent, options):
        calls.append(spec)
        return {"synthetic": True}

    value = request().model_dump(mode="json")
    monkeypatch.setattr(runtime, "run_container", run)
    assert await runtime.run_remediation_container(value, tmp_path, {}) == {
        "synthetic": True
    }
    assert calls == [value]


def runtime_options(tmp_path, request, source, budget):
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
    return {
        "source_dir": str(source),
        "source_commit": request.source_commit,
        "phase": "development",
        "dependencies_dir": str(dependencies),
        "dependencies_lock_sha256": "5" * 64,
        "knowledge_dir": str(tmp_path / "knowledge"),
        "knowledge_sha256": "7" * 64,
        "budget_dir": str(budget.parent),
        "budget_identity": request.budget_identity,
        "model_identity_binding": request.model_identity_binding.model_dump(
            mode="json"
        ),
        "output_dir": str(tmp_path / "output"),
        "image_id": "sha256:" + "4" * 64,
        "network": "synthetic",
        "controller_manifest_path": str(controller),
    }


@pytest.mark.asyncio
@pytest.mark.parametrize("tamper", ["epoch", "phase", "model", "budget"])
async def test_controller_checks_admission_before_key_or_container(
    tmp_path, monkeypatch, tamper
):
    module, value, agent, source, budget, _ = development_inputs(tmp_path, monkeypatch)
    options = runtime_options(tmp_path, value, source, budget)
    if tamper == "phase":
        options["phase"] = "formal"
    elif tamper == "model":
        options["model_identity_binding"] = {
            **options["model_identity_binding"],
            "model_epoch_id": "crossed",
        }
    elif tamper == "budget":
        options["budget_identity"] = {}
    monkeypatch.setattr(runtime, "_validate_source", lambda *a: None)
    monkeypatch.setattr(
        runtime,
        "dependency_tree_hash",
        lambda path: "6" * 64 if path.name == "deps" else "7" * 64,
    )
    checked = []

    def reject(*a, **kw):
        checked.append(True)
        raise PermissionError("synthetic missing registered epoch")

    monkeypatch.setattr(module, "validate_epoch_development_runtime", reject)

    async def forbidden(*a, **kw):
        pytest.fail("container started before admission")

    class Secrets(dict):
        def __getitem__(self, key):
            assert key != "DEEPSEEK_API_KEY", "credential read before admission"
            return super().__getitem__(key)

    monkeypatch.setattr(runtime.asyncio, "create_subprocess_exec", forbidden)
    monkeypatch.setattr(
        runtime.os, "environ", Secrets({"DEEPSEEK_API_KEY": "synthetic-never-read"})
    )
    with pytest.raises((ValueError, PermissionError)):
        await runtime.run_container(value.model_dump(mode="json"), agent, options)
    assert checked == ([True] if tamper == "epoch" else [])


@pytest.mark.asyncio
async def test_controller_passes_real_admitted_development_binding_with_original_mounts(
    tmp_path, monkeypatch
):
    binding = {
        "image_id": "sha256:" + "4" * 64,
        "dependencies_lock_sha256": "5" * 64,
        "dependencies_tree_sha256": "6" * 64,
        "knowledge_sha256": "7" * 64,
        "controller_manifest_sha256": sha256(b'{"synthetic":true}').hexdigest(),
    }
    _, value, agent, source, budget, manifest = development_inputs(
        tmp_path, monkeypatch, runtime_binding=binding
    )
    options = runtime_options(tmp_path, value, source, budget)
    # Synthetic export/dependency fixtures; all registered epoch, original-account,
    # adopted-model and actual controller entrypoint checks run unmocked.
    monkeypatch.setenv("DEEPSEEK_API_KEY", "synthetic-never-sent")
    monkeypatch.setattr(runtime, "_validate_source", lambda *a: None)
    monkeypatch.setattr(
        runtime,
        "dependency_tree_hash",
        lambda path: "6" * 64 if path.name == "deps" else "7" * 64,
    )
    before = budget.read_bytes()
    captured = []

    class Prepared(Exception):
        pass

    def prepared(**kwargs):
        captured.append(kwargs)
        raise Prepared

    monkeypatch.setattr(runtime, "docker_run_arguments", prepared)
    with pytest.raises(Prepared):
        await runtime.run_container(value.model_dump(mode="json"), agent, options)
    assert len(captured) == 1
    passed = captured[0]["environment"]
    assert passed["TASK13_PHASE"] == "development"
    assert json.loads(passed["TASK13_RUNTIME_BINDING"]) == binding
    assert passed["TASK13_EPOCH_HOST_BUDGET_PATH"] == manifest["budget_path"]
    assert (
        set(captured[0]["mounts"]) == runtime.READ_ONLY_MOUNTS | runtime.WRITABLE_MOUNTS
    )
    assert not any(key.startswith("TASK13_IMPORT_") for key in passed)
    assert captured[0]["mounts"]["/app/budget"] == str(budget.parent.resolve())
    assert budget.read_bytes() == before
