"""New-kind controller admission and inspected host budget forwarding."""

import json
from hashlib import sha256

import pytest

from evals.contracts import canonical_hash
from evals.e_planning import planning_requests
from evals.tests.test_e_additional_selection import actual_fixture


async def admitted_inputs(tmp_path, monkeypatch, *, omit=None):
    from evals.tests import test_epoch_development as epochs
    from evals.tests.test_e_planning_journal import register_fixture
    from evals.tests.test_epoch_development_runtime import runtime_options

    binding = {
        "image_id": "sha256:" + "4" * 64,
        "dependencies_lock_sha256": "5" * 64,
        "dependencies_tree_sha256": "6" * 64,
        "knowledge_sha256": "7" * 64,
        "controller_manifest_sha256": sha256(b'{"synthetic":true}').hexdigest(),
    }
    factory = epochs.development_inputs

    def inputs(*args, **kwargs):
        return factory(*args, **kwargs, runtime_binding=binding, omit=omit)

    monkeypatch.setattr(epochs, "development_inputs", inputs)
    original, package, _imported, _selection, registration = await actual_fixture(
        tmp_path, monkeypatch
    )
    request = planning_requests(registration)[0]
    monkeypatch.delenv("TASK13_WORKER_NONCE")
    monkeypatch.delenv("TASK13_EPOCH_HOST_BUDGET_PATH")
    monkeypatch.setattr("os.getpid", lambda: 999)
    path = tmp_path / "dispatch/e-planning.sqlite"
    path.parent.mkdir()
    _, authority, _ = register_fixture(path, registration)
    options = runtime_options(
        tmp_path, request, original.paths["source_receipt"].parent, original.budget
    )
    options.update(
        phase="development",
        import_source_dir=str(package),
        import_dispatch_path=str(path),
        planning_authority_sha256=canonical_hash(authority),
    )
    return request, options, original, binding


@pytest.mark.asyncio
@pytest.mark.parametrize("review", [False, True])
async def test_host_passes_only_admitted_additional_original_budget_to_planning_and_review(
    tmp_path, monkeypatch, review
):
    from evals.adapters.e_planning_review import build_review_request
    from evals.tests.test_e_planning_review import reference
    from scripts import task13_worker_runtime as runtime

    request, options, original, binding = await admitted_inputs(tmp_path, monkeypatch)
    if review:
        request = build_review_request(
            request, reference(request), operation="read_packet"
        )
        options["phase"] = "verification"
    # Only Docker/dependency fixture I/O is replaced; host epoch, source, account,
    # identity, package and journal admission all execute against real temp bytes.
    monkeypatch.setattr(runtime, "_validate_source", lambda *args: None)
    monkeypatch.setattr(
        runtime,
        "dependency_tree_hash",
        lambda path: "6" * 64 if path.name == "deps" else "7" * 64,
    )
    captured = []

    class Prepared(Exception):
        pass

    def prepared(**kwargs):
        captured.append(kwargs)
        raise Prepared

    monkeypatch.setattr(runtime, "docker_run_arguments", prepared)
    before = original.budget.read_bytes()
    with pytest.raises(Prepared):
        await runtime.run_container(
            request.model_dump(mode="json"), original.paths["events"].parent, options
        )
    assert len(captured) == 1
    passed = captured[0]["environment"]
    assert passed["TASK13_EPOCH_HOST_BUDGET_PATH"] == str(original.budget.resolve())
    assert json.loads(passed["TASK13_RUNTIME_BINDING"]) == binding
    assert captured[0]["mounts"]["/app/budget"] == str(original.budget.parent.resolve())
    assert original.budget.read_bytes() == before


@pytest.mark.asyncio
async def test_host_rejects_missing_additional_export_helper_before_container(
    tmp_path, monkeypatch
):
    from scripts import task13_worker_runtime as runtime

    request, options, original, _binding = await admitted_inputs(
        tmp_path, monkeypatch, omit="evals/additional_source_selection.py"
    )
    with pytest.raises(ValueError, match="entrypoint|export"):
        runtime.validate_e_planning_host(
            request,
            original.paths["events"].parent,
            options,
            {"lock_sha256": "5" * 64, "tree_sha256": "6" * 64},
        )
