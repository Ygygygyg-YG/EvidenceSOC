"""Synthetic v4 analysis admission; temporary accounts and fake HTTP only."""

import importlib
import importlib.util
import json
import os
import shutil
import sqlite3
from contextlib import contextmanager
from copy import deepcopy
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from evals.adapters.epoch_remediation import EpochRemediationRequest
from evals.adapters.remediation_contracts import RemediationRequest
from evals.contracts import CallBudget, ModelConfig, SeedPolicy, canonical_hash
from evals.tests.test_remediation import request_values


def development_module():
    assert importlib.util.find_spec("evals.adapters.epoch_development") is not None, (
        "development needs its own strict epoch request and admission"
    )
    return importlib.import_module("evals.adapters.epoch_development")


def request_data():
    return {
        **request_values("development"),
        "schema_version": "task13-remediation-worker-v4",
        "epoch_id": "synthetic-epoch-1",
        "epoch_manifest_sha256": "e" * 64,
        "model_identity_binding": {
            "model_epoch_id": "model-0",
            "model_identity_sha256": "9" * 64,
        },
    }


def test_v4_preserves_fixed_development_contract_and_budget_binding():
    request = development_module().EpochDevelopmentRequest(**request_data())
    legacy = RemediationRequest(
        **request_values("development"), budget=CallBudget(max_model_calls=1)
    )
    assert request.worker_spec() == legacy.worker_spec()
    assert request.budget_binding() == {
        **legacy.budget_binding(),
        "epoch_id": request.epoch_id,
        **request.model_identity_binding.model_dump(mode="json"),
    }
    assert request.purpose == "development" and request.group == "B3"
    assert request.budget == CallBudget(max_model_calls=1)
    with pytest.raises(ValueError):
        EpochRemediationRequest.model_validate(
            {
                **request.model_dump(mode="json"),
                "schema_version": "task13-remediation-worker-v3",
            }
        )


@pytest.mark.parametrize(
    "patch",
    [
        {"model": {**ModelConfig().model_dump(), "max_context_bytes": 262144}},
        {"model": {**ModelConfig().model_dump(), "max_tokens": 512}},
        {"model": {**ModelConfig().model_dump(), "timeout_seconds": 60}},
        {"seed": {**SeedPolicy().model_dump(), "max_events": 100}},
        {"seed": {**SeedPolicy().model_dump(), "max_event_bytes": 4096}},
        {"seed": {**SeedPolicy().model_dump(), "max_total_bytes": 32768}},
        {"seed": {**SeedPolicy().model_dump(), "knowledge_top_k": 1}},
        {"repeat": 2},
        {"budget": CallBudget().model_dump()},
    ],
)
def test_v4_rejects_changes_to_frozen_scientific_settings(patch):
    with pytest.raises(ValueError):
        development_module().EpochDevelopmentRequest(**{**request_data(), **patch})


@pytest.mark.parametrize(
    "patch",
    [
        {"purpose": "regression"},
        {"purpose": "planning"},
        {"group": "B2"},
        {"initial_query": None},
        {"initial_query_sha256": "f" * 64},
        {"rag_mode": None},
        {"model_identity_binding": None},
        {"model_identity_binding": {"model_epoch_id": "model-0"}},
        {"schema_version": "task13-remediation-worker-v3"},
    ],
)
def test_v4_rejects_crossed_scope_or_missing_fixed_condition(patch):
    with pytest.raises(ValueError):
        development_module().EpochDevelopmentRequest(**{**request_data(), **patch})


@pytest.mark.parametrize(
    "field", ["epoch_id", "epoch_manifest_sha256", "model_identity_binding"]
)
def test_v4_requires_explicit_source_and_adopted_identity(field):
    value = request_data()
    del value[field]
    with pytest.raises(ValueError):
        development_module().EpochDevelopmentRequest(**value)


WORKER_ENTRIES = {
    "scripts/task13_worker_runtime.py",
    "evals/adapters/epoch_development.py",
    "evals/adapters/epoch_remediation.py",
    "evals/adapters/remediation_worker.py",
    "evals/adapters/remediation_contracts.py",
    "evals/adapters/budget_v2.py",
    "evals/adapters/source_epochs.py",
    "evals/adapters/model_identity_runtime.py",
    "evals/adapters/model_identities.py",
    "evals/adapters/model_client.py",
    "evals/contracts.py",
    "evals/adapters/e_planning_contracts.py",
}


def development_inputs(
    tmp_path,
    monkeypatch,
    *,
    adopted=True,
    omit=None,
    wrong_entry=None,
    extra_source_entries=(),
    runtime_binding=None,
):
    from evals.adapters.budget_v2 import SupplementBudgetAccount
    from evals.tests.test_model_identities import adopt
    from evals.tests.test_remediation_worker import request_for
    from evals.tests.test_source_epochs import manifest_for, register

    module = development_module()
    monkeypatch.delenv("TASK13_WORKER_NONCE", raising=False)
    legacy, agent, source = request_for(tmp_path, mode="disabled")
    (source / "worker.py").unlink()
    repository = Path(__file__).resolve().parents[2]
    files, entries = {}, {}
    worker_entries = WORKER_ENTRIES | set(extra_source_entries)
    for name in worker_entries | {"evals/remediation.py"}:
        content = (repository / name).read_bytes()
        entries[name] = sha256(content).hexdigest()
        if name in worker_entries and name != omit:
            target = source / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
            files[name] = entries[name]
    if wrong_entry:
        entries[wrong_entry] = "f" * 64
    receipt = {"source_commit": legacy.source_commit, "files": files}
    (source / "source_receipt.json").write_text(json.dumps(receipt), encoding="utf-8")
    budget = tmp_path / "budget/campaign.sqlite"
    SupplementBudgetAccount(
        budget, **{**legacy.budget_binding(), "source_sha256": "a" * 64}
    )
    controller = tmp_path / "controller"
    controller.mkdir()
    common = {
        "source_commit": legacy.source_commit,
        "config_sha256": legacy.config_sha256,
        "budget_path": str(budget.resolve()),
        "entrypoints": entries,
        "entrypoints_sha256": canonical_hash(entries),
    }
    if runtime_binding is not None:
        common["runtime_binding"] = runtime_binding
    register(budget, manifest_for(legacy.budget_identity, controller, **common))
    manifest = manifest_for(
        legacy.budget_identity,
        controller,
        1,
        **{**common, "source_sha256": canonical_hash(receipt)},
    )
    register(budget, manifest)
    inherited = {
        "response_model": "old",
        "fingerprint": "old-fp",
        "halt": "observable model version changed",
    }
    with sqlite3.connect(budget) as db:
        db.executemany("INSERT OR REPLACE INTO config VALUES (?,?)", inherited.items())
    identity = {
        "schema_version": "task13-model-identity-v1",
        "campaign_id": manifest["campaign_id"],
        "model_epoch_id": "model-0",
        "model_epoch_number": 0,
        "predecessor_model_epoch_id": None,
        "epoch_id": manifest["epoch_id"],
        "source_manifest_sha256": canonical_hash(manifest),
        "source_sha256": manifest["source_sha256"],
        "config_sha256": manifest["config_sha256"],
        "budget_identity": legacy.budget_identity,
        "budget_limits": manifest["budget_limits"],
        "budget_path": manifest["budget_path"],
        "controller_state_roots": manifest["controller_state_roots"],
        "expected_model": {
            "id": "model-0",
            "response_model": "approved",
            "fingerprint": "approved-fp",
        },
        "purposes": ["development"],
        "inherited_global": inherited,
        "halt_evidence_sha256": ["1" * 64, "2" * 64],
        "adoption_decision_sha256": "3" * 64,
        "authority_identity": "synthetic-independent-host",
    }
    if adopted:
        adopt(budget, identity)
    request = module.EpochDevelopmentRequest.model_validate(
        {
            **legacy.model_dump(mode="json"),
            "budget": CallBudget(max_model_calls=1).model_dump(mode="json"),
            "schema_version": "task13-remediation-worker-v4",
            "source_sha256": canonical_hash(receipt),
            "epoch_id": manifest["epoch_id"],
            "epoch_manifest_sha256": canonical_hash(manifest),
            "model_identity_binding": {
                "model_epoch_id": identity["model_epoch_id"],
                "model_identity_sha256": canonical_hash(identity),
            },
        }
    )
    return module, request, agent, source, budget, manifest


def preflight(module, request, agent, source, budget, manifest, *, worker=False):
    return module.validate_epoch_development_runtime(
        request,
        agent,
        source,
        budget,
        manifest["runtime_binding"],
        request.source_commit,
        worker=worker,
    )


def set_worker(monkeypatch, request, source, budget, manifest):
    from evals.tests.test_epoch_remediation import set_worker as regression_environment

    regression_environment(monkeypatch, request, source, budget, manifest)
    monkeypatch.setenv("TASK13_PHASE", "development")


def test_host_and_worker_admission_are_read_only_and_preserve_minimal_mount(
    tmp_path, monkeypatch
):
    args = development_inputs(tmp_path, monkeypatch)
    _, request, _, source, budget, manifest = args
    before = budget.read_bytes()
    assert preflight(*args) == manifest
    set_worker(monkeypatch, request, source, budget, manifest)
    assert preflight(*args, worker=True) == manifest
    assert not (source / "evals/remediation.py").exists()
    assert budget.read_bytes() == before


@pytest.mark.parametrize(
    "tamper",
    ["source", "model", "epoch", "runtime", "budget_prefix", "clone", "adoption"],
)
def test_source_model_runtime_and_original_account_drift_reject_read_only(
    tmp_path, monkeypatch, tamper
):
    args = list(development_inputs(tmp_path, monkeypatch, adopted=tamper != "adoption"))
    module, request, _, source, budget, manifest = args
    values = request.model_dump(mode="json")
    if tamper == "source":
        (source / "evals/adapters/epoch_development.py").write_text("# changed")
    elif tamper == "model":
        values["model_identity_binding"]["model_identity_sha256"] = "f" * 64
    elif tamper == "epoch":
        values["epoch_id"] = "synthetic-epoch-0"
    elif tamper == "runtime":
        args[-1] = deepcopy(manifest)
        args[-1]["runtime_binding"]["image_id"] = "sha256:" + "f" * 64
    elif tamper == "budget_prefix":
        with sqlite3.connect(budget) as db:
            db.execute("UPDATE reservations SET actual=0.9 WHERE rowid=1")
    elif tamper == "clone":
        clone = tmp_path / "clone.sqlite"
        shutil.copyfile(budget, clone)
        args[4] = clone
    args[1] = module.EpochDevelopmentRequest(**values)
    before = args[4].read_bytes()
    with pytest.raises((ValueError, RuntimeError)):
        preflight(*args)
    assert args[4].read_bytes() == before


@pytest.mark.parametrize("worker", [False, True])
@pytest.mark.parametrize(
    "missing",
    ["evals/adapters/epoch_development.py", "evals/adapters/model_identity_runtime.py"],
)
def test_every_required_entrypoint_must_be_exported(
    tmp_path, monkeypatch, worker, missing
):
    args = development_inputs(tmp_path, monkeypatch, omit=missing)
    if worker:
        set_worker(monkeypatch, args[1], args[3], args[4], args[5])
    with pytest.raises(ValueError, match="entrypoint"):
        preflight(*args, worker=worker)


def test_actual_controller_hash_is_checked_on_host(tmp_path, monkeypatch):
    args = development_inputs(tmp_path, monkeypatch, wrong_entry="evals/remediation.py")
    with pytest.raises(ValueError, match="controller entrypoint"):
        preflight(*args)


def test_adopted_model_cannot_cross_into_a_later_source_epoch(tmp_path, monkeypatch):
    from evals.tests.test_source_epochs import register

    args = list(development_inputs(tmp_path, monkeypatch))
    module, request, _, _, budget, manifest = args
    next_epoch = {
        **manifest,
        "epoch_id": "synthetic-epoch-2",
        "epoch_number": 2,
        "predecessor_epoch_id": manifest["epoch_id"],
    }
    register(budget, next_epoch)
    args[1] = module.EpochDevelopmentRequest.model_validate(
        {
            **request.model_dump(mode="json"),
            "epoch_id": next_epoch["epoch_id"],
            "epoch_manifest_sha256": canonical_hash(next_epoch),
        }
    )
    args[-1] = next_epoch
    before = budget.read_bytes()
    with pytest.raises(ValueError, match="identity"):
        preflight(*args)
    assert budget.read_bytes() == before


def test_v3_keeps_its_existing_minimal_worker_dependencies(tmp_path, monkeypatch):
    import builtins

    from evals.tests.test_epoch_remediation import epoch_inputs
    from evals.tests.test_epoch_remediation import preflight as v3_preflight

    args = epoch_inputs(tmp_path, monkeypatch)
    original = builtins.__import__

    def existing_source_import(name, *args, **kwargs):
        assert name != "evals.adapters.epoch_development", (
            "v3 must not require the v4 module"
        )
        return original(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", existing_source_import)
    assert v3_preflight(*args) == args[-1]


@pytest.mark.asyncio
@pytest.mark.parametrize("entry", ["dedicated", "shared"])
@pytest.mark.parametrize(
    "tamper", ["pid", "nonce", "phase", "runtime", "host_budget", "model", "source"]
)
async def test_worker_admission_precedes_key_model_and_services(
    tmp_path, monkeypatch, entry, tamper
):
    from evals.adapters import remediation_worker as worker

    module, request, agent, source, budget, manifest = development_inputs(
        tmp_path, monkeypatch
    )
    set_worker(monkeypatch, request, source, budget, manifest)
    monkeypatch.setenv("DEEPSEEK_API_KEY", "synthetic-never-read")
    if tamper == "pid":
        monkeypatch.setattr(os, "getpid", lambda: 2)
    elif tamper == "nonce":
        monkeypatch.delenv("TASK13_WORKER_NONCE")
    elif tamper == "phase":
        monkeypatch.setenv("TASK13_PHASE", "formal")
    elif tamper == "runtime":
        monkeypatch.setenv("TASK13_RUNTIME_BINDING", "{}")
    elif tamper == "host_budget":
        monkeypatch.setenv("TASK13_EPOCH_HOST_BUDGET_PATH", "other.sqlite")
    elif tamper == "model":
        request.model_identity_binding.model_identity_sha256 = "f" * 64
    else:
        (source / "evals/adapters/epoch_development.py").write_text("# changed")

    def forbidden(*args, **kwargs):
        pytest.fail("invalid admission reached model/service construction")

    class Secrets(dict):
        def get(self, key, *args):
            assert key != "DEEPSEEK_API_KEY", "credential read before admission"
            return super().get(key, *args)

    monkeypatch.setattr(os, "environ", Secrets(os.environ))
    monkeypatch.setattr(worker, "make_model", forbidden)
    monkeypatch.setattr(worker, "case_environment", forbidden)
    with pytest.raises((ValueError, PermissionError)):
        await (
            module.run_epoch_development
            if entry == "dedicated"
            else worker.run_remediation
        )(request, agent)


@pytest.mark.asyncio
@pytest.mark.parametrize("valid", [True, False])
async def test_v4_real_analysis_chain_only_charges_development_and_caps_attempts(
    tmp_path, monkeypatch, valid
):
    from evals.adapters import remediation_worker as worker
    from scripts import task13_worker_runtime as runtime

    _, request, agent, source, budget, manifest = development_inputs(
        tmp_path, monkeypatch
    )
    set_worker(monkeypatch, request, source, budget, manifest)
    output = tmp_path / "output"
    output.mkdir()
    monkeypatch.setenv("TASK13_OUTPUT_DIR", str(output))
    monkeypatch.setenv("DEEPSEEK_API_KEY", "synthetic-never-sent")
    payloads = []

    @contextmanager
    def environment(spec, seed):
        yield SimpleNamespace(incident_id="synthetic", sessions=None)

    async def probe(*args):
        return {"status": "passed", "latency_ms": 0}

    async def forbidden(*args, **kwargs):
        pytest.fail("analysis-only request reached regression/respond chain")

    def respond(http_request):
        payload = json.loads(http_request.content)
        payloads.append(payload)
        state = json.loads(payload["messages"][-1]["content"])
        from evals.tests.test_remediation_worker import analysis_answer

        answer = analysis_answer(state) if valid else {"diagnosis": None}
        return httpx.Response(
            200,
            json={
                "id": "synthetic",
                "model": "approved",
                "system_fingerprint": "approved-fp",
                "usage": {"prompt_tokens": 20, "completion_tokens": 5},
                "choices": [
                    {
                        "finish_reason": "stop",
                        "message": {"content": json.dumps(answer)},
                    }
                ],
            },
        )

    factory = worker.make_model
    monkeypatch.setattr(
        worker,
        "make_model",
        lambda *a, **kw: factory(*a, transport=httpx.MockTransport(respond), **kw),
    )
    monkeypatch.setattr(worker, "case_environment", environment)
    monkeypatch.setattr(worker, "run_service_probe", probe)
    monkeypatch.setattr(worker, "export_tool_ledger", lambda _: [])
    monkeypatch.setattr(worker, "run_case", forbidden)
    result = await runtime._invoke_adapter(
        runtime._worker_request(request.model_dump(mode="json")), agent
    )
    assert result.execution_status == ("completed" if valid else "failed"), (
        result.errors
    )
    assert result.product_status == "analysis_only"
    assert len(payloads) == len(result.model_ledger) == (1 if valid else 3)
    assert result.resources["model_logical_calls"] == 1
    assert all(row["role"] == "analyze" for row in result.model_ledger)
    if valid:
        assert result.diagnostic_snapshot["sealed_after"] == "analyze"
        assert result.diagnostic_snapshot["diagnosis"]["verdict"] == "benign"
    with sqlite3.connect(budget) as db:
        rows = db.execute(
            "SELECT r.phase,s.purpose,s.role FROM supplement_requests s JOIN reservations r ON r.id=s.reservation_id"
        ).fetchall()
    assert rows == [("development", "development", "analyze")] * len(payloads)
