"""Synthetic-only regression epoch dispatch; never opens a paid transport."""

import importlib
import importlib.util
import json
import os
import sqlite3
from copy import deepcopy
from hashlib import sha256
from pathlib import Path

import httpx
import pytest
from pydantic import ValidationError

from evals.adapters.remediation_contracts import RemediationRequest
from evals.contracts import AdapterResult, canonical_hash
from evals.tests.test_remediation import request_values


def epoch_module():
    assert importlib.util.find_spec("evals.adapters.epoch_remediation") is not None, (
        "regression needs a separate strict epoch request and runtime preflight"
    )
    return importlib.import_module("evals.adapters.epoch_remediation")


def test_explicit_epoch_request_keeps_v2_unmodified_and_binds_original_budget():
    module = epoch_module()
    values = request_values("regression")
    legacy = RemediationRequest(**values)
    request = module.EpochRemediationRequest(
        **values, epoch_id="synthetic-epoch-1", epoch_manifest_sha256="e" * 64
    )
    assert request.schema_version == "task13-remediation-worker-v3"
    assert request.budget_binding() == {
        **legacy.budget_binding(),
        "epoch_id": "synthetic-epoch-1",
    }
    assert request.worker_spec() == legacy.worker_spec()
    assert "epoch_id" not in legacy.model_dump(mode="json")
    with pytest.raises(ValidationError):
        RemediationRequest(**values, epoch_id=request.epoch_id)
    for field in ("epoch_id", "epoch_manifest_sha256"):
        missing = request.model_dump(mode="json")
        missing.pop(field)
        with pytest.raises(ValidationError):
            module.EpochRemediationRequest.model_validate(missing)


@pytest.mark.parametrize("purpose", ["development", "f8"])
def test_epoch_schema_never_reopens_development_or_other_purposes(purpose):
    module = epoch_module()
    with pytest.raises(ValidationError):
        module.EpochRemediationRequest(
            **{**request_values("regression"), "purpose": purpose},
            epoch_id="synthetic-epoch-1",
            epoch_manifest_sha256="e" * 64,
        )


WORKER_ENTRIES = {
    "scripts/task13_worker_runtime.py",
    "evals/adapters/epoch_remediation.py",
    "evals/adapters/remediation_worker.py",
    "evals/adapters/remediation_contracts.py",
    "evals/adapters/budget_v2.py",
    "evals/adapters/source_epochs.py",
}


def epoch_inputs(tmp_path, monkeypatch, *, omit=None, wrong_entry=None):
    from evals.adapters.budget_v2 import SupplementBudgetAccount
    from evals.tests.test_remediation_worker import request_for
    from evals.tests.test_source_epochs import manifest_for, register

    monkeypatch.delenv("TASK13_WORKER_NONCE", raising=False)
    module = epoch_module()
    legacy, agent, source = request_for(tmp_path, purpose="regression")
    (source / "worker.py").unlink()
    repository = Path(__file__).resolve().parents[2]
    files = {}
    entries = {}
    for name in WORKER_ENTRIES | {"evals/remediation.py"}:
        content = (repository / name).read_bytes()
        entries[name] = sha256(content).hexdigest()
        if name in WORKER_ENTRIES and name != omit:
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
    register(budget, manifest_for(legacy.budget_identity, controller, **common))
    manifest = manifest_for(
        legacy.budget_identity,
        controller,
        1,
        **{**common, "source_sha256": canonical_hash(receipt)},
    )
    register(budget, manifest)
    request = module.EpochRemediationRequest.model_validate(
        {
            **legacy.model_dump(mode="json"),
            "schema_version": "task13-remediation-worker-v3",
            "source_sha256": canonical_hash(receipt),
            "epoch_id": manifest["epoch_id"],
            "epoch_manifest_sha256": canonical_hash(manifest),
        }
    )
    return module, request, agent, source, budget, manifest


def preflight(module, request, agent, source, budget, manifest, *, worker=False):
    assert hasattr(module, "validate_epoch_runtime"), (
        "read-only epoch preflight is required"
    )
    return module.validate_epoch_runtime(
        request,
        agent,
        source,
        budget,
        manifest["runtime_binding"],
        request.source_commit,
        worker=worker,
    )


def set_worker(monkeypatch, request, source, budget, manifest):
    monkeypatch.setattr(os, "getpid", lambda: 1)
    monkeypatch.setenv("TASK13_WORKER_NONCE", "synthetic-inspected-nonce")
    monkeypatch.setenv("TASK13_PHASE", "formal")
    monkeypatch.setenv("TASK13_SOURCE_DIR", str(source))
    monkeypatch.setenv("TASK13_SOURCE_COMMIT", request.source_commit)
    monkeypatch.setenv("TASK13_BUDGET_DB", str(budget))
    monkeypatch.setenv(
        "TASK13_RUNTIME_BINDING", json.dumps(manifest["runtime_binding"])
    )
    monkeypatch.setenv("TASK13_EPOCH_HOST_BUDGET_PATH", manifest["budget_path"])


def test_registered_latest_epoch_preflight_is_read_only_and_keeps_host_files_unmounted(
    tmp_path, monkeypatch
):
    args = epoch_inputs(tmp_path, monkeypatch)
    _module, request, _agent, source, budget, manifest = args
    before = budget.read_bytes()
    assert preflight(*args) == manifest
    set_worker(monkeypatch, request, source, budget, manifest)
    assert preflight(*args, worker=True) == manifest
    assert not (source / "evals/remediation.py").exists()
    assert budget.read_bytes() == before


@pytest.mark.parametrize(
    "field",
    [
        "epoch_id",
        "epoch_manifest_sha256",
        "source_sha256",
        "config_sha256",
        "source_commit",
        "budget_identity",
    ],
)
def test_wrong_or_retired_epoch_binding_is_rejected_read_only(
    tmp_path, monkeypatch, field
):
    args = list(epoch_inputs(tmp_path, monkeypatch))
    patch = {
        "epoch_id": "synthetic-epoch-0",
        "epoch_manifest_sha256": "f" * 64,
        "source_sha256": "f" * 64,
        "config_sha256": "f" * 64,
        "source_commit": "f" * 40,
        "budget_identity": {**args[1].budget_identity, "baseline_sha256": "f" * 64},
    }
    args[1] = args[0].EpochRemediationRequest.model_validate(
        {
            **args[1].model_dump(mode="json"),
            field: patch[field],
        }
    )
    before = args[4].read_bytes()
    with pytest.raises(ValueError):
        preflight(*args)
    assert args[4].read_bytes() == before


@pytest.mark.parametrize(
    "field",
    [
        "image_id",
        "dependencies_lock_sha256",
        "dependencies_tree_sha256",
        "knowledge_sha256",
        "controller_manifest_sha256",
    ],
)
def test_runtime_binding_drift_is_rejected(tmp_path, monkeypatch, field):
    module, request, agent, source, budget, manifest = epoch_inputs(
        tmp_path, monkeypatch
    )
    runtime = {**manifest["runtime_binding"], field: "f" * 64}
    with pytest.raises(ValueError):
        module.validate_epoch_runtime(
            request, agent, source, budget, runtime, request.source_commit
        )


@pytest.mark.parametrize(
    "tamper", ["missing_budget", "cloned_budget", "agent", "source"]
)
def test_actual_inputs_and_original_budget_path_are_required(
    tmp_path, monkeypatch, tamper
):
    args = list(epoch_inputs(tmp_path, monkeypatch))
    if tamper == "missing_budget":
        args[4] = tmp_path / "nonexistent.sqlite"
    elif tamper == "cloned_budget":
        clone = tmp_path / "cloned.sqlite"
        clone.write_bytes(args[4].read_bytes())
        args[4] = clone
    elif tamper == "agent":
        (args[2] / "events.jsonl").write_bytes(b"changed")
    else:
        (args[3] / "evals/adapters/source_epochs.py").write_bytes(b"changed")
    with pytest.raises(ValueError):
        preflight(*args)


def test_host_controller_entrypoints_and_worker_subset_are_required(
    tmp_path, monkeypatch
):
    args = epoch_inputs(tmp_path, monkeypatch, wrong_entry="evals/remediation.py")
    with pytest.raises(ValueError, match="entrypoint|controller"):
        preflight(*args)


def test_worker_requires_every_registered_worker_entrypoint(tmp_path, monkeypatch):
    args = epoch_inputs(
        tmp_path, monkeypatch, omit="evals/adapters/remediation_worker.py"
    )
    set_worker(monkeypatch, args[1], args[3], args[4], args[5])
    with pytest.raises(ValueError, match="entrypoint"):
        preflight(*args, worker=True)


@pytest.mark.asyncio
@pytest.mark.parametrize("tamper", ["pid", "nonce", "phase", "runtime", "host_budget"])
async def test_worker_rejects_before_existing_runner_or_model(
    tmp_path, monkeypatch, tamper
):
    module, request, agent, source, budget, manifest = epoch_inputs(
        tmp_path, monkeypatch
    )
    set_worker(monkeypatch, request, source, budget, manifest)
    assert hasattr(module, "run_epoch_remediation"), (
        "dedicated epoch runner is required"
    )
    from evals.adapters import remediation_worker

    calls = []

    async def forbidden(*args):
        calls.append(args)
        raise AssertionError("invalid preflight reached model/service runner")

    monkeypatch.setattr(remediation_worker, "run_remediation", forbidden)
    if tamper == "pid":
        monkeypatch.setattr(os, "getpid", lambda: 2)
    elif tamper == "nonce":
        monkeypatch.delenv("TASK13_WORKER_NONCE")
    elif tamper == "phase":
        monkeypatch.setenv("TASK13_PHASE", "development")
    elif tamper == "host_budget":
        monkeypatch.setenv(
            "TASK13_EPOCH_HOST_BUDGET_PATH", str(tmp_path / "clone.sqlite")
        )
    else:
        monkeypatch.setenv("TASK13_RUNTIME_BINDING", "{}")
    with pytest.raises((ValueError, PermissionError)):
        await module.run_epoch_remediation(request, agent)
    assert calls == []


@pytest.mark.asyncio
async def test_epoch_worker_reuses_real_runner_after_security_checks(
    tmp_path, monkeypatch
):
    from evals.adapters import remediation_worker

    module, request, agent, source, budget, manifest = epoch_inputs(
        tmp_path, monkeypatch
    )
    set_worker(monkeypatch, request, source, budget, manifest)
    monkeypatch.setenv("DEEPSEEK_API_KEY", "synthetic-never-sent")
    calls = []

    original_factory = remediation_worker.make_model

    def no_http(_request):
        pytest.fail("preflight test must not send HTTP")

    monkeypatch.setattr(
        remediation_worker,
        "make_model",
        lambda *args, **kwargs: original_factory(
            *args,
            transport=httpx.MockTransport(no_http),
            **kwargs,
        ),
    )

    async def case(spec, actual_agent, *, model_factory):
        assert spec == request.worker_spec() and actual_agent == agent
        # Exercise the real unchanged budget/model constructor; no HTTP is made.
        model = model_factory(spec, "formal")
        assert model.account.request_binding()["epoch_id"] == request.epoch_id
        calls.append(spec.run_id)
        return AdapterResult()

    monkeypatch.setattr(remediation_worker, "run_case", case)
    assert (
        await module.run_epoch_remediation(request, agent)
    ).execution_status == "completed"
    assert calls == [request.run_id]
    with sqlite3.connect(budget) as db:
        assert db.execute("SELECT COUNT(*) FROM supplement_requests").fetchone()[0] == 0


EPOCH_BINDING = {"epoch_id": "synthetic-epoch-1", "epoch_manifest_sha256": "e" * 64}


def epoch_bundle():
    from evals import remediation
    from evals.tests.test_remediation import budget_config, registration

    return remediation.prepare_bundle(
        registration(),
        source_commit="a" * 40,
        source_sha256="b" * 64,
        config=budget_config(),
        epoch_binding=EPOCH_BINDING,
    )


def test_explicit_v3_bundle_preserves_all_fixed_slots_and_default_v2_bytes():
    from evals import remediation
    from evals.tests.test_remediation import budget_config, registration

    legacy = remediation.prepare_bundle(
        registration(),
        source_commit="a" * 40,
        source_sha256="b" * 64,
        config=budget_config(),
    )
    assert (
        canonical_hash(legacy)
        == "0cfe7197ee7506a11429aa72bf0da7218f4ee97953dc961b6a631a542b517e42"
    )
    assert canonical_hash(RemediationRequest(**request_values())) == (
        "3147bfcd7e2f7e3e404a5daeb05b4df622392497003575f5a253352df53a9a32"
    )
    bundle = epoch_bundle()
    assert bundle["schema_version"] == "task13-remediation-bundle-v3"
    assert all(bundle[key] == value for key, value in EPOCH_BINDING.items())
    requests = remediation.validate_bundle(bundle)
    assert len(requests) == 176
    for before, after, request in zip(
        legacy["rows"], bundle["rows"], requests, strict=True
    ):
        assert before["slot_id"] == after["slot_id"]
        assert request.schema_version == "task13-remediation-worker-v3"
        assert {
            k: v
            for k, v in after["request"].items()
            if k not in {"schema_version", *EPOCH_BINDING}
        } == {k: v for k, v in before["request"].items() if k != "schema_version"}


@pytest.mark.parametrize(
    "mutation",
    [
        "epoch",
        "manifest",
        "mixed_schema",
        "missing_epoch",
        "purpose",
        "config",
        "source",
        "order",
        "group",
        "model",
        "seed",
        "budget",
        "input",
    ],
)
def test_v3_bundle_rejects_epoch_or_fixed_policy_drift(mutation):
    from evals import remediation

    bundle = epoch_bundle()
    request = bundle["rows"][0]["request"]
    if mutation == "epoch":
        bundle["epoch_id"] = "other-epoch"
    elif mutation == "manifest":
        request["epoch_manifest_sha256"] = "f" * 64
    elif mutation == "mixed_schema":
        request["schema_version"] = "task13-remediation-worker-v2"
    elif mutation == "missing_epoch":
        bundle.pop("epoch_id")
    elif mutation == "purpose":
        bundle["purpose"] = "development"
    elif mutation == "config":
        bundle["config"]["changed"] = True
    elif mutation == "source":
        request["source_sha256"] = "f" * 64
    elif mutation == "order":
        bundle["rows"].reverse()
    elif mutation == "group":
        request["group"] = "B3"
    elif mutation == "model":
        request["model"]["max_tokens"] = 512
    elif mutation == "seed":
        request["seed"]["knowledge_top_k"] = 1
    elif mutation == "budget":
        request["budget"]["max_model_calls"] = 1
    else:
        bundle["rows"][0]["input_hashes"]["events.jsonl"] = "f" * 64
    bundle["bundle_sha256"] = canonical_hash(
        {key: value for key, value in bundle.items() if key != "bundle_sha256"}
    )
    # Reversing complete adjacent pairs is not intrinsically invalid in v2;
    # v3 explicitly binds the registered order hash as well.
    with pytest.raises((ValueError, KeyError)):
        remediation.validate_bundle(bundle)


@pytest.mark.parametrize(
    "epoch_binding",
    [
        {},
        {"epoch_id": "synthetic-epoch-1"},
        {**EPOCH_BINDING, "authority": "self-approved"},
    ],
)
def test_epoch_preparation_requires_complete_explicit_binding(epoch_binding):
    from evals import remediation
    from evals.tests.test_remediation import budget_config, registration

    with pytest.raises(ValueError):
        remediation.prepare_bundle(
            registration(),
            source_commit="a" * 40,
            source_sha256="b" * 64,
            config=budget_config(),
            epoch_binding=epoch_binding,
        )


def execution_epoch_bundle(tmp_path):
    from evals.tests.test_remediation import setup_execution

    module, old, agent = setup_execution(tmp_path)
    # Same original registration, with the first pair's actual observable bytes.
    from evals.tests.test_remediation import registration

    registered = registration()
    for row in registered["rows"][:2]:
        row["input_hashes"] = deepcopy(old["rows"][0]["input_hashes"])
    bundle = module.prepare_bundle(
        registered,
        source_commit=old["source_commit"],
        source_sha256=old["source_sha256"],
        config=old["config"],
        epoch_binding=EPOCH_BINDING,
    )
    return module, bundle, agent


def epoch_gate(bundle):
    from evals.tests.test_remediation import gate_for

    return {
        **gate_for(bundle),
        **EPOCH_BINDING,
        "schema_version": "task13-v3-execution-gate-v1",
    }


def test_epoch_execution_keeps_external_admission_unknown_stop_and_no_replay(tmp_path):
    module, bundle, _ = execution_epoch_bundle(tmp_path)
    calls = []

    async def uncertain(request, agent):
        assert request.epoch_id == EPOCH_BINDING["epoch_id"]
        calls.append(request.slot_id)
        raise ConnectionError("synthetic dispatch uncertainty")

    options = {
        "case_roots": {"ait": tmp_path / "cases"},
        "offline_worker": uncertain,
        "row_limit": 1,
    }
    with pytest.raises(PermissionError):
        module.execute_bundle(bundle, tmp_path / "outputs", **options)
    options["admitter"] = lambda _identity: epoch_gate(bundle)
    first = module.execute_bundle(bundle, tmp_path / "outputs", **options)
    second = module.execute_bundle(bundle, tmp_path / "outputs", **options)
    assert first["counts"]["unknown"] == second["counts"]["unknown"] == 1
    assert calls == [bundle["rows"][0]["slot_id"]]


@pytest.mark.parametrize(
    "patch",
    [
        {"schema_version": "task13-v2-execution-gate-v1"},
        {"epoch_id": "other"},
        {"epoch_manifest_sha256": "f" * 64},
        {"scope": "real_execution"},
    ],
)
def test_epoch_execution_requires_explicit_matching_scope_and_epoch_gate(
    tmp_path, patch
):
    module, bundle, _ = execution_epoch_bundle(tmp_path)

    async def forbidden(*args):
        pytest.fail("invalid epoch gate dispatched worker")

    with pytest.raises(PermissionError):
        module.execute_bundle(
            bundle,
            tmp_path / "outputs",
            case_roots={"ait": tmp_path / "cases"},
            offline_worker=forbidden,
            row_limit=1,
            admitter=lambda _identity: {**epoch_gate(bundle), **patch},
        )
    assert not list((tmp_path / "outputs").glob("regression-*/started.json"))


def test_old_request_cannot_bind_new_source_or_silently_select_an_epoch(
    tmp_path, monkeypatch
):
    from evals.adapters.remediation_worker import make_model

    module, request, _, _, budget, _ = epoch_inputs(tmp_path, monkeypatch)
    values = request.model_dump(mode="json")
    values.pop("epoch_id")
    values.pop("epoch_manifest_sha256")
    values["schema_version"] = "task13-remediation-worker-v2"
    legacy = RemediationRequest.model_validate(values)
    before = budget.read_bytes()
    with pytest.raises(ValueError, match="frozen|configuration|binding"):
        make_model(legacy, budget, "formal")
    assert budget.read_bytes() == before
    assert (
        module.EpochRemediationRequest.model_validate(request).epoch_id
        == request.epoch_id
    )


def test_missing_epoch_registration_is_not_created_by_preflight(tmp_path, monkeypatch):
    from evals.tests.test_remediation_worker import request_for

    module = epoch_module()
    legacy, agent, source = request_for(tmp_path, purpose="regression")
    request = module.EpochRemediationRequest.model_validate(
        {
            **legacy.model_dump(mode="json"),
            "schema_version": "task13-remediation-worker-v3",
            **EPOCH_BINDING,
        }
    )
    budget = tmp_path / "budget/campaign.sqlite"
    before = budget.read_bytes()
    with pytest.raises(ValueError, match="epoch"):
        module.validate_epoch_runtime(
            request, agent, source, budget, {}, request.source_commit
        )
    assert budget.read_bytes() == before
    with sqlite3.connect(budget) as db:
        assert (
            db.execute(
                "SELECT name FROM sqlite_master WHERE name='supplement_source_epochs'"
            ).fetchall()
            == []
        )


def test_epoch_bundle_preparation_cannot_reopen_original36(tmp_path):
    from evals import remediation
    from evals.tests.test_remediation import budget_config, development_registration

    with pytest.raises(ValueError, match="regression"):
        remediation.prepare_bundle(
            development_registration(),
            source_commit="a" * 40,
            source_sha256="b" * 64,
            config=budget_config(),
            epoch_binding=EPOCH_BINDING,
        )


def test_epoch_execution_preserves_input_and_campaign_mutation_stop(tmp_path):
    module, bundle, agent = execution_epoch_bundle(tmp_path)
    calls = []

    async def completed(request, agent):
        calls.append(request.slot_id)
        return AdapterResult()

    options = {
        "case_roots": {"ait": tmp_path / "cases"},
        "offline_worker": completed,
        "row_limit": 1,
        "admitter": lambda _identity: epoch_gate(bundle),
    }
    first = module.execute_bundle(bundle, tmp_path / "outputs", **options)
    assert first["counts"]["completed"] == 1
    result = tmp_path / "outputs" / bundle["rows"][0]["slot_id"] / "result.json"
    original = result.read_bytes()
    (agent / "events.jsonl").write_bytes(b"changed")
    with pytest.raises(ValueError, match="changed|hash differs"):
        module.execute_bundle(bundle, tmp_path / "outputs", **options)
    changed = deepcopy(bundle)
    changed["epoch_id"] = "different-epoch"
    for row in changed["rows"]:
        row["request"]["epoch_id"] = changed["epoch_id"]
    changed["bundle_sha256"] = canonical_hash(
        {k: v for k, v in changed.items() if k != "bundle_sha256"}
    )
    with pytest.raises(PermissionError, match="scope changed"):
        module.execute_bundle(changed, tmp_path / "outputs", **options)
    assert calls == [bundle["rows"][0]["slot_id"]]
    assert result.read_bytes() == original


def test_original36_v2_request_snapshot_roundtrips_without_changing_raw_bytes():
    from evals.remediation import validate_bundle

    # This optional archival check reads the approved original artifact. The
    # portable deterministic v2 snapshot above always runs, including in CI.
    repository = Path(__file__).resolve().parents[2]
    artifact = (
        repository.parents[1]
        / "data/task13/supplements/task13-repair-202610-v2/development"
        / "preflight-b1666d38d5fc0467102166beafe229d87f826539/bundle36.json"
    )
    if not artifact.is_file():
        pytest.skip("original immutable 36-request archive is not present")
    raw = artifact.read_bytes()
    assert sha256(raw).hexdigest() == (
        "25b5eed9f76ba53c3b94d3df2eae8d31a7c5206f039ce65d26c2c898ba4ff6e8"
    )
    bundle = json.loads(raw)
    requests = validate_bundle(bundle)
    assert len(requests) == 36
    assert [request.model_dump(mode="json") for request in requests] == [
        row["request"] for row in bundle["rows"]
    ]
    assert canonical_hash([row["request"] for row in bundle["rows"]]) == (
        "21a7eb8770ab1004044e65796a854418b90db95cf1414242d9646297a9a183f1"
    )
    assert artifact.read_bytes() == raw
