"""Explicitly free regression-host fixtures; no real consent, models or budget."""

from __future__ import annotations

import asyncio
import importlib
import importlib.util
import json
from copy import deepcopy
from datetime import timedelta
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace

import pytest

from evals.contracts import CallBudget, ModelConfig, SeedPolicy, canonical_hash


def module():
    assert importlib.util.find_spec("scripts.task13_regression") is not None, (
        "a frozen existing-only regression host is required"
    )
    return importlib.import_module("scripts.task13_regression")


def pin(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = json.dumps(value, ensure_ascii=False).encode()
    path.write_bytes(raw)
    return {"path": str(path.resolve()), "sha256": sha256(raw).hexdigest()}


@pytest.fixture
def fixture(tmp_path):
    m = module()
    from evals.e_planning import planning_requests
    from evals.e_timing import ETimingCampaign, build_e_timing_registration
    from evals.remediation import prepare_bundle
    from evals.tests.test_e_timing import Clock, admit, lifecycle, value_for, verify
    from evals.tests.test_e_timing_replicates import approved_source, registration
    from evals.tests.test_remediation import registration as regression_registration

    clock = Clock()
    timing_reg = registration(tmp_path)
    planning = deepcopy(timing_reg["planning_registration"])
    reg = regression_registration()
    for row in reg["rows"][:2]:
        row["case_id"] = planning["source"]["case_id"]
        row["slot_id"] = (
            "regression-" + canonical_hash([row["case_id"], row["group"]])[:24]
        )
    reg["order_sha256"] = canonical_hash(
        [(row["case_id"], row["group"]) for row in reg["rows"]]
    )
    roots = {dataset: tmp_path / dataset for dataset in ("ait", "dedale")}
    artifacts = {}
    for row in reg["rows"][::2]:
        agent = roots[row["dataset"]] / row["case_id"] / "agent"
        agent.mkdir(parents=True)
        events = b'{"event":"free synthetic data"}\n'
        (agent / "events.jsonl").write_bytes(events)
        manifest = {
            "case_id": row["case_id"],
            "events_file": "events.jsonl",
            "events_sha256": sha256(events).hexdigest(),
        }
        pin(agent / "manifest.json", manifest)
        hashes = {
            name: sha256((agent / name).read_bytes()).hexdigest()
            for name in ("manifest.json", "events.jsonl")
        }
        artifacts[row["case_id"]] = {
            "agent/" + name: digest for name, digest in hashes.items()
        }
    for row in reg["rows"]:
        row["input_hashes"] = {
            key.removeprefix("agent/"): value
            for key, value in artifacts[row["case_id"]].items()
        }
    code = Path(m.__file__).resolve()
    code_hash = sha256(code.read_bytes()).hexdigest()
    source_files = {str(code): code_hash}
    source_receipt = {
        "source_commit": "a" * 40,
        "files": {"scripts/task13_regression.py": code_hash},
    }
    source_sha = canonical_hash(source_receipt)
    budget_identity = deepcopy(planning["epoch_binding"]["budget_identity"])
    budget_identity.update(baseline_count=3350, baseline_max_rowid=3350)
    core = {
        "model": ModelConfig().model_dump(mode="json"),
        "seed": SeedPolicy().model_dump(mode="json"),
        "budget": CallBudget().model_dump(mode="json"),
        "budget_identity": budget_identity,
        "active_budget_path": str(tmp_path / "original-budget/campaign.sqlite"),
        "f8_plan_sha256": "f" * 64,
        "original_observed_model_binding": {
            "response_model": "deepseek-flash",
            "fingerprint": "original-fingerprint",
        },
    }
    planning["core_config"] = deepcopy(core)
    planning["core_config_sha256"] = canonical_hash(core)
    planning["epoch_binding"].update(
        source_sha256=source_sha, budget_identity=budget_identity
    )
    planning["budget_source_receipt_sha256"] = source_sha
    requests = planning_requests(planning)
    dispatch = {
        "schema_version": "task13-e-planning-dispatch-registration-v1",
        "campaign_id": planning["campaign_id"],
        "registration_sha256": canonical_hash(planning),
        "authority_sha256": "4" * 64,
        "journal_path": str(tmp_path / "e-planning.sqlite"),
        "synthetic": True,
        "planning_slot_ids": [request.planning_slot_id for request in requests],
    }
    timing_reg = build_e_timing_registration(
        planning,
        source_files=source_files,
        f8_plan_sha256=core["f8_plan_sha256"],
        planning_dispatch_registration_receipt=dispatch,
    )
    store = ETimingCampaign(
        timing_reg,
        tmp_path / "synthetic-timing",
        execution_admitter=admit,
        approval_verifier=verify,
        worker_lifecycle_verifier=lifecycle,
        now=clock.now,
        monotonic_ns=clock.monotonic_ns,
    )

    async def trials():
        async def worker(request):
            clock.advance(1)
            return value_for(request)

        for index, trial in enumerate(timing_reg["trials"]):
            await store.run_trial(
                trial["trial_id"],
                approved_source(store, index, clock),
                run_worker=worker,
            )

    asyncio.run(trials())
    timing = store.export_timing_receipt()
    bundle = prepare_bundle(
        reg,
        source_commit="a" * 40,
        source_sha256=source_sha,
        config=core,
        epoch_binding={
            key: planning["epoch_binding"][key]
            for key in ("epoch_id", "epoch_manifest_sha256")
        },
    )
    selections = {}
    for dataset in roots:
        cases = [
            {"case_id": cid, "artifacts": hashes}
            for cid, hashes in artifacts.items()
            if cid.startswith(dataset + "-")
        ]
        selections[dataset] = {"split": "test", "cases": cases}
    admissions = {
        "ait": {
            "selection_sha256": "replace",
            "test_cases": [
                {
                    "case_id": row["case_id"],
                    "artifacts": {
                        name: {"current_sha256": digest, "relocated_sha256": digest}
                        for name, digest in row["artifacts"].items()
                    },
                }
                for row in selections["ait"]["cases"]
            ],
        },
        "dedale": {
            "task12_accepted": True,
            "status": "accepted_and_frozen",
            "selection": {},
        },
    }
    task12 = {}
    for dataset in roots:
        selection_pin = pin(tmp_path / f"{dataset}-selection.json", selections[dataset])
        if dataset == "ait":
            admissions[dataset]["selection_sha256"] = selection_pin["sha256"]
        else:
            admissions[dataset]["selection"]["sha256"] = selection_pin["sha256"]
        task12[f"{dataset}_selection"] = selection_pin
        task12[f"{dataset}_receipt"] = pin(
            tmp_path / f"{dataset}-admission.json", admissions[dataset]
        )
    report = {
        "exit_code": 0,
        "paid_calls": 0,
        "source_unchanged": True,
        "tests": [
            {"nodeid": "critical-safety-test", "when": "call", "outcome": "passed"}
        ],
    }
    report_pin = pin(tmp_path / "test-results.json", report)
    tests = {
        group: {
            "critical_tests": ["critical-safety-test"],
            "noncritical_skips": [],
            "evidence": report_pin,
        }
        for group in ("backend", "evals")
    }
    engineering = {
        "schema_version": "task13-regression-engineering-v1",
        "status": "passed",
        "source_commit": "a" * 40,
        "source_files_sha256": canonical_hash(source_files),
        "critical_skips": 0,
        "tests": tests,
        "task12": task12,
    }
    source_binding = {"git_head": "a" * 40, "files_sha256": source_receipt["files"]}
    gate_pins = {}
    for label, filename in (("R1", "r1-channel.json"), ("R2", "r2-isolation.json")):
        gate_pins[filename] = pin(
            tmp_path / filename,
            {
                "status": "passed",
                "gate": label,
                "created_at": clock.now().isoformat(),
                "source": source_binding,
                "paid_model_requests": 0,
                "cleanup_completed": True,
                "nonlocal_connect_attempts": 0,
                "model_config": core["model"],
            },
        )
    rag = {
        "schema_version": "task13-rag-gate-index-v2",
        "status": "passed",
        "created_at": clock.now().isoformat(),
        "paid_model_requests": 0,
        "source": source_binding,
        "gates": gate_pins,
    }
    price = {
        "schema_version": "task13-regression-model-price-v1",
        "status": "verified",
        "checked_at": clock.now().isoformat(),
        "valid_until": (clock.now() + timedelta(hours=1)).isoformat(),
        "model": core["model"],
        "observed_model_binding": core["original_observed_model_binding"],
        "checks": {str(i): True for i in range(8)},
        "evidence": [
            pin(tmp_path / "public-pricing-evidence.json", {"synthetic": True})
        ],
    }
    runtime = {
        "source_commit": "a" * 40,
        "source_dir": str(tmp_path / "export"),
        "budget_dir": str(tmp_path / "original-budget"),
        "phase": "formal",
        "budget_identity": budget_identity,
        "output_dir": str(tmp_path / "worker-output"),
    }
    values = {
        "registration": reg,
        "bundle": bundle,
        "core_config": core,
        "runtime_options": runtime,
        "source_receipt": source_receipt,
        "e_timing_receipt": timing,
        "rag_receipt": rag,
        "engineering_receipt": engineering,
        "model_price_receipt": price,
    }
    refs = {key: pin(tmp_path / f"{key}.json", value) for key, value in values.items()}
    timing_path = store.root / "timings" / (canonical_hash(timing) + ".json")
    refs["e_timing_receipt"] = {
        "path": str(timing_path.resolve()),
        "sha256": sha256(timing_path.read_bytes()).hexdigest(),
    }
    final = {
        "schema_version": "task13-regression-final-freeze-v1",
        "status": "frozen",
        "synthetic": True,
        "campaign_id": bundle["campaign_id"],
        **{
            key: bundle[key]
            for key in (
                "source_commit",
                "source_sha256",
                "config_sha256",
                "epoch_id",
                "epoch_manifest_sha256",
            )
        },
        "source_files": source_files,
        "bindings": {key: value["sha256"] for key, value in refs.items()},
    }
    refs["final_freeze"] = pin(tmp_path / "final_freeze.json", final)
    scope = {
        "schema_version": "task13-regression-scope-v1",
        "scope": m.SCOPE,
        "campaign_id": bundle["campaign_id"],
        "final_freeze_sha256": refs["final_freeze"]["sha256"],
        "bundle_sha256": bundle["bundle_sha256"],
        "registered_rows": 176,
        "deadline_at": (clock.now() + timedelta(hours=1)).isoformat(),
    }
    refs["scope_packet"] = pin(tmp_path / "scope.json", scope)
    decision = {
        "schema_version": "task13-regression-user-scope-decision-v1",
        "role": "user",
        "scope": m.SCOPE,
        "decision": "approved",
        "record_id": "synthetic-user-fixture",
        "text": "Synthetic separate regression scope fixture.",
        "decided_at": clock.now().isoformat(),
        "scope_packet_sha256": refs["scope_packet"]["sha256"],
    }
    refs["scope_decision"] = pin(tmp_path / "decision.json", decision)
    manifest = {
        "schema_version": "task13-regression-host-v1",
        "synthetic": True,
        "inputs": refs,
        "case_roots": {key: str(path) for key, path in roots.items()},
        "output_dir": str(tmp_path / "execution"),
        "deadline_at": scope["deadline_at"],
        "max_evidence_age_seconds": 3600,
    }
    calls = []

    async def worker(request, agent):
        calls.append(request.slot_id)
        return {"execution_status": "completed", "model_ledger": []}

    def runtime_check(*args):
        calls.append("runtime-check")

    dependencies = m.FreeDependencies(
        worker=worker, runtime_validator=runtime_check, now=clock.now
    )
    state = SimpleNamespace(
        module=m,
        root=tmp_path,
        manifest=manifest,
        values=values,
        final=final,
        scope=scope,
        decision=decision,
        dependencies=dependencies,
        clock=clock,
        calls=calls,
    )

    def host():
        binding = pin(tmp_path / "host.json", state.manifest)
        return m.RegressionHost(
            binding["path"], binding["sha256"], free_dependencies=dependencies
        )

    state.host = host
    return state


def test_missing_future_artifacts_are_pending_without_runtime(tmp_path):
    m = module()
    binding = pin(
        tmp_path / "future-host.json",
        {
            "schema_version": "task13-regression-host-v1",
            "synthetic": False,
            "inputs": {
                key: {"path": str(tmp_path / (key + ".json")), "sha256": "0" * 64}
                for key in m.INPUTS
            },
            "case_roots": {
                "ait": str(tmp_path / "ait"),
                "dedale": str(tmp_path / "dedale"),
            },
            "output_dir": str(tmp_path / "never-created"),
            "deadline_at": "2030-01-01T00:00:00Z",
            "max_evidence_age_seconds": 3600,
        },
    )
    host = m.RegressionHost(binding["path"], binding["sha256"])
    assert host.readiness()["status"] == "PENDING"
    assert host.status()["status"] == "PENDING"
    assert not (tmp_path / "never-created").exists()


def test_free_injection_requires_explicit_synthetic_manifest(fixture):
    f = fixture
    f.manifest["synthetic"] = False
    with pytest.raises(PermissionError, match="synthetic"):
        f.host()


def test_free_readiness_and_exact176_execution_reuses_existing_matrix(fixture):
    f = fixture
    host = f.host()
    assert host.readiness()["status"] == "verified"
    assert host.status()["counts"]["not_started"] == 176
    result = host.execute(row_limit=2)
    assert result["scope"] == "offline_contract_test"
    assert result["counts"]["completed"] == 2
    assert result["counts"]["not_started"] == 174
    assert [c for c in f.calls if c != "runtime-check"] == [
        r["slot_id"] for r in f.values["bundle"]["rows"][:2]
    ]
    host.execute(row_limit=1)
    assert len([c for c in f.calls if c != "runtime-check"]) == 3


@pytest.mark.parametrize(
    "fault",
    [
        "deadline",
        "pin",
        "core",
        "scope",
        "decision",
        "synthetic_timing",
        "timing_short",
        "rag",
        "critical",
        "price",
        "input",
        "source",
    ],
)
def test_each_admission_boundary_fails_before_free_worker(fixture, fault):
    f = fixture
    if fault == "deadline":
        f.clock.advance(4000)
    elif fault == "pin":
        Path(f.manifest["inputs"]["scope_decision"]["path"]).write_text("{}")
    elif fault == "input":
        first = f.values["registration"]["rows"][0]
        (
            Path(f.manifest["case_roots"]["ait"])
            / first["case_id"]
            / "agent/events.jsonl"
        ).write_bytes(b"changed")
    elif fault == "source":
        code = next(iter(f.final["source_files"]))
        f.final["source_files"][code] = "0" * 64
        f.manifest["inputs"]["final_freeze"] = pin(f.root / "bad-freeze.json", f.final)
    else:
        key = {
            "core": "core_config",
            "scope": "scope_packet",
            "decision": "scope_decision",
            "synthetic_timing": "e_timing_receipt",
            "timing_short": "e_timing_receipt",
            "rag": "rag_receipt",
            "critical": "engineering_receipt",
            "price": "model_price_receipt",
        }[fault]
        value = deepcopy(
            f.values.get(key, f.scope if key == "scope_packet" else f.decision)
        )
        if fault == "core":
            value["model"]["max_tokens"] = 8192
        elif fault == "scope":
            value["scope"] = "original36"
        elif fault == "decision":
            value["decision"] = "rejected"
        elif fault == "synthetic_timing":
            value["synthetic"] = False
        elif fault == "timing_short":
            value["trials"].pop()
        elif fault == "rag":
            value["paid_model_requests"] = 1
        elif fault == "critical":
            value["critical_skips"] = 1
        elif fault == "price":
            value["checks"]["0"] = False
        f.manifest["inputs"][key] = pin(f.root / f"bad-{key}.json", value)
        if key in f.final["bindings"]:
            f.final["bindings"][key] = f.manifest["inputs"][key]["sha256"]
            f.manifest["inputs"]["final_freeze"] = pin(
                f.root / "rebound-freeze.json", f.final
            )
            f.scope["final_freeze_sha256"] = f.manifest["inputs"]["final_freeze"][
                "sha256"
            ]
            f.manifest["inputs"]["scope_packet"] = pin(
                f.root / "rebound-scope.json", f.scope
            )
            f.decision["scope_packet_sha256"] = f.manifest["inputs"]["scope_packet"][
                "sha256"
            ]
            f.manifest["inputs"]["scope_decision"] = pin(
                f.root / "rebound-decision.json", f.decision
            )
    host = f.host()
    assert host.readiness()["status"] == "PENDING"
    with pytest.raises((ValueError, PermissionError, OSError)):
        host.execute(row_limit=1)
    assert not any(c != "runtime-check" for c in f.calls)


def test_started_unknown_stops_without_replay(fixture):
    f = fixture

    async def lost(request, agent):
        f.calls.append(request.slot_id)
        raise ConnectionError("Synthetic ambiguous dispatch")

    f.dependencies = f.module.FreeDependencies(
        worker=lost, runtime_validator=lambda *args: None, now=f.clock.now
    )
    binding = pin(f.root / "lost-host.json", f.manifest)
    host = f.module.RegressionHost(
        binding["path"], binding["sha256"], free_dependencies=f.dependencies
    )
    first = host.execute(row_limit=1)
    second = host.execute(row_limit=1)
    assert first["counts"]["unknown"] == second["counts"]["unknown"] == 1
    assert len(f.calls) == 1


def test_budget_refusal_stops_outer_loop_without_touching_later_slots(fixture):
    f = fixture

    async def exhausted(request, agent):
        f.calls.append(request.slot_id)
        return {"execution_status": "failed", "errors": [{"error_type": "BudgetLimit"}]}

    deps = f.module.FreeDependencies(
        worker=exhausted, runtime_validator=lambda *args: None, now=f.clock.now
    )
    binding = pin(f.root / "budget-host.json", f.manifest)
    host = f.module.RegressionHost(
        binding["path"], binding["sha256"], free_dependencies=deps
    )
    result = host.execute(row_limit=3)
    assert result["counts"]["failed"] == 1
    assert result["counts"]["not_started"] == 175
    assert len(f.calls) == 1


def test_restart_checks_existing_received_identity_without_rewriting_result(fixture):
    f = fixture
    host = f.host()
    host._free = (
        None  # Inspect the real read-only result boundary; dispatch is never called.
    )
    row = f.values["bundle"]["rows"][0]
    value = {
        "execution_status": "completed",
        "model_ledger": [
            {
                "http_status": 200,
                "response_model": "deepseek-flash",
                "raw_response": {"model": "deepseek-flash"},
            }
        ],
    }
    result = pin(Path(f.manifest["output_dir"]) / row["slot_id"] / "result.json", value)
    with pytest.raises(PermissionError, match="identity"):
        host._prior_results(f.values)
    assert sha256(Path(result["path"]).read_bytes()).hexdigest() == result["sha256"]
    assert not (Path(f.manifest["output_dir"]) / "model-runtime-halt.json").exists()


def test_actual_test_report_rejects_failed_and_skipped_critical_calls(fixture):
    f = fixture
    host = f.host()
    for outcome in ("failed", "skipped"):
        report = {
            "exit_code": 0,
            "paid_calls": 0,
            "source_unchanged": True,
            "tests": [{"nodeid": "critical", "when": "call", "outcome": outcome}],
        }
        spec = {
            "critical_tests": ["critical"],
            "noncritical_skips": [],
            "evidence": pin(f.root / f"critical-{outcome}.json", report),
        }
        with pytest.raises(PermissionError, match="critical"):
            host._test_report(spec, f.values)


def test_real_freeze_requires_actual_host_helper_source_coverage(fixture):
    f = fixture
    host = f.host()
    host._manifest["synthetic"] = False
    f.final["synthetic"] = False
    with pytest.raises(PermissionError, match="critical actual host helper"):
        host._fixed({**f.values, "final_freeze": f.final})


def test_real_freeze_accepts_minimal_worker_export_and_pinned_host_helpers(fixture):
    f = fixture
    host = f.host()
    root = Path(f.module.__file__).resolve().parents[1]
    files = {
        str(root / relative): sha256((root / relative).read_bytes()).hexdigest()
        for relative in f.module.HOST_ENTRIES | f.module.RAG_ENTRIES
    }
    # Host-only controllers must stay outside the worker's minimal export.
    source = deepcopy(f.values["source_receipt"])
    source["files"].pop(f.module.HOST_ENTRYPOINT)
    core = f.values["core_config"]
    old = f.values["bundle"]
    from evals.remediation import prepare_bundle

    bundle = prepare_bundle(
        f.values["registration"],
        source_commit=old["source_commit"],
        source_sha256=canonical_hash(source),
        config=core,
        epoch_binding={key: old[key] for key in ("epoch_id", "epoch_manifest_sha256")},
    )
    freeze = deepcopy(f.final)
    freeze.update(
        source_files=files, source_sha256=bundle["source_sha256"], synthetic=False
    )
    for key, value in (("source_receipt", source), ("bundle", bundle)):
        host._manifest["inputs"][key] = pin(f.root / f"minimal-{key}.json", value)
        freeze["bindings"][key] = host._manifest["inputs"][key]["sha256"]
    host._manifest["synthetic"] = False
    data = {
        **f.values,
        "source_receipt": source,
        "bundle": bundle,
        "final_freeze": freeze,
    }
    host._fixed(data)
    host._source_binding(
        {
            "git_head": bundle["source_commit"],
            "files_sha256": {
                relative: files[str(root / relative)]
                for relative in f.module.RAG_ENTRIES
            },
        },
        data,
    )
    data["final_freeze"]["source_files"].pop(str(root / "evals/e_timing.py"))
    with pytest.raises(PermissionError, match="critical actual host helper"):
        host._fixed(data)


def test_postreturn_missing_fingerprint_preserves_result_and_halts(fixture):
    f = fixture
    host = f.host()
    host._free = None  # Real result validation only; no provider/runtime call.
    row = f.values["bundle"]["rows"][0]
    value = {
        "execution_status": "completed",
        "model_ledger": [
            {
                "http_status": 200,
                "response_model": "deepseek-flash",
                "system_fingerprint": "original-fingerprint",
                "raw_response": {"model": "deepseek-flash"},
            }
        ],
    }
    result = pin(Path(f.manifest["output_dir"]) / row["slot_id"] / "result.json", value)
    with pytest.raises(PermissionError, match="identity"):
        host._received_model_guard(f.values, row)
    assert sha256(Path(result["path"]).read_bytes()).hexdigest() == result["sha256"]
    halt = json.loads(
        (Path(f.manifest["output_dir"]) / "model-runtime-halt.json").read_bytes()
    )
    assert halt["result"] == result


@pytest.mark.parametrize(
    "fault", ["response_only_budget", "changed_seed", "missing_seed"]
)
def test_rebound_formal_core_requires_standard_seed_and_budget(fixture, fault):
    from evals.remediation import prepare_bundle

    f = fixture
    host = f.host()
    core = deepcopy(f.values["core_config"])
    if fault == "response_only_budget":
        core["budget"]["max_model_calls"] = 1
    elif fault == "changed_seed":
        core["seed"]["max_events"] = 1
    else:
        core.pop("seed")
    old = f.values["bundle"]
    bundle = prepare_bundle(
        f.values["registration"],
        source_commit=old["source_commit"],
        source_sha256=old["source_sha256"],
        config=core,
        epoch_binding={key: old[key] for key in ("epoch_id", "epoch_manifest_sha256")},
    )
    freeze = deepcopy(f.final)
    for key, value in (("core_config", core), ("bundle", bundle)):
        host._manifest["inputs"][key] = pin(
            f.root / f"rebound-standard-{key}.json", value
        )
        freeze["bindings"][key] = host._manifest["inputs"][key]["sha256"]
    freeze["config_sha256"] = bundle["config_sha256"]
    with pytest.raises(PermissionError, match="configuration"):
        host._fixed(
            {**f.values, "bundle": bundle, "core_config": core, "final_freeze": freeze}
        )


def test_rebound_outer_epoch_cannot_admit_actual_old_e_sources(fixture):
    from evals.e_timing import build_e_timing_registration
    from evals.remediation import prepare_bundle

    f = fixture
    host = f.host()
    timing = deepcopy(f.values["e_timing_receipt"])
    branch_hash = canonical_hash([trial["branches"] for trial in timing["trials"]])
    planning = timing["planning_registration"]
    planning["epoch_binding"].update(
        epoch_id="different-unmeasured-epoch", epoch_manifest_sha256="9" * 64
    )
    dispatch = timing["planning_dispatch_registration_receipt"]
    dispatch["registration_sha256"] = canonical_hash(planning)
    timing["planning_registration_sha256"] = canonical_hash(planning)
    expected = build_e_timing_registration(
        planning,
        source_files=f.final["source_files"],
        f8_plan_sha256=f.values["core_config"]["f8_plan_sha256"],
        planning_dispatch_registration_receipt=dispatch,
    )
    timing["registration_sha256"] = canonical_hash(expected)
    old = f.values["bundle"]
    bundle = prepare_bundle(
        f.values["registration"],
        source_commit=old["source_commit"],
        source_sha256=old["source_sha256"],
        config=f.values["core_config"],
        epoch_binding={
            key: planning["epoch_binding"][key]
            for key in ("epoch_id", "epoch_manifest_sha256")
        },
    )
    path = f.root / "synthetic-timing/timings" / (canonical_hash(timing) + ".json")
    host._manifest["inputs"]["e_timing_receipt"] = pin(path, timing)
    assert branch_hash == canonical_hash(
        [trial["branches"] for trial in timing["trials"]]
    )
    with pytest.raises(PermissionError, match="planning|retained|source|binding"):
        host._timing(
            {
                **f.values,
                "final_freeze": f.final,
                "e_timing_receipt": timing,
                "bundle": bundle,
            }
        )


@pytest.mark.parametrize(
    "fault", ["missing_source", "changed_source", "slot", "resources", "approval"]
)
def test_timing_requires_original_source_blobs_and_exact_trial_binding(fixture, fault):
    f = fixture
    host = f.host()
    timing = deepcopy(f.values["e_timing_receipt"])
    binding = timing["trials"][0]["binding"]
    path = f.root / "synthetic-timing/sources" / (binding["source_sha256"] + ".json")
    if fault == "missing_source":
        path.unlink()
    elif fault == "changed_source":
        source = json.loads(path.read_bytes())
        source["planning_request"]["epoch_id"] = "changed-source-epoch"
        pin(path, source)
    else:
        key = {
            "slot": "planning_slot_id",
            "resources": "resources_sha256",
            "approval": "approval_id",
        }[fault]
        binding[key] = "substituted-binding"
        new_path = (
            f.root / "synthetic-timing/timings" / (canonical_hash(timing) + ".json")
        )
        host._manifest["inputs"]["e_timing_receipt"] = pin(new_path, timing)
    with pytest.raises(
        (PermissionError, OSError), match="source|binding|cannot find|No such"
    ):
        host._timing({**f.values, "final_freeze": f.final, "e_timing_receipt": timing})
