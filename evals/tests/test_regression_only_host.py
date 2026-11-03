"""Explicitly free regression-host fixtures; no real consent, models or budget."""

from __future__ import annotations

import importlib
import importlib.util
import json
from datetime import timedelta
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace

import pytest

from evals.contracts import CallBudget, ModelConfig, SeedPolicy, canonical_hash


def module():
    assert importlib.util.find_spec("scripts.task13_regression_only") is not None, (
        "a frozen existing-only regression host is required"
    )
    return importlib.import_module("scripts.task13_regression_only")


def pin(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = json.dumps(value, ensure_ascii=False).encode()
    path.write_bytes(raw)
    return {"path": str(path.resolve()), "sha256": sha256(raw).hexdigest()}


@pytest.fixture
def fixture(tmp_path):
    m = module()
    from evals.remediation import prepare_bundle
    from evals.tests.test_e_timing import Clock
    from evals.tests.test_remediation import budget_config
    from evals.tests.test_remediation import registration as regression_registration

    clock = Clock()
    reg = regression_registration()
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
    helper = Path(
        importlib.import_module("scripts.task13_regression").__file__
    ).resolve()
    source_files = {
        str(code): code_hash,
        str(helper): sha256(helper.read_bytes()).hexdigest(),
    }
    source_receipt = {
        "source_commit": "a" * 40,
        "files": {
            "scripts/task13_regression_only.py": code_hash,
            "scripts/task13_regression.py": sha256(helper.read_bytes()).hexdigest(),
        },
    }
    source_sha = canonical_hash(source_receipt)
    budget_identity = budget_config()["budget_identity"]
    budget_identity.update(baseline_count=3350, baseline_max_rowid=3350)
    core = {
        "model": ModelConfig().model_dump(mode="json"),
        "seed": SeedPolicy().model_dump(mode="json"),
        "budget": CallBudget().model_dump(mode="json"),
        "budget_identity": budget_identity,
        "active_budget_path": str(tmp_path / "original-budget/campaign.sqlite"),
        "original_observed_model_binding": {
            "response_model": "deepseek-flash",
            "fingerprint": "original-fingerprint",
        },
    }
    bundle = prepare_bundle(
        reg,
        source_commit="a" * 40,
        source_sha256=source_sha,
        config=core,
        epoch_binding={
            key: {
                "epoch_id": "synthetic-regression-only-epoch",
                "epoch_manifest_sha256": "e" * 64,
            }[key]
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
        "rag_receipt": rag,
        "engineering_receipt": engineering,
        "model_price_receipt": price,
    }
    refs = {key: pin(tmp_path / f"{key}.json", value) for key, value in values.items()}
    final = {
        "schema_version": "task13-regression-only-final-freeze-v1",
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
        "schema_version": "task13-regression-only-scope-v1",
        "scope": m.SCOPE,
        "campaign_id": bundle["campaign_id"],
        "final_freeze_sha256": refs["final_freeze"]["sha256"],
        "bundle_sha256": bundle["bundle_sha256"],
        "registered_rows": 176,
        "mode": "regression_only",
        "deadline_at": None,
    }
    refs["scope_packet"] = pin(tmp_path / "scope.json", scope)
    decision = {
        "schema_version": "task13-regression-only-user-scope-decision-v1",
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
        "schema_version": "task13-regression-only-host-v1",
        "synthetic": True,
        "inputs": refs,
        "case_roots": {key: str(path) for key, path in roots.items()},
        "output_dir": str(tmp_path / "execution"),
        "mode": "regression_only",
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
        return m.RegressionOnlyHost(
            binding["path"], binding["sha256"], free_dependencies=dependencies
        )

    state.host = host
    return state


def test_independent_176_without_timing_or_f8(fixture):
    f = fixture
    host = f.host()
    assert "e_timing_receipt" not in f.manifest["inputs"]
    assert "f8_plan_sha256" not in f.values["core_config"]
    assert f.manifest["deadline_at"] is None
    assert host.readiness()["status"] == "verified"
    result = host.execute()
    assert result["counts"]["completed"] == 176
    assert [c for c in f.calls if c != "runtime-check"] == [
        r["slot_id"] for r in f.values["bundle"]["rows"]
    ]


@pytest.mark.parametrize(
    "field,value", [("deadline_at", "2030-01-01T00:00:00Z"), ("mode", "after_e")]
)
def test_explicit_independent_mode_and_null_deadline(fixture, field, value):
    fixture.manifest[field] = value
    with pytest.raises(ValueError):
        fixture.host()


def test_legacy_host_refuses_no_timing_manifest(fixture):
    from scripts.task13_regression import RegressionHost

    f = fixture
    f.manifest.update(
        schema_version="task13-regression-host-v1", deadline_at="2030-01-01T00:00:00Z"
    )
    ref = pin(f.root / "legacy.json", f.manifest)
    with pytest.raises(ValueError):
        RegressionHost(ref["path"], ref["sha256"], free_dependencies=f.dependencies)


@pytest.mark.parametrize(
    "key",
    ["scope_decision", "source_receipt", "final_freeze", "registration", "core_config"],
)
def test_changed_pins_refused_before_worker(fixture, key):
    f = fixture
    host = f.host()
    Path(f.manifest["inputs"][key]["path"]).write_bytes(b"{}")
    assert host.readiness()["status"] == "PENDING"
    assert f.calls == []


def test_offline_frozen_scope_no_runtime_or_fresh_price(fixture):
    f = fixture
    host = f.host()
    host.execute(row_limit=2)
    f.calls.clear()
    f.clock.advance(90000)
    assert host.readiness()["status"] == "PENDING"
    authority = host.validate_frozen_scope()
    assert authority["status"] == "verified"
    assert len(authority["attempts"]) == 2
    assert authority["summary"]["counts"]["completed"] == 2
    assert f.calls == []
    authority["bundle"]["rows"].clear()
    assert len(host.validate_frozen_scope()["bundle"]["rows"]) == 176


def test_unknown_stops_and_sealed_failed_success_immutable(fixture):
    f = fixture

    async def worker(request, agent):
        f.calls.append(request.slot_id)
        if len(f.calls) == 3:
            raise RuntimeError("synthetic lost worker")
        return {
            "execution_status": "completed" if len(f.calls) == 1 else "failed",
            "model_ledger": [],
        }

    f.dependencies = f.module.FreeDependencies(
        worker=worker, runtime_validator=lambda *a: None, now=f.clock.now
    )
    ref = pin(f.root / "host.json", f.manifest)
    host = f.module.RegressionOnlyHost(
        ref["path"], ref["sha256"], free_dependencies=f.dependencies
    )
    result = host.execute()
    assert result["counts"] == {
        "completed": 1,
        "failed": 1,
        "unknown": 1,
        "not_started": 173,
    }
    before = {str(p): p.read_bytes() for p in host._root.rglob("*.json")}
    assert host.execute()["counts"] == result["counts"]
    assert before == {str(p): p.read_bytes() for p in host._root.rglob("*.json")}
    assert host.audit()["status"] == "PENDING"


def test_offline_seal_corruption_refused(fixture):
    f = fixture
    host = f.host()
    host.execute(row_limit=1)
    row = f.values["bundle"]["rows"][0]
    (host._root / row["slot_id"] / "result.json").write_bytes(b"{}")
    with pytest.raises(PermissionError):
        host.validate_frozen_scope()


def test_independent_entrypoint_exists():
    assert importlib.util.find_spec("scripts.task13_regression_only") is not None


def test_offline_accepts_sealed_interrupted_failure(fixture):
    f = fixture

    async def interrupted(request, agent):
        return {"execution_status": "interrupted", "model_ledger": []}

    deps = f.module.FreeDependencies(
        worker=interrupted, runtime_validator=lambda *a: None, now=f.clock.now
    )
    ref = pin(f.root / "host.json", f.manifest)
    host = f.module.RegressionOnlyHost(
        ref["path"], ref["sha256"], free_dependencies=deps
    )
    assert host.execute(row_limit=1)["counts"]["failed"] == 1
    assert host.validate_frozen_scope()["attempts"][0]["status"] == "failed"


@pytest.mark.parametrize("fault", ["decision", "scope", "helper", "registration"])
def test_resealed_bad_authority_refused_before_worker(fixture, fault):
    f = fixture
    refs = f.manifest["inputs"]
    if fault == "decision":
        f.decision["decision"] = "declined"
    elif fault == "scope":
        f.scope["mode"] = "after_e"
    elif fault == "helper":
        helper = str(
            Path(
                importlib.import_module("scripts.task13_regression").__file__
            ).resolve()
        )
        f.final["source_files"].pop(helper)
    elif fault == "registration":
        f.values["registration"]["rows"].reverse()
        refs["registration"] = pin(
            f.root / "registration.json", f.values["registration"]
        )
        f.final["bindings"]["registration"] = refs["registration"]["sha256"]
    refs["final_freeze"] = pin(f.root / "final_freeze.json", f.final)
    f.scope["final_freeze_sha256"] = refs["final_freeze"]["sha256"]
    refs["scope_packet"] = pin(f.root / "scope.json", f.scope)
    f.decision["scope_packet_sha256"] = refs["scope_packet"]["sha256"]
    refs["scope_decision"] = pin(f.root / "decision.json", f.decision)
    host = f.host()
    assert host.readiness()["status"] == "PENDING"
    assert host.audit()["status"] == "PENDING"
    assert f.calls == []


def test_offline_rejects_resealed_received_model_mismatch(fixture):
    f = fixture
    host = f.host()
    host.execute(row_limit=1)
    row = f.values["bundle"]["rows"][0]
    directory = host._root / row["slot_id"]
    result = json.loads((directory / "result.json").read_text(encoding="utf-8"))
    result["model_ledger"] = [
        {
            "http_status": 200,
            "response_model": "wrong",
            "system_fingerprint": "wrong",
            "raw_response": {"model": "wrong", "system_fingerprint": "wrong"},
        }
    ]
    ref = pin(directory / "result.json", result)
    attempt = json.loads((directory / "attempt.json").read_text(encoding="utf-8"))
    attempt["result_sha256"] = ref["sha256"]
    pin(directory / "attempt.json", attempt)
    with pytest.raises(PermissionError, match="model"):
        host.validate_frozen_scope()


def test_offline_rejects_resealed_runtime_budget_identity(fixture):
    f = fixture
    refs = f.manifest["inputs"]
    f.values["runtime_options"]["budget_identity"] = {"wrong": "identity"}
    refs["runtime_options"] = pin(
        f.root / "runtime_options.json", f.values["runtime_options"]
    )
    f.final["bindings"]["runtime_options"] = refs["runtime_options"]["sha256"]
    refs["final_freeze"] = pin(f.root / "final_freeze.json", f.final)
    f.scope["final_freeze_sha256"] = refs["final_freeze"]["sha256"]
    refs["scope_packet"] = pin(f.root / "scope.json", f.scope)
    f.decision["scope_packet_sha256"] = refs["scope_packet"]["sha256"]
    refs["scope_decision"] = pin(f.root / "decision.json", f.decision)
    host = f.host()
    with pytest.raises(PermissionError, match="budget/source identity"):
        host.validate_frozen_scope()
    assert f.calls == []


def test_pending_real_artifacts_do_not_initialize_runtime(tmp_path):
    m = module()
    manifest = {
        "schema_version": "task13-regression-only-host-v1",
        "synthetic": False,
        "mode": "regression_only",
        "deadline_at": None,
        "inputs": {
            key: {"path": str(tmp_path / (key + ".json")), "sha256": "0" * 64}
            for key in m.INPUTS
        },
        "case_roots": {key: str(tmp_path / key) for key in ("ait", "dedale")},
        "output_dir": str(tmp_path / "never-created"),
        "max_evidence_age_seconds": 3600,
    }
    ref = pin(tmp_path / "host.json", manifest)
    host = m.RegressionOnlyHost(ref["path"], ref["sha256"])
    assert host.readiness()["status"] == "PENDING"
    assert host.audit()["status"] == "PENDING"
    assert not (tmp_path / "never-created").exists()


def test_real_new_host_requires_full_actual_helper_freeze(fixture):
    f = fixture
    host = f.host()
    host._manifest["synthetic"] = False
    f.final["synthetic"] = False
    with pytest.raises(PermissionError, match="critical actual host helper"):
        host._fixed({**f.values, "final_freeze": f.final})
