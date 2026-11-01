"""Offline regressions for reviewed pool proposal and export contracts."""

from copy import deepcopy
from types import SimpleNamespace

from evals.contracts import canonical_hash
from evals.e_timing import build_e_timing_registration
from evals.tests.test_e_timing_replicates import registration
from evals.timing_pool_controller import pool_scope_proposal


def test_proposal_does_not_retain_future_hash_via_formal_binding(tmp_path):
    native = registration(tmp_path)
    epoch = native["planning_registration"]["epoch_binding"]
    pool = {
        "children": [{"child_id": "a", "registration": native}],
        "formal_binding": {
            k: epoch[k] for k in ("epoch_id", "epoch_manifest_sha256", "source_sha256")
        },
    }
    proposal = pool_scope_proposal(pool)
    changed = deepcopy(pool)
    planning = deepcopy(native["planning_registration"])
    planning["epoch_binding"]["epoch_manifest_sha256"] = "f" * 64
    dispatch = deepcopy(native["planning_dispatch_registration_receipt"])
    dispatch["authority_sha256"] = "a" * 64
    dispatch["registration_sha256"] = canonical_hash(planning)
    changed["children"][0]["registration"] = build_e_timing_registration(
        planning,
        source_files=native["source_files"],
        f8_plan_sha256=native["f8_plan_sha256"],
        planning_dispatch_registration_receipt=dispatch,
    )
    changed["formal_binding"]["epoch_manifest_sha256"] = "f" * 64
    assert pool_scope_proposal(changed) == proposal
    changed["formal_binding"]["epoch_id"] = "another-epoch"
    assert pool_scope_proposal(changed) != proposal


def test_export_meets_explicit_non_synthetic_receipt_contract(monkeypatch):
    from scripts import task13_timing_pool as module

    controller = object.__new__(module.NativePoolController)
    controller.journal = SimpleNamespace(
        status=lambda: {
            "qualified": 3,
            "pending": None,
            "attempted": 2,
            "observed_max_seconds": 400.0,
        }
    )
    controller.pool = {
        "schema_version": "task13-e-timing-pool-registration-v1",
        "identity": {},
        "formal_binding": {},
        "imported_observations": [{"trial_id": "old"}],
        "attempt_order": [
            {"child_id": "a", "trial_id": "one"},
            {"child_id": "a", "trial_id": "two"},
        ],
        "children": [{"child_id": "a", "evidence_root": "synthetic-root"}],
    }
    controller.digest = "a" * 64
    controller.controller_evidence = dict
    monkeypatch.setattr(
        module,
        "read_native_observation",
        lambda *args: {"registration_sha256": "b" * 64},
    )

    def validate(receipt, identity):
        assert receipt.get("synthetic") is False
        assert len(receipt["observations"]) == 3
        return 400.0

    monkeypatch.setattr(module, "validate_pool_receipt", validate)
    assert controller.export()["synthetic"] is False
