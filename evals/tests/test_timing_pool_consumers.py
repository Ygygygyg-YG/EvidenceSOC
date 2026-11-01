import pytest

from evals import verification_v2
from evals.contracts import canonical_hash
from scripts.task13_regression import RegressionHost


def test_pool_dispatch_is_explicit_and_preserves_identity(monkeypatch):
    identity = {"source_commit": "actual"}
    receipt = {"schema_version": "task13-e-timing-pool-receipt-v1"}
    import evals.timing_pool as pool

    seen = []
    monkeypatch.setattr(
        pool, "validate_pool_receipt", lambda r, i: seen.append((r, i)) or 390.0
    )
    assert hasattr(verification_v2, "observed_timing_max"), (
        "explicit new-schema consumer required"
    )
    assert verification_v2.observed_timing_max(receipt, identity) == 390.0
    assert seen == [(receipt, identity)]
    with pytest.raises(PermissionError):
        verification_v2.observed_six_branch_max(receipt, identity)


def test_regression_pool_bridge_binds_budget_epoch_and_model(monkeypatch):
    host = object.__new__(RegressionHost)
    host._manifest = {"synthetic": True}
    core = {"f8_plan_sha256": "p"}
    bundle = {
        "campaign_id": "c",
        "source_commit": "s",
        "source_sha256": "budget",
        "config_sha256": "config",
        "epoch_id": "e",
        "epoch_manifest_sha256": "manifest",
        "model_identity_binding": {"model": 6},
    }
    freeze = {"source_files": {"a": "b"}}
    identity = {k: bundle[k] for k in ("campaign_id", "source_commit", "config_sha256")}
    identity.update(
        plan_sha256="p", source_sha256=canonical_hash(freeze["source_files"])
    )
    receipt = {
        "schema_version": "task13-e-timing-pool-receipt-v1",
        "synthetic": True,
        "identity": identity,
        "formal_binding": {
            k: bundle[k]
            for k in (
                "source_sha256",
                "epoch_id",
                "epoch_manifest_sha256",
                "model_identity_binding",
            )
        },
    }
    data = {
        "e_timing_receipt": receipt,
        "core_config": core,
        "bundle": bundle,
        "final_freeze": freeze,
    }
    import evals.timing_pool as pool

    monkeypatch.setattr(
        pool,
        "validate_pool_receipt",
        lambda r, i: 390.0 if i == identity else (_ for _ in ()).throw(ValueError()),
    )
    host._timing(data)
    receipt["formal_binding"]["epoch_id"] = "wrong"
    with pytest.raises(PermissionError, match="pool.*binding"):
        host._timing(data)


def test_real_pool_consumer_requires_frozen_validator_before_trusting_evidence(
    monkeypatch,
):
    host = object.__new__(RegressionHost)
    host._manifest = {"synthetic": False}
    bundle = {
        "campaign_id": "c",
        "source_commit": "s",
        "config_sha256": "config",
        "source_sha256": "budget",
        "epoch_id": "e",
        "epoch_manifest_sha256": "m",
        "model_identity_binding": {},
    }
    receipt = {
        "schema_version": "task13-e-timing-pool-receipt-v1",
        "synthetic": False,
        "formal_binding": {
            k: bundle[k]
            for k in (
                "source_sha256",
                "epoch_id",
                "epoch_manifest_sha256",
                "model_identity_binding",
            )
        },
    }
    import evals.timing_pool as pool

    called = []
    monkeypatch.setattr(
        pool, "validate_pool_receipt", lambda *args: called.append(True) or 1.0
    )
    with pytest.raises(PermissionError, match="validator"):
        host._timing(
            {
                "e_timing_receipt": receipt,
                "core_config": {"f8_plan_sha256": "p"},
                "bundle": bundle,
                "final_freeze": {"source_files": {}},
            }
        )
    assert called == []
