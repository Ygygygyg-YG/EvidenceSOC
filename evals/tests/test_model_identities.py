"""Synthetic pinned identities; no real registration or provider traffic."""

import sqlite3

import pytest

from evals.adapters.model_client import BudgetAccount
from evals.contracts import canonical_hash
from evals.tests.test_budget_v2 import finished, started, supplement
from evals.tests.test_source_epochs import historical_account, manifest_for, register


def fixture(tmp_path):
    path, identity, controller = historical_account(tmp_path)
    source = manifest_for(identity, controller)
    register(path, source)
    with sqlite3.connect(path) as db:
        db.executemany(
            "INSERT OR REPLACE INTO config VALUES (?,?)",
            [
                ("response_model", "old"),
                ("fingerprint", "old-fp"),
                ("halt", "observable model version changed"),
            ],
        )
    manifest = {
        "schema_version": "task13-model-identity-v1",
        "campaign_id": source["campaign_id"],
        "model_epoch_id": "model-0",
        "model_epoch_number": 0,
        "predecessor_model_epoch_id": None,
        "epoch_id": source["epoch_id"],
        "source_manifest_sha256": canonical_hash(source),
        "source_sha256": source["source_sha256"],
        "config_sha256": source["config_sha256"],
        "budget_identity": identity,
        "budget_limits": source["budget_limits"],
        "budget_path": str(path.resolve()),
        "controller_state_roots": source["controller_state_roots"],
        "expected_model": {
            "id": "model-0",
            "response_model": "approved",
            "fingerprint": "approved-fp",
        },
        "purposes": ["development"],
        "inherited_global": {
            "response_model": "old",
            "fingerprint": "old-fp",
            "halt": "observable model version changed",
        },
        "halt_evidence_sha256": ["1" * 64, "2" * 64],
        "adoption_decision_sha256": "3" * 64,
        "authority_identity": "synthetic-independent-host",
    }
    return path, manifest


def adopt(path, manifest, **overrides):
    from evals.adapters.model_identities import register_model_identity

    authority = {
        "schema_version": "task13-model-identity-authority-v1",
        "kind": "runtime_model_adoption",
        "decision": "approved",
        "manifest_sha256": canonical_hash(manifest),
        "adoption_decision_sha256": manifest["adoption_decision_sha256"],
        "authority_identity": manifest["authority_identity"],
        "confirmation_sha256": "4" * 64,
    }
    kwargs = {
        "expected_manifest_sha256": canonical_hash(manifest),
        "budget_identity": manifest["budget_identity"],
        "authority": authority,
        "expected_authority_sha256": canonical_hash(authority),
    }
    kwargs.update(overrides)
    return register_model_identity(path, manifest, **kwargs)


def account(path, manifest, **overrides):
    return supplement(
        path,
        epoch_id=manifest["epoch_id"],
        model_epoch_id=manifest["model_epoch_id"],
        model_identity_sha256=canonical_hash(manifest),
        **overrides,
    )


def test_explicit_identity_cannot_be_inferred_or_adopted_by_engineering(tmp_path):
    path, manifest = fixture(tmp_path)
    with pytest.raises(ValueError):
        account(path, manifest)
    with pytest.raises(PermissionError):
        adopt(path, manifest, authority=None)
    with pytest.raises(PermissionError):
        adopt(path, manifest, authority={"kind": "engineering_consent"})


def test_adoption_scopes_identity_halt_without_changing_global(tmp_path):
    path, manifest = fixture(tmp_path)
    adopt(path, manifest)
    scoped = account(path, manifest)
    reservation = scoped.reserve("new", 0.1, "development", metadata=started())
    scoped.bind_model("approved", "approved-fp", reservation_id=reservation)
    scoped.settle(reservation, None, metadata=finished())
    with pytest.raises(RuntimeError, match="halted"):
        BudgetAccount(path).reserve("legacy", 0.1, "formal")
    with sqlite3.connect(path) as db:
        assert dict(db.execute("SELECT * FROM config"))["response_model"] == "old"


@pytest.mark.parametrize(
    "model,fp",
    [
        (None, "approved-fp"),
        ("approved", None),
        ("other", "approved-fp"),
        ("approved", "other"),
    ],
)
def test_identity_drift_halts_before_future_dispatch(tmp_path, model, fp):
    path, manifest = fixture(tmp_path)
    adopt(path, manifest)
    scoped = account(path, manifest)
    with pytest.raises(RuntimeError, match="identity"):
        scoped.bind_model(model, fp)
    with pytest.raises(RuntimeError):
        account(path, manifest).reserve(
            "blocked", 0.1, "development", metadata=started()
        )


def test_old_code_cannot_hide_global_provider_halt(tmp_path):
    path, manifest = fixture(tmp_path)
    adopt(path, manifest)
    with sqlite3.connect(path) as db:
        db.execute("INSERT OR REPLACE INTO config VALUES ('halt','provider HTTP 401')")
        db.execute(
            "INSERT OR REPLACE INTO config VALUES ('halt','observable model version changed')"
        )
    with pytest.raises(RuntimeError):
        account(path, manifest).reserve(
            "blocked", 0.1, "development", metadata=started()
        )


def test_identity_request_mapping_is_append_only_and_stable_key_unchanged(tmp_path):
    path, manifest = fixture(tmp_path)
    adopt(path, manifest)
    scoped = account(path, manifest)
    legacy = supplement(path, epoch_id=manifest["epoch_id"])
    assert scoped.physical_request_key(
        "call", 1, explicit_call_id="call"
    ) == legacy.physical_request_key("call", 1, explicit_call_id="call")
    scoped.reserve("new", 0.1, "development", metadata=started())
    with sqlite3.connect(path) as db, pytest.raises(sqlite3.IntegrityError):
        db.execute("DELETE FROM supplement_request_models")


def test_purpose_and_manifest_pin_are_checked_in_transaction(tmp_path):
    from evals.adapters.model_identities import require_registered_model_identity

    path, manifest = fixture(tmp_path)
    adopt(path, manifest)
    bindings = {
        "epoch_id": manifest["epoch_id"],
        "source_sha256": manifest["source_sha256"],
        "config_sha256": manifest["config_sha256"],
        "manifest_sha256": canonical_hash(manifest),
    }
    with pytest.raises(ValueError):
        require_registered_model_identity(
            path, manifest["model_epoch_id"], purpose="f8", **bindings
        )
    bindings["manifest_sha256"] = "0" * 64
    with pytest.raises(ValueError):
        require_registered_model_identity(
            path, manifest["model_epoch_id"], purpose="development", **bindings
        )


def test_scoped_settlement_rejects_missing_mapping_atomically(tmp_path):
    path, manifest = fixture(tmp_path)
    adopt(path, manifest)
    scoped = account(path, manifest)
    reservation = scoped.reserve("new", 0.1, "development", metadata=started())
    with sqlite3.connect(path) as db:
        db.execute("DROP TRIGGER supplement_request_models_no_delete")
        db.execute("DELETE FROM supplement_request_models")
    with pytest.raises(ValueError):
        scoped.settle(reservation, 0.05, metadata=finished())
    with sqlite3.connect(path) as db:
        assert (
            db.execute(
                "SELECT settled FROM reservations WHERE id=?", (reservation,)
            ).fetchone()[0]
            == 0
        )


def test_scoped_summary_uses_effective_halt(tmp_path):
    path, manifest = fixture(tmp_path)
    adopt(path, manifest)
    scoped = account(path, manifest)
    summary = scoped.supplement_summary()
    assert summary["halted"] is True
    assert summary["effective_halted"] is False
    assert summary["dispatchable_cny"] > 0
    with pytest.raises(RuntimeError):
        scoped.bind_model("wrong", "approved-fp")
    summary = scoped.supplement_summary()
    assert summary["effective_halted"] is True
    assert summary["dispatchable_cny"] == 0


def test_provider_and_overbound_are_durable_global_blockers(tmp_path):
    path, manifest = fixture(tmp_path)
    adopt(path, manifest)
    scoped = account(path, manifest)
    reservation = scoped.reserve("new", 0.1, "development", metadata=started())
    with pytest.raises(Exception, match="exceeded"):
        scoped.settle(reservation, 0.2, metadata=finished(usage_missing_reason=None))
    with sqlite3.connect(path) as db:
        assert db.execute(
            "SELECT actual,settled FROM reservations WHERE id=?", (reservation,)
        ).fetchone() == (0.2, 1)
        db.execute(
            "INSERT OR REPLACE INTO config VALUES ('halt','observable model version changed')"
        )
    with pytest.raises(RuntimeError):
        scoped.reserve("blocked", 0.1, "development", metadata=started())


@pytest.mark.parametrize("trigger", ["capture", "append"])
def test_inactive_same_named_trigger_is_refused(tmp_path, trigger):
    path, manifest = fixture(tmp_path)
    adopt(path, manifest)
    with sqlite3.connect(path) as db:
        if trigger == "capture":
            db.execute("DROP TRIGGER budget_capture_halt_insert")
            db.execute(
                "CREATE TRIGGER budget_capture_halt_insert AFTER INSERT ON config WHEN 0 AND NEW.key='halt' AND NEW.value<>'observable model version changed' BEGIN INSERT INTO budget_halt_events(reason) VALUES (NEW.value); END"
            )
        else:
            db.execute("DROP TRIGGER supplement_model_halts_no_delete")
            db.execute(
                "CREATE TRIGGER supplement_model_halts_no_delete BEFORE DELETE ON supplement_model_halts WHEN 0 BEGIN SELECT RAISE(ABORT,'model identity records are append-only'); END"
            )
    with pytest.raises(ValueError):
        account(path, manifest)


def test_model_halt_evidence_tamper_is_refused(tmp_path):
    path, manifest = fixture(tmp_path)
    adopt(path, manifest)
    scoped = account(path, manifest)
    with pytest.raises(RuntimeError):
        scoped.bind_model("bad", "approved-fp")
    with sqlite3.connect(path) as db:
        db.execute("DROP TRIGGER supplement_model_halts_no_update")
        db.execute("UPDATE supplement_model_halts SET evidence_sha256=?", ("0" * 64,))
        db.execute(
            "CREATE TRIGGER supplement_model_halts_no_update BEFORE UPDATE ON supplement_model_halts BEGIN SELECT RAISE(ABORT,'model identity records are append-only'); END"
        )
    with pytest.raises(ValueError):
        account(path, manifest)


def test_successor_cannot_replay_same_semantic_request(tmp_path):
    from evals.adapters.model_client import BudgetLimit

    path, manifest = fixture(tmp_path)
    adopt(path, manifest)
    old = account(path, manifest)
    reservation = old.reserve("first", 0.1, "development", metadata=started())
    old.settle(reservation, None, metadata=finished())
    successor = {
        **manifest,
        "model_epoch_id": "model-1",
        "model_epoch_number": 1,
        "predecessor_model_epoch_id": "model-0",
        "expected_model": {**manifest["expected_model"], "id": "model-1"},
    }
    adopt(path, successor)
    new = account(path, successor)
    with pytest.raises(BudgetLimit, match="replay"):
        new.reserve("second", 0.1, "development", metadata=started("different-id"))


def test_concurrent_scoped_reservations_share_purpose_cap(tmp_path):
    from concurrent.futures import ThreadPoolExecutor

    from evals.adapters.model_client import BudgetLimit

    path, manifest = fixture(tmp_path)
    adopt(path, manifest)

    def reserve(i):
        try:
            return account(path, manifest).reserve(
                str(i),
                4,
                "development",
                metadata=started(str(i), logical_call_id=str(i)),
            )
        except BudgetLimit:
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(reserve, range(2)))
    assert sum(x is not None for x in results) == 1
    with sqlite3.connect(path) as db:
        assert (
            db.execute("SELECT COUNT(*) FROM supplement_request_models").fetchone()[0]
            == 1
        )


def test_identity_halt_does_not_prevent_settlement(tmp_path):
    path, manifest = fixture(tmp_path)
    adopt(path, manifest)
    scoped = account(path, manifest)
    reservation = scoped.reserve("new", 0.1, "development", metadata=started())
    with pytest.raises(RuntimeError):
        scoped.bind_model("bad", "approved-fp", reservation_id=reservation)
    scoped.settle(reservation, 0.05, metadata=finished(usage_missing_reason=None))
    with sqlite3.connect(path) as db:
        assert db.execute(
            "SELECT actual,settled FROM reservations WHERE id=?", (reservation,)
        ).fetchone() == (0.05, 1)
