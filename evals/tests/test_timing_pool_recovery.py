"""Free synthetic recovery locking; never registers or dispatches real work."""

import importlib.util
import json
import sqlite3
from contextlib import ExitStack
from datetime import datetime, timezone
from hashlib import sha256

import pytest

from evals.tests.test_model_identities import adopt
from evals.tests.test_model_identities import fixture as model_fixture
from evals.tests.test_source_epochs import historical_account, manifest_for, register


@pytest.mark.parametrize("kind", ["source", "model"])
def test_registration_locked_audit_refusal_rolls_back_and_releases_locks(
    tmp_path, kind
):
    if kind == "source":
        path, identity, root = historical_account(tmp_path)
        manifest = manifest_for(identity, root)
        function, table = register, "supplement_source_epochs"
    else:
        path, manifest = model_fixture(tmp_path)
        root = tmp_path / "controller"
        function, table = adopt, "supplement_model_epochs"
    seen = []

    def refuse(*, db, controller_state_roots, owned_locks):
        assert db.in_transaction
        assert tuple(manifest["controller_state_roots"]) == controller_state_roots
        assert owned_locks == frozenset(
            root / name for name in (".writer-lock", ".analysis36-campaign-lock")
        )
        assert all(lock.is_dir() for lock in owned_locks)
        seen.append(True)
        raise PermissionError("fresh recovery audit refused")

    with pytest.raises(PermissionError, match="fresh recovery audit"):
        function(path, manifest, locked_audit=refuse)
    assert seen == [True]
    with sqlite3.connect(path) as db:
        exists = db.execute(
            "SELECT 1 FROM sqlite_master WHERE name=?", (table,)
        ).fetchone()
        assert (
            not exists or db.execute(f"SELECT count(*) FROM {table}").fetchone()[0] == 0
        )
    assert not (root / ".writer-lock").exists()
    assert not (root / ".analysis36-campaign-lock").exists()


def recovery():
    assert importlib.util.find_spec("evals.timing_pool_recovery"), (
        "manual recovery module missing"
    )
    from evals import timing_pool_recovery

    return timing_pool_recovery


def test_manual_audit_requires_unforgeable_live_outer_lease():
    module = recovery()
    with pytest.raises(PermissionError, match="lease"):
        module.audit_old_pool_locked({}, lease=object())


@pytest.mark.parametrize("completed", [False, True])
@pytest.mark.parametrize("register_sealed", [False, True])
def test_outer_lease_preserves_native_additional_inventory_and_all_root_locks(
    tmp_path, monkeypatch, completed, register_sealed
):
    from evals.adapters.source_epochs import (
        _additional_terminal,
        _lock_controller_roots,
    )
    from evals.tests.test_source_epochs import additional_terminal

    module, spec, journal = synthetic_spec(tmp_path, monkeypatch)
    sealed = additional_terminal(journal.path.parent, completed=completed)
    nested = sealed / "worker.controller"
    spec["controller_state_roots"].append(str(nested))
    if register_sealed:
        spec["controller_state_roots"].append(str(sealed))
    start = json.loads((sealed / "started.json").read_bytes())
    _additional_terminal(sealed, start)
    before = {str(p): p.read_bytes() for p in sealed.rglob("*") if p.is_file()}
    with module.manual_recovery_quiescence(spec) as lease, ExitStack() as stack:
        # Exercise the actual native exact inventory before inspecting our lease.
        locks = _lock_controller_roots(spec["controller_state_roots"], stack)
        module.require_native_lock_ownership(spec["controller_state_roots"], locks)
        assert len(locks) == 2 * len(spec["controller_state_roots"])
        assert (journal.path.parent / "host-writer.lock").is_file()
        for root in (sealed, nested):
            assert not (root / "host-writer.lock").exists()
            if str(root) in spec["controller_state_roots"]:
                assert list((root / ".pool-adoption-fence").iterdir()) == []
        module._require_lease(lease)
        _additional_terminal(sealed, start)
        assert before == {
            str(p): p.read_bytes() for p in sealed.rglob("*") if p.is_file()
        }
    assert before == {str(p): p.read_bytes() for p in sealed.rglob("*") if p.is_file()}


@pytest.mark.parametrize("damage", ["missing_receipt", "extra_file", "host_lock"])
def test_outer_lease_does_not_classify_invalid_additional_output_as_sealed(
    tmp_path, monkeypatch, damage
):
    from evals.tests.test_source_epochs import additional_terminal

    module, spec, journal = synthetic_spec(tmp_path, monkeypatch)
    sealed = additional_terminal(journal.path.parent)
    spec["controller_state_roots"].append(str(sealed))
    if damage == "missing_receipt":
        (sealed / "launch-receipt.json").unlink()
    else:
        (
            sealed / ("host-writer.lock" if damage == "host_lock" else "extra")
        ).write_bytes(b"existing")
    before = {str(p): p.read_bytes() for p in sealed.rglob("*") if p.is_file()}
    with pytest.raises(PermissionError), module.manual_recovery_quiescence(spec):
        pass
    assert before == {str(p): p.read_bytes() for p in sealed.rglob("*") if p.is_file()}
    assert not list(journal.path.parent.rglob(".pool-adoption-fence"))


def test_outer_lease_empty_fence_rejects_replacement_and_foreign_contents(
    tmp_path, monkeypatch
):
    module, spec, journal = synthetic_spec(tmp_path, monkeypatch)
    with module.manual_recovery_quiescence(spec) as lease:
        fence = journal.path.parent / ".pool-adoption-fence"
        assert list(fence.iterdir()) == []
        foreign = fence / "foreign"
        foreign.write_bytes(b"not ours")
        with pytest.raises(PermissionError, match="ownership"):
            module._require_lease(lease)
        foreign.unlink()
        held = journal.path.parent / "original-fence"
        fence.rename(held)
        fence.mkdir()
        try:
            with pytest.raises(PermissionError, match="ownership"):
                module._require_lease(lease)
        finally:
            fence.rmdir()
            held.rename(fence)


def test_outer_lease_fences_new_pool_creation_in_every_registered_tree(
    tmp_path, monkeypatch
):
    from evals.timing_pool_controller import PoolJournal

    module, spec, _journal = synthetic_spec(tmp_path, monkeypatch)
    unrelated = tmp_path / "unrelated"
    unrelated.mkdir()
    spec["controller_state_roots"].append(str(unrelated))
    with module.manual_recovery_quiescence(spec):
        with pytest.raises(PermissionError, match="fence"):
            PoolJournal.prepare(
                unrelated / "pool-journal.jsonl",
                pool_sha256="c" * 64,
                attempts=[f"x{i}" for i in range(6)],
                imported_trial_id="imported",
                now=datetime(2026, 11, 1, tzinfo=timezone.utc),
            )
        assert not (unrelated / "pool-journal.jsonl").exists()


def test_outer_lease_cleanup_preserves_replaced_foreign_fence(tmp_path, monkeypatch):
    module, spec, journal = synthetic_spec(tmp_path, monkeypatch)
    fence = journal.path.parent / ".pool-adoption-fence"
    held = journal.path.parent / "original-fence"
    with (
        pytest.raises(PermissionError, match="ownership"),
        module.manual_recovery_quiescence(spec),
    ):
        fence.rename(held)
        fence.mkdir()
        (fence / "foreign").write_bytes(b"must remain")
    assert (fence / "foreign").read_bytes() == b"must remain"
    assert held.is_dir()
    assert not journal.lock_path.exists()
    assert not (journal.path.parent / "host-writer.lock").exists()


def test_native_locks_still_reject_sealed_mutation_after_outer_classification(
    tmp_path, monkeypatch
):
    from evals.adapters.source_epochs import _lock_controller_roots
    from evals.tests.test_source_epochs import additional_terminal

    module, spec, journal = synthetic_spec(tmp_path, monkeypatch)
    sealed = additional_terminal(journal.path.parent)
    spec["controller_state_roots"].append(str(sealed))
    with module.manual_recovery_quiescence(spec):
        (sealed / "late-extra").write_bytes(b"must fail native inventory")
        with pytest.raises(PermissionError, match="terminal"), ExitStack() as stack:
            _lock_controller_roots(spec["controller_state_roots"], stack)
    assert (sealed / "late-extra").exists()


@pytest.mark.parametrize("which", ["predecessor", "target"])
def test_pinned_host_cannot_overlap_authenticated_sealed_output(
    tmp_path, monkeypatch, which
):
    from evals.tests.test_source_epochs import additional_terminal

    if which == "target":
        module, spec, journal, _ = target_genesis(tmp_path, monkeypatch)
    else:
        module, spec, journal = synthetic_spec(tmp_path, monkeypatch)
    sealed = additional_terminal(journal.path.parent)
    nested = sealed / "worker.controller"
    spec["controller_state_roots"] += [str(sealed), str(nested)]
    if which == "predecessor":
        host = json.loads((tmp_path / "host.json").read_bytes())
        host["hosts"] = {
            "child": pinned(
                tmp_path / "child-host.json",
                {
                    "schema_version": "task13-e-host-controller-v1",
                    "output_dir": str(nested),
                },
            )
        }
        spec["pool_host_manifest"] = pinned(tmp_path / "host.json", host)
        monkeypatch.setitem(
            module.FROZEN, "pool_host_manifest", spec["pool_host_manifest"]["sha256"]
        )
    else:
        target = json.loads((tmp_path / "target.json").read_bytes())
        target["children"] = [{"evidence_root": str(nested / "timing")}]
        spec["target_pool_registration"] = pinned(tmp_path / "target.json", target)
    with (
        pytest.raises(PermissionError, match="conflicts"),
        module.manual_recovery_quiescence(spec),
    ):
        pass
    assert not list(journal.path.parent.rglob(".pool-adoption-fence"))


def test_outer_lease_retains_historical_and_pre_genesis_host_protocol_locks(
    tmp_path, monkeypatch
):
    from scripts.task13_e_trial import ETrialController

    module, spec, _journal = synthetic_spec(tmp_path, monkeypatch)
    host_roots = [tmp_path / name for name in ("historical-host", "target-pre-genesis")]
    for root in host_roots:
        root.mkdir()
        spec["controller_state_roots"].append(str(root))
    with module.manual_recovery_quiescence(spec):
        for root in host_roots:
            host = object.__new__(ETrialController)
            host._root = root
            with pytest.raises(PermissionError, match="host writer"), host._lock():
                pass
            assert not (root / "host-binding.json").exists()


def test_outer_lease_preserves_preexisting_empty_fence(tmp_path, monkeypatch):
    module, spec, journal = synthetic_spec(tmp_path, monkeypatch)
    fence = journal.path.parent / ".pool-adoption-fence"
    fence.mkdir()
    identity = (fence.stat().st_dev, fence.stat().st_ino)
    with (
        pytest.raises(PermissionError, match="stale"),
        module.manual_recovery_quiescence(spec),
    ):
        pass
    assert (fence.stat().st_dev, fence.stat().st_ino) == identity


def test_native_lock_capability_is_live_and_cannot_be_recreated(tmp_path):
    from evals.adapters.source_epochs import _lock_controller_roots

    module = recovery()
    root = str(tmp_path.resolve())
    with ExitStack() as stack:
        locks = _lock_controller_roots([root], stack)
        module.require_native_lock_ownership((root,), locks)
        with pytest.raises(PermissionError, match="native"):
            module.require_native_lock_ownership((root,), frozenset(list(locks)))
    with pytest.raises(PermissionError, match="native"):
        module.require_native_lock_ownership((root,), locks)


def pinned(path, value):
    path.write_text(json.dumps(value), encoding="utf-8")
    return {"path": str(path), "sha256": sha256(path.read_bytes()).hexdigest()}


def synthetic_spec(tmp_path, monkeypatch):
    from evals.timing_pool_controller import PoolJournal

    module = recovery()
    root = tmp_path / "root"
    root.mkdir()
    journal = PoolJournal.prepare(
        root / "pool-journal.jsonl",
        pool_sha256="a" * 64,
        attempts=[f"t{i}" for i in range(6)],
        imported_trial_id="old",
        now=datetime(2026, 11, 1, tzinfo=timezone.utc),
    )
    journal.begin(
        "t0",
        now=datetime(2026, 11, 1, tzinfo=timezone.utc),
        quiescent=True,
        reserved_yuan="0.1",
    )
    journal.stop("unknown_native_execution")
    host = pinned(
        tmp_path / "host.json", {"journal_path": str(journal.path), "hosts": {}}
    )
    scope = pinned(tmp_path / "scope.json", {"unsigned": True})
    stop = pinned(
        tmp_path / "stop.json",
        {
            "pool_journal": {
                "path": str(journal.path),
                "sha256": sha256(journal.path.read_bytes()).hexdigest(),
            },
            "journal_head": journal.status()["journal_head"],
        },
    )
    fee = pinned(tmp_path / "fee.json", {})
    spec = {
        "schema_version": "task13-manual-recovery-lock-spec-v1",
        "pool_host_manifest": host,
        "expected_scope": scope,
        "stop_evidence": stop,
        "fee_audit": fee,
        "controller_state_roots": [str(root)],
    }
    monkeypatch.setattr(
        module,
        "FROZEN",
        {
            "pool_host_manifest": host["sha256"],
            "stop_evidence": stop["sha256"],
            "fee_audit": fee["sha256"],
            "journal_head": journal.status()["journal_head"],
            "pool_sha256": "a" * 64,
        },
    )
    return module, spec, journal


def test_outer_lease_holds_host_pool_fences_and_releases_without_evidence_writes(
    tmp_path, monkeypatch
):
    module, spec, journal = synthetic_spec(tmp_path, monkeypatch)
    original = journal.path.read_bytes()
    root = journal.path.parent
    with module.manual_recovery_quiescence(spec) as lease:
        assert (root / ".pool-adoption-fence").is_dir()
        assert (root / "host-writer.lock").is_file()
        assert journal.lock_path.is_file()
        with pytest.raises(PermissionError, match="native"):
            module.audit_old_pool_locked(spec, lease=lease)
        with pytest.raises(PermissionError):
            journal.stop("must_not_write")
    assert journal.path.read_bytes() == original
    assert sorted(p.name for p in root.iterdir()) == ["pool-journal.jsonl"]
    with pytest.raises(PermissionError, match="lease"):
        module.audit_old_pool_locked(spec, lease=lease)


def test_outer_lease_refuses_missing_scope_pin_and_unlisted_pending_pool(
    tmp_path, monkeypatch
):
    module, spec, journal = synthetic_spec(tmp_path, monkeypatch)
    invalid = {**spec, "expected_scope": {**spec["expected_scope"], "sha256": "b" * 64}}
    with (
        pytest.raises(PermissionError, match="pin"),
        module.manual_recovery_quiescence(invalid),
    ):
        pass
    from evals.timing_pool_controller import PoolJournal

    nested = journal.path.parent / "nested"
    nested.mkdir()
    other = PoolJournal.prepare(
        nested / "pool-journal.jsonl",
        pool_sha256="c" * 64,
        attempts=[f"x{i}" for i in range(6)],
        imported_trial_id="old",
        now=datetime(2026, 11, 1, tzinfo=timezone.utc),
    )
    other.begin(
        "x0",
        now=datetime(2026, 11, 1, tzinfo=timezone.utc),
        quiescent=True,
        reserved_yuan="0.1",
    )
    with (
        pytest.raises(PermissionError, match="pending"),
        module.manual_recovery_quiescence(spec),
    ):
        pass
    assert not list(journal.path.parent.rglob("*.lock"))
    assert not list(journal.path.parent.rglob(".pool-adoption-fence"))


def test_native_quarantine_snapshot_rejects_any_branch_or_trial_progress():
    from types import SimpleNamespace

    module = recovery()
    view = SimpleNamespace(
        events=[{"kind": "genesis"}],
        trials={f"t{i}": {"status": "not_started", "binding": None} for i in range(3)},
        records={
            f"r{i}": {"status": "not_started", "review_pending": False}
            for i in range(18)
        },
    )
    assert module._native_untouched(view) == {"trials": 3, "branches": 18, "events": 1}
    view.records["r0"]["input_sha256"] = "a" * 64
    with pytest.raises(PermissionError, match="native"):
        module._native_untouched(view)
    view.records["r0"].pop("input_sha256")
    view.trials["t0"]["status"] = "expired"
    with pytest.raises(PermissionError, match="native"):
        module._native_untouched(view)


def test_worker_absence_rejects_present_or_unknown_container(monkeypatch):
    import subprocess

    module = recovery()
    seen = []

    def run(argv, **kwargs):
        seen.append(argv)
        return subprocess.CompletedProcess(argv, 0, stdout=b"a" * 64, stderr=b"")

    monkeypatch.setattr(subprocess, "run", run)
    with pytest.raises(PermissionError, match="absen"):
        module._container_absent("a" * 64)
    assert seen[0][1:3] == ["container", "ls"]
    with pytest.raises(PermissionError, match="identity"):
        module._container_absent("x;docker run")


def test_quarantine_schema_never_accepts_native_ttl_or_authority():
    module = recovery()
    for evidence in (
        {"schema_version": "task13-pool-pre-timing-expiry-v1"},
        {"schema_version": "task13-manual-pool-quarantine-v1", "authority": True},
    ):
        with pytest.raises(PermissionError, match="quarantine"):
            module.validate_quarantine_evidence(evidence, expected_scope={})


def test_active_outer_lease_rejects_forged_native_capability_and_tree_drift(
    tmp_path, monkeypatch
):
    module, spec, journal = synthetic_spec(tmp_path, monkeypatch)
    from evals.adapters.source_epochs import _lock_controller_roots

    with (
        module.manual_recovery_quiescence(spec) as lease,
        sqlite3.connect(":memory:") as db,
    ):
        db.execute("BEGIN IMMEDIATE")
        callback = lease.locked_audit()
        with pytest.raises(PermissionError, match="native"):
            callback(
                db=db,
                controller_state_roots=tuple(spec["controller_state_roots"]),
                owned_locks=frozenset(),
            )
        with ExitStack() as stack:
            locks = _lock_controller_roots(spec["controller_state_roots"], stack)

            def drift(*args):
                (journal.path.parent / "unexpected.json").write_text("changed")
                return {}

            monkeypatch.setattr(module, "_audit_prefix", drift)
            with pytest.raises(PermissionError, match="raw evidence changed"):
                callback(
                    db=db,
                    controller_state_roots=tuple(spec["controller_state_roots"]),
                    owned_locks=locks,
                )
            assert lease.native is None


def test_validator_rejects_worker_record_that_does_not_prove_absence():
    module = recovery()
    with pytest.raises(PermissionError, match="worker"):
        module._validate_worker_inspections(
            [
                {
                    "phase": "plan",
                    "container_id": "a" * 64,
                    "runtime_sha256": "b" * 64,
                    "inspection": {"returncode": 0},
                }
            ]
        )


def test_old_fee_baseline_allows_new_epoch_appends_but_refuses_old_row_changes(
    tmp_path,
    monkeypatch,
):
    from evals.contracts import canonical_hash

    module = recovery()
    # This test isolates the immutable row-prefix check; native registered
    # source/model admission of extra rows is exercised independently below.
    monkeypatch.setattr(
        module, "_validate_new_fee_rows", lambda *a: None, raising=False
    )
    path = tmp_path / "campaign.sqlite"
    with sqlite3.connect(path) as db:
        db.executescript(
            "CREATE TABLE config(key TEXT,value TEXT);"
            "CREATE TABLE reservations(id TEXT,actual REAL,settled INTEGER);"
            "CREATE TABLE supplement_requests(reservation_id TEXT,epoch_id TEXT,source_sha256 TEXT,config_sha256 TEXT,purpose TEXT);"
            "CREATE TABLE supplement_request_epochs(reservation_id TEXT,epoch_id TEXT);"
            "CREATE TABLE supplement_request_models(reservation_id TEXT,model_epoch_id TEXT,identity_manifest_sha256 TEXT);"
        )
        db.execute("INSERT INTO config VALUES ('halt','original halt')")
        for i in range(77):
            db.execute("INSERT INTO reservations VALUES (?,0.01,1)", (f"old-{i}",))
            db.execute(
                "INSERT INTO supplement_requests(reservation_id,epoch_id) VALUES (?,'source10')",
                (f"old-{i}",),
            )
        original = db.execute(
            "SELECT rowid,* FROM reservations ORDER BY rowid"
        ).fetchall()
        physical = db.execute(
            "SELECT s.*,r.actual,r.settled,e.epoch_id,m.model_epoch_id,m.identity_manifest_sha256 FROM supplement_requests s JOIN reservations r ON s.reservation_id=r.id LEFT JOIN supplement_request_epochs e ON e.reservation_id=s.reservation_id LEFT JOIN supplement_request_models m ON m.reservation_id=s.reservation_id ORDER BY s.reservation_id"
        ).fetchall()
        fees = {
            "reservation_ids": sorted(f"old-{i}" for i in range(77)),
            "original_reservation_max_rowid": 77,
            "original_reservation_count": 77,
            "reservations_sha256": canonical_hash(original),
            "physical_rows_sha256": canonical_hash(physical),
            "config_sha256": canonical_hash(
                db.execute("SELECT key,value FROM config ORDER BY key").fetchall()
            ),
        }
    module._check_fee_baseline(path, fees)
    with sqlite3.connect(path) as db:
        db.execute(
            "INSERT INTO supplement_request_models VALUES ('old-0','forged-model','forged-pin')"
        )
    with pytest.raises(PermissionError, match="baseline"):
        module._check_fee_baseline(path, fees)
    with sqlite3.connect(path) as db:
        db.execute("DELETE FROM supplement_request_models")
    with sqlite3.connect(path) as db:
        db.execute("INSERT INTO reservations VALUES ('new',0.02,1)")
        db.execute(
            "INSERT INTO supplement_requests(reservation_id,epoch_id) VALUES ('new','source11')"
        )
    module._check_fee_baseline(path, fees)
    with sqlite3.connect(path) as db:
        db.execute("UPDATE reservations SET actual=0.03 WHERE id='old-0'")
    with pytest.raises(PermissionError, match="baseline"):
        module._check_fee_baseline(path, fees)


def test_runtime_fresh_worker_check_rechecks_every_owned_container(monkeypatch):
    module = recovery()
    evidence = {
        "expected_scope": {"path": "unused", "sha256": "a" * 64},
        "workers": [{"container_id": "b" * 64}, {"container_id": "c" * 64}],
    }
    seen = []
    monkeypatch.setattr(module, "validate_quarantine_evidence", lambda e, **kw: e)
    monkeypatch.setattr(
        module, "_container_absent", lambda c: seen.append(c) or {"absent": True}
    )
    proof = module.fresh_quarantine_workers_absent(evidence)
    assert seen == ["b" * 64, "c" * 64]
    assert proof["status"] == "verified"


def test_native_capability_rejects_replaced_lock_directory(tmp_path):
    from evals.adapters.source_epochs import _lock_controller_roots

    module = recovery()
    root = str(tmp_path.resolve())
    with ExitStack() as stack:
        locks = _lock_controller_roots([root], stack)
        lock = tmp_path / ".writer-lock"
        retained = tmp_path / "retained-lock"
        lock.rename(retained)
        lock.mkdir()
        with pytest.raises(PermissionError, match="native"):
            module.require_native_lock_ownership((root,), locks)
        retained.rmdir()


def test_preserved_raw_file_map_rejects_changed_and_missing_bytes(tmp_path):
    from evals.contracts import canonical_hash

    module = recovery()
    path = tmp_path / "old.json"
    path.write_bytes(b"original bytes")
    files = {str(path): sha256(path.read_bytes()).hexdigest()}
    module._check_preserved_files(files, canonical_hash(files))
    path.write_bytes(b"changed bytes")
    with pytest.raises(PermissionError, match="preserved"):
        module._check_preserved_files(files, canonical_hash(files))


def test_audit_snapshot_freezes_only_original_roots_and_records_live_callback_result(
    tmp_path, monkeypatch
):
    module, spec, journal = synthetic_spec(tmp_path, monkeypatch)
    from evals.adapters.source_epochs import _lock_controller_roots

    successor = tmp_path / "successor"
    successor.mkdir()
    (successor / "new-journal.json").write_text("future data")
    spec["controller_state_roots"].append(str(successor))
    monkeypatch.setattr(
        module,
        "_audit_prefix",
        lambda *a: {"old_controller_state_roots": [str(journal.path.parent)]},
    )
    monkeypatch.setattr(
        module, "validate_quarantine_evidence", lambda evidence, **kw: evidence
    )
    with (
        module.manual_recovery_quiescence(spec) as lease,
        ExitStack() as stack,
        sqlite3.connect(":memory:") as db,
    ):
        locks = _lock_controller_roots(spec["controller_state_roots"], stack)
        db.execute("BEGIN IMMEDIATE")
        lease.locked_audit()(
            db=db,
            controller_state_roots=tuple(spec["controller_state_roots"]),
            owned_locks=locks,
        )
        assert str(journal.path) in lease.evidence["preserved_files"]
        assert not any(
            path.startswith(str(successor))
            for path in lease.evidence["preserved_files"]
        )
        assert lease.native is None


def test_native_audit_transaction_requires_original_budget_file(tmp_path):
    module = recovery()
    path = tmp_path / "original.sqlite"
    with sqlite3.connect(path) as db:
        db.execute("BEGIN IMMEDIATE")
        module._require_original_budget_transaction(db, path)
    with sqlite3.connect(":memory:") as db:
        db.execute("BEGIN IMMEDIATE")
        with pytest.raises(PermissionError, match="original budget"):
            module._require_original_budget_transaction(db, path)


def target_genesis(tmp_path, monkeypatch):
    from copy import deepcopy

    from evals.contracts import canonical_hash
    from evals.tests.test_e_planning_limited_authority import limited_fixture
    from evals.timing_pool import RECOVERY_REGISTRATION_SCHEMA, pool_policy
    from evals.timing_pool_controller import PoolJournal

    module, spec, old = synthetic_spec(tmp_path, monkeypatch)
    old_registration = pinned(
        tmp_path / "old-registration.json", {"synthetic": "old pool"}
    )
    spec["pool_host_manifest"] = pinned(
        tmp_path / "host.json",
        {
            "journal_path": str(old.path),
            "pool_registration": old_registration,
            "hosts": {},
        },
    )
    monkeypatch.setitem(
        module.FROZEN, "pool_host_manifest", spec["pool_host_manifest"]["sha256"]
    )
    _, authorities = limited_fixture(tmp_path)
    grant = deepcopy(authorities[0]["migration_grant"])
    stop = json.loads((tmp_path / "stop.json").read_bytes())
    grant.update(
        recovery_plan_sha256=spec["expected_scope"]["sha256"],
        predecessor_pool_registration_sha256=old_registration["sha256"],
        predecessor_pool_journal_sha256=stop["pool_journal"]["sha256"],
        predecessor_pool_head_sha256=stop["journal_head"],
    )
    quarantine = pinned(tmp_path / "quarantine.json", {"synthetic": True})
    grant["quarantine_record_sha256"] = quarantine["sha256"]
    predecessor = {
        "pool_registration": old_registration,
        "pool_journal": stop["pool_journal"],
        "pool_head_sha256": stop["journal_head"],
        "quarantine_record": quarantine,
    }
    target_root = tmp_path / "target"
    target_root.mkdir()
    spec["controller_state_roots"].append(str(target_root))
    target = {
        "schema_version": RECOVERY_REGISTRATION_SCHEMA,
        "children": [],
        "execution_journal_path": str(target_root / "pool-journal.jsonl"),
        "future_logical_limit": 5,
        "future_physical_limit": 15,
        "attempt_order": [
            {"child_id": "synthetic", "trial_id": f"new-{i}"} for i in range(5)
        ],
        "imported_observations": [{"trial_id": "original-c10"}],
        "migration_grant": grant,
        "migration_grant_sha256": canonical_hash(grant),
        "quarantined_predecessor": predecessor,
        "quarantine_record": quarantine,
        "recovery_plan": spec["expected_scope"],
        "original_account_baseline": pinned(
            tmp_path / "target-account.json",
            {
                "development_ledger": {
                    "rows": [
                        {"reservation_id": "historical", "actual": "0", "settled": 1}
                    ],
                    "spent_yuan": "0",
                }
            },
        ),
    }
    spec["target_pool_registration"] = pinned(tmp_path / "target.json", target)
    journal = PoolJournal.prepare(
        target["execution_journal_path"],
        pool_sha256=canonical_hash(target),
        attempts=[a["trial_id"] for a in target["attempt_order"]],
        imported_trial_id="original-c10",
        imported_max_seconds=384.562,
        now=datetime(2026, 11, 1, tzinfo=timezone.utc),
        policy=pool_policy(target),
        migration_grant=grant,
        quarantined_predecessor=predecessor,
    )
    return module, spec, old, journal


def test_explicit_metadata_resume_accepts_only_pinned_target_v2_genesis(
    tmp_path, monkeypatch
):
    from evals.adapters.source_epochs import _lock_controller_roots

    module, spec, old, target = target_genesis(tmp_path, monkeypatch)
    original_old, original_target = old.path.read_bytes(), target.path.read_bytes()
    # Completed source/model and child/doc metadata already exist. The resume
    # callback uses their same original native locks without appending metadata.
    (target.path.parent / "children-completed.json").write_text("fixed metadata")
    monkeypatch.setattr(
        module,
        "_audit_prefix",
        lambda *a: {"old_controller_state_roots": [str(old.path.parent)]},
    )
    monkeypatch.setattr(
        module, "validate_quarantine_evidence", lambda evidence, **kw: evidence
    )
    expected = None
    for _ in range(2):
        with (
            module.manual_recovery_quiescence(spec) as lease,
            ExitStack() as stack,
            sqlite3.connect(":memory:") as db,
        ):
            locks = _lock_controller_roots(spec["controller_state_roots"], stack)
            db.execute("BEGIN IMMEDIATE")
            lease.locked_audit(expected_evidence=expected)(
                db=db,
                controller_state_roots=tuple(spec["controller_state_roots"]),
                owned_locks=locks,
            )
            expected = lease.evidence
    assert old.path.read_bytes() == original_old
    assert target.path.read_bytes() == original_target


@pytest.mark.parametrize(
    "change",
    ["unlisted", "forged_pin", "begun", "stopped", "grant", "spent", "maximum"],
)
def test_target_genesis_resume_rejects_unpinned_or_progressed_pool(
    tmp_path, monkeypatch, change
):
    module, spec, _, target = target_genesis(tmp_path, monkeypatch)
    if change == "unlisted":
        spec.pop("target_pool_registration")
    elif change == "forged_pin":
        spec["target_pool_registration"]["sha256"] = "f" * 64
    elif change == "begun":
        target.begin(
            "new-0",
            now=datetime(2026, 11, 1, tzinfo=timezone.utc),
            quiescent=True,
            reserved_yuan="0.1",
        )
    elif change == "stopped":
        target.stop("unknown_native_execution")
    elif change in ("spent", "maximum"):
        from evals.timing_pool_controller import _raw

        event = json.loads(target.path.read_bytes())
        event["payload"][
            "initial_spent_yuan" if change == "spent" else "imported_max_seconds"
        ] = "1" if change == "spent" else 500
        event.pop("sha256")
        event["sha256"] = sha256(_raw(event)).hexdigest()
        target.path.write_bytes(_raw(event) + b"\n")
    else:
        data = json.loads((tmp_path / "target.json").read_bytes())
        data["migration_grant"]["recovery_plan_sha256"] = "f" * 64
        spec["target_pool_registration"] = pinned(tmp_path / "target.json", data)
    with pytest.raises(PermissionError), module.manual_recovery_quiescence(spec):
        pass


@pytest.mark.parametrize(
    "change",
    [
        None,
        "old_source",
        "old_model",
        "earlier_source",
        "earlier_model",
        "missing_source",
        "missing_model",
        "wrong_manifest",
        "wrong_pair",
        "mismatched_registered_pair",
        "unsettled",
        "unknown_cost",
    ],
)
def test_added_fee_rows_require_new_registered_source_and_matching_new_model(
    tmp_path, change
):
    from copy import deepcopy

    from evals.contracts import canonical_hash

    module = recovery()
    path, model = model_fixture(tmp_path)
    adopt(path, model)
    sources, models = [], [model]
    root = tmp_path / "controller"
    for number in (1, 2):
        source = manifest_for(model["budget_identity"], root, number=number)
        register(path, source)
        successor = deepcopy(models[-1])
        successor.update(
            model_epoch_id=f"model-{number}",
            model_epoch_number=number,
            predecessor_model_epoch_id=f"model-{number - 1}",
            epoch_id=source["epoch_id"],
            source_manifest_sha256=canonical_hash(source),
            source_sha256=source["source_sha256"],
            config_sha256=source["config_sha256"],
        )
        successor["expected_model"]["id"] = successor["model_epoch_id"]
        adopt(path, successor)
        sources.append(source)
        models.append(successor)
    legacy = {
        "epoch_id": sources[0]["epoch_id"],
        "epoch_manifest_sha256": canonical_hash(sources[0]),
        "model_epoch_id": models[1]["model_epoch_id"],
        "model_identity_sha256": canonical_hash(models[1]),
    }
    row = [
        "new-reservation",
        0.01,
        1,
        sources[1]["epoch_id"],
        models[2]["model_epoch_id"],
        canonical_hash(models[2]),
        sources[1]["source_sha256"],
        sources[1]["config_sha256"],
        "development",
    ]
    if change in ("old_source", "earlier_source"):
        row[3] = "synthetic-epoch-1" if change == "old_source" else "synthetic-epoch-0"
    elif change in ("old_model", "earlier_model"):
        row[4] = "model-1" if change == "old_model" else "model-0"
    elif change == "missing_source":
        row[3] = None
    elif change == "missing_model":
        row[4] = None
    elif change == "wrong_manifest":
        row[5] = "f" * 64
    elif change == "wrong_pair":
        row[3] = "synthetic-epoch-99"
    elif change == "mismatched_registered_pair":
        source = manifest_for(model["budget_identity"], root, number=3)
        register(path, source)
        row[3] = source["epoch_id"]
    elif change == "unsettled":
        row[2] = 0
    elif change == "unknown_cost":
        row[1] = None
    with sqlite3.connect(path) as db:
        db.execute("BEGIN")
        if change is None:
            module._validate_new_fee_rows(db, [row], legacy)
        else:
            with pytest.raises(PermissionError, match="new.*fee|fee.*new"):
                module._validate_new_fee_rows(db, [row], legacy)
