"""Startup predecessor validation and original SQL transaction defenses."""

import json
import sqlite3
from copy import deepcopy
from pathlib import Path

import pytest

AUDIT = Path(
    r"D:\传智杯\data\task13\supplements\task13-repair-202610-v2\audit\manual-recovery-resume-20261102\startup-recovery-v3"
)


def startup_material():
    stop = json.loads((AUDIT / "startup-stop-evidence.json").read_bytes())
    host = json.loads(Path(stop["pool_host_manifest"]["path"]).read_bytes())
    pool = json.loads(Path(host["pool_registration"]["path"]).read_bytes())
    events = [
        json.loads(line)
        for line in Path(stop["pool_journal"]["path"]).read_bytes().splitlines()
    ]
    started = json.loads(Path(stop["native_plan_started"]["path"]).read_bytes())
    terminal = json.loads(Path(stop["native_plan_terminal"]["path"]).read_bytes())
    failure = json.loads(Path(stop["startup_failure"]["path"]).read_bytes())
    return stop, pool, events, started, terminal, failure


def test_exact_startup_unknown_shape_consumes_one_attempt_with_zero_requests():
    from evals.timing_pool_startup_recovery import validate_startup_shape

    values = startup_material()
    assert validate_startup_shape(*values) == {
        "original_consumed_logical": 8,
        "original_consumed_physical": 24,
        "failed_attempts": 1,
        "failed_attempt_physical_upper_bound": 3,
        "consumed_logical": 9,
        "consumed_physical": 27,
        "remaining_logical": 4,
        "remaining_physical": 12,
        "charged_requests": 0,
        "actual_cny": "0",
    }


@pytest.mark.parametrize(
    "mutation", ["go", "trial", "terminal", "read", "extra_begin", "enlarged_old_grant"]
)
def test_startup_shape_rejects_different_predecessor(mutation):
    from evals.timing_pool_startup_recovery import validate_startup_shape

    values = list(deepcopy(startup_material()))
    if mutation == "go":
        values[5]["go_authorized"] = True
    if mutation == "trial":
        values[0]["trial_id"] = "a" * 32
    if mutation == "terminal":
        values[4]["status"] = "completed"
    if mutation == "read":
        values[2][2]["payload"]["phase"] = "read"
    if mutation == "extra_begin":
        values[2].append(values[2][1])
    if mutation == "enlarged_old_grant":
        values[1]["migration_grant"]["remaining_logical"] = 6
    with pytest.raises(PermissionError):
        validate_startup_shape(*values)


def test_sql_audit_rejects_rowid_change_and_preserves_transaction(tmp_path):
    from evals.timing_pool_startup_recovery import (
        connection_snapshot,
        validate_sql_prefix,
    )

    path = tmp_path / "original.sqlite"
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE config(key TEXT PRIMARY KEY,value TEXT)")
        db.execute("INSERT INTO config VALUES ('halt','unknown')")
        db.commit()
        baseline = connection_snapshot(db)
        db.execute("BEGIN IMMEDIATE")
        validate_sql_prefix(db, baseline)
        assert db.in_transaction
        db.execute("UPDATE config SET rowid=7")
        with pytest.raises(PermissionError):
            validate_sql_prefix(db, baseline)
        db.rollback()
        assert connection_snapshot(db) == baseline


def test_sql_target_prefix_admits_only_exact_source_then_model_metadata(tmp_path):
    from evals.contracts import canonical_hash
    from evals.timing_pool_startup_recovery import (
        connection_snapshot,
        validate_sql_prefix,
    )

    source = {
        "epoch_id": "source12",
        "campaign_id": "synthetic",
        "epoch_number": 12,
        "predecessor_epoch_id": "source11",
    }
    model = {
        "model_epoch_id": "model9",
        "campaign_id": "synthetic",
        "model_epoch_number": 9,
        "predecessor_model_epoch_id": "model8",
    }
    sa, ma = {"approved_source": "exact"}, {"approved_model": "exact"}
    material = {
        "source": source,
        "model": model,
        "source_authority": sa,
        "model_authority": ma,
    }
    with sqlite3.connect(tmp_path / "private.sqlite") as db:
        for name, count in (
            ("supplement_source_epochs", 9),
            ("supplement_model_epochs", 10),
        ):
            db.execute(
                f"CREATE TABLE {name} ({','.join('c' + str(i) for i in range(count))})"
            )
        db.execute("CREATE TABLE config(key TEXT,value TEXT)")
        db.execute("INSERT INTO config VALUES ('halt','unknown-two')")
        db.commit()
        baseline = connection_snapshot(db)
        db.execute("BEGIN IMMEDIATE")
        assert validate_sql_prefix(db, baseline, expected_target=material) == (
            False,
            False,
        )
        srow = [
            "source12",
            "synthetic",
            12,
            "source11",
            json.dumps(source),
            canonical_hash(source),
            canonical_hash(sa),
            "synthetic-time",
            "synthetic-chain",
        ]
        mrow = [
            "model9",
            "synthetic",
            9,
            "model8",
            json.dumps(model),
            canonical_hash(model),
            json.dumps(ma),
            canonical_hash(ma),
            "synthetic-time",
            "synthetic-chain",
        ]
        db.execute(
            "INSERT INTO supplement_source_epochs VALUES (?,?,?,?,?,?,?,?,?)", srow
        )
        assert validate_sql_prefix(db, baseline, expected_target=material) == (
            True,
            False,
        )
        db.execute(
            "INSERT INTO supplement_model_epochs VALUES (?,?,?,?,?,?,?,?,?,?)", mrow
        )
        assert validate_sql_prefix(db, baseline, expected_target=material) == (
            True,
            True,
        )
        db.execute("UPDATE config SET value='cleared'")
        with pytest.raises(PermissionError):
            validate_sql_prefix(db, baseline, expected_target=material)
        db.rollback()
        assert connection_snapshot(db) == baseline


def test_closed_startup_selector_includes_both_frozen_unknown_parents():
    from evals.timing_pool_startup_recovery import closed_predecessors
    from scripts.task13_pool_prepare import pin

    stop = json.loads((AUDIT / "startup-stop-evidence.json").read_bytes())
    predecessors = closed_predecessors(
        {
            "pool_host_manifest": stop["pool_host_manifest"],
            "stop_evidence": pin(AUDIT / "startup-stop-evidence.json"),
        }
    )
    assert [p["schema"] for p in predecessors] == [
        "task13-e-timing-pool-registration-v2",
        "task13-e-timing-pool-registration-v1",
    ]
    assert [p["head"] for p in predecessors] == [
        "39be936e93a21e627e33deb4d8b8cbc215379b3629454cefb697fe1f454b0bf5",
        "68a42b853ae3ba98b9fc0605e0cf7e635f63ece6212d78d9883cda31fad7f4d9",
    ]


@pytest.mark.parametrize("unlisted", [False, True])
def test_startup_lease_owns_both_closed_parent_locks_and_rejects_third_pool(
    tmp_path, monkeypatch, unlisted
):
    from datetime import datetime, timezone
    from hashlib import sha256

    from evals import timing_pool_startup_recovery as startup
    from evals.contracts import canonical_hash
    from evals.tests.test_timing_pool_recovery import pinned, synthetic_spec
    from evals.tests.test_timing_pool_v2 import pool_fixture
    from evals.timing_pool import pool_policy
    from evals.timing_pool_controller import PoolJournal
    from scripts.task13_manual_recovery import STARTUP_COUNTS

    recovery, original_spec, older = synthetic_spec(tmp_path, monkeypatch)
    second = tmp_path / "second"
    second.mkdir()
    pool = pool_fixture(second)
    journal = PoolJournal.prepare(
        second / "pool-journal.jsonl",
        pool_sha256=canonical_hash(pool),
        attempts=[a["trial_id"] for a in pool["attempt_order"]],
        imported_trial_id=pool["imported_observations"][0]["trial_id"],
        now=datetime(2026, 11, 1, tzinfo=timezone.utc),
        policy=pool_policy(pool),
        migration_grant=pool["migration_grant"],
        quarantined_predecessor=pool["quarantined_predecessor"],
    )
    journal.begin(
        pool["attempt_order"][0]["trial_id"],
        now=datetime(2026, 11, 1, tzinfo=timezone.utc),
        quiescent=True,
        reserved_yuan="0.1",
    )
    journal.stop("native_unknown")
    host = pinned(
        tmp_path / "startup-host.json", {"journal_path": str(journal.path), "hosts": {}}
    )
    old_stop = json.loads(Path(original_spec["stop_evidence"]["path"]).read_bytes())
    old_quarantine = pinned(
        tmp_path / "older-quarantine.json",
        {
            "pool_host_manifest": original_spec["pool_host_manifest"],
            "parent_journal": {
                **old_stop["pool_journal"],
                "head_sha256": old_stop["journal_head"],
            },
        },
    )
    stop = pinned(
        tmp_path / "startup-stop.json",
        {
            "pool_journal": {
                "path": str(journal.path),
                "sha256": sha256(journal.path.read_bytes()).hexdigest(),
            },
            "journal_head": journal.status()["journal_head"],
            "old_quarantine_record": old_quarantine,
        },
    )
    material = pinned(tmp_path / "original-material.json", {"synthetic": True})
    prep = pinned(tmp_path / "original-prep.json", {"synthetic": True})
    identity = "c" * 32
    plan = pinned(
        tmp_path / "startup-plan.json",
        {
            "schema_version": "task13-manual-startup-recovery-plan-v1",
            "recovery_id": identity,
            "quota": STARTUP_COUNTS,
            "predecessor_pool_host": host,
            "predecessor_head_sha256": journal.status()["journal_head"],
            "predecessor_materialization": material,
            "predecessor_preparation": prep,
            "deadline": "2026-11-02T23:59:59+08:00",
            "development_cap_cny": 6,
            "temporary_roots": [
                f"D:/传智杯/.tmp/t13v3-{identity[:12]}-{i}" for i in (1, 2)
            ],
            "actual_authority": None,
            "provider_requests": 0,
            "timing_credit": 0,
        },
    )
    fee = pinned(tmp_path / "startup-fee.json", {"synthetic": True})
    monkeypatch.setattr(
        startup,
        "STARTUP_FROZEN",
        {
            "pool_host_manifest": host["sha256"],
            "stop_evidence": stop["sha256"],
            "fee_audit": fee["sha256"],
            "materialization": material["sha256"],
            "preparation": prep["sha256"],
            "journal_head": journal.status()["journal_head"],
            "pool_sha256": canonical_hash(pool),
        },
    )
    spec = {
        "schema_version": startup.STARTUP_LOCK_SCHEMA,
        "pool_host_manifest": host,
        "stop_evidence": stop,
        "fee_audit": fee,
        "expected_scope": plan,
        "controller_state_roots": [str(older.path.parent), str(second)],
    }
    if unlisted:
        nested = second / "unlisted"
        nested.mkdir()
        PoolJournal.prepare(
            nested / "pool-journal.jsonl",
            pool_sha256="a" * 64,
            attempts=[f"t{i}" for i in range(6)],
            imported_trial_id="old",
            now=datetime(2026, 11, 1, tzinfo=timezone.utc),
        )
        with (
            pytest.raises(PermissionError, match="unlisted"),
            recovery.manual_recovery_quiescence(spec),
        ):
            pass
    else:
        before = {p: p.read_bytes() for p in (older.path, journal.path)}
        with recovery.manual_recovery_quiescence(spec) as lease:
            assert {j.path for j, _owner in lease.journals} == {
                older.path,
                journal.path,
            }
            assert all(j.lock_path.is_file() for j in (older, journal))
            for root in spec["controller_state_roots"]:
                assert (Path(root) / ".pool-adoption-fence").is_dir()
                assert (Path(root) / "host-writer.lock").is_file()
        assert before == {p: p.read_bytes() for p in before}
        assert all(not j.lock_path.exists() for j in (older, journal))


def test_startup_spec_rejects_caller_selected_predecessor():
    from evals.timing_pool_recovery import _spec

    with pytest.raises(PermissionError):
        _spec(
            {
                "schema_version": "task13-manual-startup-recovery-lock-spec-v1",
                "pool_host_manifest": {"path": "x", "sha256": "a" * 64},
            }
        )


def test_only_authentic_live_lease_writer_paths_are_transient(tmp_path, monkeypatch):
    from evals.tests.test_timing_pool_recovery import synthetic_spec
    from evals.timing_pool_startup_recovery import _owned_transient_paths

    recovery, spec, journal = synthetic_spec(tmp_path, monkeypatch)
    assert _owned_transient_paths(spec) == set()
    with recovery.manual_recovery_quiescence(spec) as lease:
        lock = journal.path.parent / "host-writer.lock"
        assert _owned_transient_paths(spec) == {lock}
        original = lock.read_bytes()
        lock.write_bytes(b"forged-owner")
        lease.owned[lock] = b"forged-owner"
        try:
            with pytest.raises(PermissionError):
                _owned_transient_paths(spec)
        finally:
            lock.write_bytes(original)
            lease.owned[lock] = original
    assert _owned_transient_paths(spec) == set()


def startup_absence_fixture():
    from evals.timing_pool_recovery import _pin

    stop = json.loads((AUDIT / "startup-stop-evidence.json").read_bytes())
    original = _pin(stop["owned_worker_absence"])
    older = _pin(stop["old_quarantine_record"])
    bridge = deepcopy(original["bridge"])
    container = {
        "argv": original["container"]["argv"],
        "returncode": 0,
        "stdout_sha256": original["container"]["stdout_sha256"],
        "stderr_sha256": original["container"]["stderr_sha256"],
    }
    workers = [
        {"container_id": w["container_id"], "inspection": w["inspection"]}
        for w in older["workers"]
    ]
    proof = {
        "schema_version": "task13-startup-quarantine-worker-absence-v1",
        "status": "verified",
        "startup": {
            "schema_version": "task13-startup-owned-worker-absence-v1",
            "status": "verified",
            "bridge": bridge,
            "container": container,
        },
        "older": {
            "schema_version": "task13-manual-quarantine-worker-absence-v1",
            "status": "verified",
            "workers": workers,
        },
    }
    quarantine = {"older_quarantine": stop["old_quarantine_record"]}
    # The complete startup stop pin is supplied by the already-validated quarantine.
    from scripts.task13_pool_prepare import pin

    quarantine["stop_evidence"] = pin(AUDIT / "startup-stop-evidence.json")
    when = "2026-11-02T08:44:00+00:00"
    return proof, quarantine, when


@pytest.mark.parametrize(
    "damage", [None, "unknown", "pid", "failed_cim", "container", "older", "truthy"]
)
def test_startup_absence_requires_kernel_identity_exact_name_and_older_proof(damage):
    from evals.timing_pool_startup_recovery import validate_startup_absence

    proof, quarantine, when = startup_absence_fixture()
    bridge, container = proof["startup"]["bridge"], proof["startup"]["container"]
    if damage == "unknown":
        bridge["known"] = False
    if damage == "pid":
        bridge["expected"]["pid"] += 1
    if damage == "failed_cim":
        bridge.update(reason="CIM_query_failed", error_code=5)
    if damage == "container":
        container["argv"][6] = "name=other"
    if damage == "older":
        proof["older"]["workers"] = []
    if damage == "truthy":
        bridge["original_process_absent"] = 1
    if damage:
        with pytest.raises(PermissionError):
            validate_startup_absence(proof, quarantine, inspected_at=when)
    else:
        validate_startup_absence(proof, quarantine, inspected_at=when)
