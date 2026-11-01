"""Self-tests use only disposable synthetic files, no Task13 account operations."""

import json
import os
import sqlite3
import subprocess
from contextlib import ExitStack, closing
from types import SimpleNamespace

import pytest

from evals.tests.manual_recovery_cow_namespace import CowNamespace, digest, sql_snapshot


def test_full_schema_rowids_raw_and_transaction_identity_transport(tmp_path):
    original = tmp_path / "original"
    original.mkdir()
    database = original / "account.sqlite"
    with sqlite3.connect(database) as db:
        db.executescript(
            "CREATE TABLE config(key TEXT PRIMARY KEY,value BLOB);"
            "INSERT INTO config VALUES('HALT',X'0001');"
            "CREATE TABLE reservations(id TEXT,settled INTEGER);"
            "INSERT INTO reservations(rowid,id,settled) VALUES(14,'unknown-a',0);"
            "INSERT INTO reservations(rowid,id,settled) VALUES(77,'unknown-b',0);"
            "CREATE TABLE unrelated(old TEXT);INSERT INTO unrelated VALUES('preserve');"
            "CREATE INDEX keep_index ON reservations(id);"
            "CREATE TRIGGER keep_old BEFORE DELETE ON unrelated BEGIN SELECT RAISE(ABORT,'immutable');END;"
        )
    raw_before, snapshot_before = digest(database), sql_snapshot(database)
    raw = original / "old-journal.jsonl"
    raw.write_bytes(b'{"unknown":"preserved"}\n')
    namespace = CowNamespace(tmp_path / "private", [original])
    with namespace:
        assert sql_snapshot(database) == snapshot_before
        with sqlite3.connect(database) as db:
            assert isinstance(db, sqlite3.Connection)
            db.execute("BEGIN IMMEDIATE")
            assert db.in_transaction
            assert db.execute("PRAGMA database_list").fetchall()[0][2] == str(database)
            db.execute("INSERT INTO unrelated VALUES('copy-only')")
        raw.write_bytes(b"shadow-only")
        nested = original / ".pool-adoption-fence"
        nested.mkdir()
        (nested / "owner.json").write_text("owned")
        assert (nested / "owner.json").read_text() == "owned"
        assert sorted(p.name for p in original.rglob("owner.json")) == ["owner.json"]
        (nested / "owner.json").unlink()
        nested.rmdir()
        new_db = original / "new.sqlite"
        with sqlite3.connect(new_db) as db:
            db.execute("CREATE TABLE only_in_copy(x)")
            assert db.execute("PRAGMA database_list").fetchall()[0][2] == str(new_db)
        with pytest.raises(PermissionError, match="external"):
            (tmp_path / "outside.txt").write_text("refuse")
    assert digest(database) == raw_before
    assert sql_snapshot(database) == snapshot_before
    assert raw.read_bytes() == b'{"unknown":"preserved"}\n'
    assert not (original / "new.sqlite").exists()
    assert namespace.pragma_events
    assert namespace.report()["production_adoption_proof"] is False


def test_authentic_native_lock_capability_still_rejects_forged_set(tmp_path):
    from evals.adapters.source_epochs import _lock_controller_roots
    from evals.timing_pool_recovery import require_native_lock_ownership

    original = tmp_path / "original"
    original.mkdir()
    with CowNamespace(tmp_path / "private", [original]):
        with ExitStack() as stack:
            locks = _lock_controller_roots([str(original)], stack)
            require_native_lock_ownership((str(original),), locks)
            assert all(lock.is_dir() for lock in locks)
            with pytest.raises(PermissionError, match="native"):
                require_native_lock_ownership((str(original),), frozenset(list(locks)))
        assert not (original / ".writer-lock").exists()
    assert list(original.iterdir()) == []


def test_original_transaction_guard_raw_fails_copy_proxy_is_disclosed(tmp_path):
    from evals.timing_pool_recovery import _require_original_budget_transaction

    original = tmp_path / "original.sqlite"
    with sqlite3.connect(original) as db:
        db.execute("CREATE TABLE x(value)")
    copy = tmp_path / "wrong.sqlite"
    with sqlite3.connect(copy) as db:
        db.execute("BEGIN IMMEDIATE")
        with pytest.raises(PermissionError, match="original budget"):
            _require_original_budget_transaction(db, original)
    namespace = CowNamespace(tmp_path / "private", [])
    with namespace, closing(sqlite3.connect(original)) as db:
        db.execute("BEGIN IMMEDIATE")
        _require_original_budget_transaction(db, original)
        assert namespace.pragma_events
        assert db.in_transaction
    assert namespace.report()["pragma_database_list_proxy"] is True


def test_genuine_native_timing_genesis_immutable_link_and_projection_transport(
    tmp_path,
):
    from evals.e_timing import ETimingCampaign
    from evals.tests.test_e_timing_replicates import registration
    from evals.verification_v2 import VerificationCampaign, _immutable

    original = tmp_path / "original"
    original.mkdir()
    frozen_registration = registration(original)
    namespace = CowNamespace(tmp_path / "private", [original])
    with namespace:
        root = original / "native-timing"
        campaign = ETimingCampaign(frozen_registration, root)
        assert campaign.events[0]["payload"]["kind"] == "campaign.registered"
        first = campaign.snapshot()
        assert first["complete_observed_trials"] == 0
        _immutable(root / "exact-native-immutable.json", {"synthetic": True})
        _immutable(root / "exact-native-immutable.json", {"synthetic": True})
        with pytest.raises(PermissionError, match="drift"):
            _immutable(root / "exact-native-immutable.json", {"synthetic": False})
        # Unchanged native atomic publisher; the small state callback is only
        # a synthetic publication fixture, not an authorization validator.
        projector = SimpleNamespace(
            root=root, _snapshot=lambda: {"synthetic": "projection"}
        )
        VerificationCampaign._project(projector)
        assert __import__("json").loads((root / "projection.json").read_bytes()) == {
            "synthetic": "projection"
        }
        assert all(path.stat().st_nlink == 1 for path in root.rglob("*.json"))
    assert not (original / "native-timing").exists()
    assert {event["operation"] for event in namespace.os_publications} == {
        "os.link",
        "os.replace",
    }


def perform_publication(operation, namespace, target):
    if operation == "guard":
        namespace._write(target)
    elif operation == "open":
        target.write_bytes(b"escaped")
    else:
        source = namespace.root / ("source-" + operation)
        source.write_bytes(b"private-only")
        getattr(os, operation)(source, target)


@pytest.mark.parametrize("operation", ["guard", "open", "link", "replace"])
def test_parent_component_escape_is_refused_for_supported_publication(
    tmp_path, operation
):
    namespace = CowNamespace(tmp_path / "private", [])
    outside = tmp_path / "outside.txt"
    target = namespace.root / ".." / outside.name
    with namespace, pytest.raises(PermissionError, match="external"):
        perform_publication(operation, namespace, target)
    assert not outside.exists()


@pytest.mark.parametrize("operation", ["guard", "open", "link", "replace"])
def test_reparse_ancestor_escape_is_refused_for_supported_publication(
    tmp_path, operation
):
    namespace = CowNamespace(tmp_path / "private", [])
    outside = tmp_path / "outside"
    outside.mkdir()
    alias = namespace.root / "linked-ancestor"
    try:
        alias.symlink_to(outside, target_is_directory=True)
    except OSError:
        if os.name != "nt":
            pytest.skip("directory symlink unavailable")
        completed = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(alias), str(outside)],
            capture_output=True,
            check=False,
        )
        if completed.returncode:
            pytest.skip("directory symlink and junction unavailable")
    with namespace, pytest.raises(PermissionError, match="external"):
        perform_publication(operation, namespace, alias / "outside.txt")
    assert list(outside.iterdir()) == []


def test_unfinished_namespace_never_claims_original_preservation(tmp_path):
    namespace = CowNamespace(tmp_path / "private", [])
    assert namespace.report()["original_complete_file_inventory_compared"] is False
    assert namespace.report().get("original_preservation_verified", False) is False


def test_exit_tamper_failure_persists_failed_report(tmp_path):
    from evals.tests.test_manual_recovery_native_rehearsal import recorded_cow_namespace

    original = tmp_path / "disposable-original"
    original.mkdir()
    marker = original / "raw-evidence.txt"
    marker.write_bytes(b"before")
    namespace = CowNamespace(tmp_path / "private", [original])
    report, output = {"status": "failed"}, tmp_path / "report.json"
    # Hold a real handle before isolation to simulate an independent writer;
    # only this disposable synthetic original is intentionally changed.
    with (
        marker.open("r+b") as independent_writer,
        pytest.raises(AssertionError, match="ORIGINAL COMPLETE FILE INVENTORY"),
        recorded_cow_namespace(namespace, report, output),
    ):
        independent_writer.write(b"tamper")
        independent_writer.flush()
        os.fsync(independent_writer.fileno())
    saved = json.loads(output.read_bytes())
    assert saved["status"] == "failed"
    assert saved["namespace"]["original_complete_file_inventory_compared"] is False
    assert saved["namespace"].get("original_preservation_verified", False) is False


def test_success_report_waits_for_completed_exit_verification(tmp_path):
    from evals.tests.test_manual_recovery_native_rehearsal import recorded_cow_namespace

    namespace = CowNamespace(tmp_path / "private", [])
    report, output = {"status": "failed"}, tmp_path / "report.json"
    with recorded_cow_namespace(namespace, report, output):
        assert report["status"] == "failed"
        assert not output.exists()
    saved = json.loads(output.read_bytes())
    assert saved["status"] == "passed"
    assert saved["namespace"]["original_preservation_verified"] is True


def test_namespace_reentry_clears_previous_verification_flags(tmp_path):
    namespace = CowNamespace(tmp_path / "private", [])
    with namespace:
        pass
    assert namespace.report()["original_preservation_verified"] is True
    with namespace:
        assert namespace.report()["preservation_verification_completed"] is False
        assert namespace.report()["original_preservation_verified"] is False
