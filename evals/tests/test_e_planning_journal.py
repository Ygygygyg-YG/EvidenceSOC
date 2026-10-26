"""Temporary synthetic host authority and one-time planning slot admission."""

import json
import shutil
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy

import pytest

from evals.contracts import canonical_hash
from evals.tests.test_e_planning_contracts import registration_fixture


def authority_fixture(path, registration):
    from evals.e_planning import planning_requests

    return {
        "schema_version": "task13-e-planning-authority-v1",
        "campaign_id": registration["campaign_id"],
        "registration_sha256": canonical_hash(registration),
        "journal_path": str(path.resolve()),
        "scope_packet_sha256": "3" * 64,
        "decision_record_sha256": "4" * 64,
        "decision": "approved",
        "decided_by": "user",
        "decided_at": "2026-10-25T12:00:00+00:00",
        "purpose": "development",
        "synthetic": True,
        "request_sha256s": [canonical_hash(r) for r in planning_requests(registration)],
    }


def register_fixture(path, registration=None, **overrides):
    from evals.adapters.e_planning_journal import register_planning_slots

    registration = registration or registration_fixture()
    authority = authority_fixture(path, registration)
    arguments = {
        "expected_registration_sha256": canonical_hash(registration),
        "authority": authority,
        "expected_authority_sha256": canonical_hash(authority),
    }
    arguments.update(overrides)
    receipt = register_planning_slots(path, registration, **arguments)
    return registration, authority, receipt


def open_fixture(path, registration, authority):
    from evals.adapters.e_planning_journal import EPlanningDispatchJournal

    return EPlanningDispatchJournal.open_existing(
        path,
        expected_registration_sha256=canonical_hash(registration),
        expected_authority_sha256=canonical_hash(authority),
    )


def test_host_registration_is_three_slots_not_approval_or_epoch_registration(tmp_path):
    from evals.e_planning import planning_requests

    path = tmp_path / "synthetic-dispatch.sqlite"
    registration, authority, receipt = register_fixture(path)
    journal = open_fixture(path, registration, authority)
    assert receipt["registration_sha256"] == canonical_hash(registration)
    assert receipt["authority_sha256"] == canonical_hash(authority)
    with sqlite3.connect(path) as db:
        tables = {
            r[0]
            for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        assert tables == {
            "e_planning_registration",
            "analysis_import_planning_slots",
            "analysis_import_planning_claims",
        }
        assert (
            db.execute(
                "SELECT COUNT(*) FROM analysis_import_planning_slots"
            ).fetchone()[0]
            == 3
        )
    receipts = [
        journal.claim_planning_slot(request)
        for request in planning_requests(registration)
    ]
    assert len({r["planning_slot_id"] for r in receipts}) == 3
    assert len({r["source_identity"] for r in receipts}) == 1
    assert all(r["status"] == "started" for r in receipts)


@pytest.mark.parametrize(
    "kind", ["authority_hash", "registration_hash", "path", "decision", "worker"]
)
def test_unpinned_or_worker_registration_is_rejected_without_creating_db(
    tmp_path, monkeypatch, kind
):
    from evals.adapters.e_planning_journal import register_planning_slots

    path = tmp_path / "synthetic-dispatch.sqlite"
    registration = registration_fixture()
    authority = authority_fixture(path, registration)
    reg_hash, authority_hash = canonical_hash(registration), canonical_hash(authority)
    if kind == "authority_hash":
        authority_hash = "0" * 64
    elif kind == "registration_hash":
        reg_hash = "0" * 64
    elif kind == "path":
        authority["journal_path"] = str(tmp_path / "another.sqlite")
        authority_hash = canonical_hash(authority)
    elif kind == "decision":
        authority["decision"] = "pending"
        authority_hash = canonical_hash(authority)
    else:
        monkeypatch.setenv("TASK13_WORKER_NONCE", "synthetic-worker")
    with pytest.raises((ValueError, PermissionError)):
        register_planning_slots(
            path,
            registration,
            expected_registration_sha256=reg_hash,
            authority=authority,
            expected_authority_sha256=authority_hash,
        )
    assert not path.exists()


def test_existing_open_never_creates_a_journal(tmp_path):
    from evals.adapters.e_planning_journal import EPlanningDispatchJournal

    path = tmp_path / "missing.sqlite"
    with pytest.raises(ValueError):
        EPlanningDispatchJournal.open_existing(
            path,
            expected_registration_sha256="a" * 64,
            expected_authority_sha256="b" * 64,
        )
    assert not path.exists()


def test_started_unknown_and_restart_never_authorize_replay(tmp_path):
    from evals.e_planning import planning_requests

    path = tmp_path / "synthetic-dispatch.sqlite"
    registration, authority, _ = register_fixture(path)
    request = planning_requests(registration)[0]
    open_fixture(path, registration, authority).claim_planning_slot(request)
    with pytest.raises(PermissionError, match="already started"):
        open_fixture(path, registration, authority).claim_planning_slot(request)
    # No completion/failure/update API exists: a crash or unknown keeps the claim.
    with sqlite3.connect(path) as db, pytest.raises(sqlite3.IntegrityError):
        db.execute("DELETE FROM analysis_import_planning_claims")


def test_two_concurrent_workers_can_consume_a_slot_only_once(tmp_path):
    from evals.e_planning import planning_requests

    path = tmp_path / "synthetic-dispatch.sqlite"
    registration, authority, _ = register_fixture(path)
    request = planning_requests(registration)[1]

    def claim(_):
        try:
            open_fixture(path, registration, authority).claim_planning_slot(request)
            return "started"
        except PermissionError:
            return "refused"

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(claim, range(2))) == ["refused", "started"]


def test_changed_epoch_or_new_fourth_slot_cannot_bypass_registered_request(tmp_path):
    from evals.adapters.e_planning_contracts import EPlanningRequest
    from evals.e_planning import planning_requests

    path = tmp_path / "synthetic-dispatch.sqlite"
    registration, authority, _ = register_fixture(path)
    journal = open_fixture(path, registration, authority)
    request = planning_requests(registration)[0].model_dump(mode="json")
    request["epoch_id"] = "synthetic-epoch-2"
    with pytest.raises(PermissionError, match="registered"):
        journal.claim_planning_slot(EPlanningRequest.model_validate(request))
    request["ordinal"] = 4
    with pytest.raises(ValueError):
        EPlanningRequest.model_validate(request)


def test_registration_and_slots_are_append_only_and_cannot_add_new_campaign(tmp_path):
    path = tmp_path / "synthetic-dispatch.sqlite"
    registration, authority, receipt = register_fixture(path)
    assert register_fixture(path, registration)[2] == receipt
    for table in ("e_planning_registration", "analysis_import_planning_slots"):
        with sqlite3.connect(path) as db, pytest.raises(sqlite3.IntegrityError):
            db.execute(f"DELETE FROM {table}")
    changed = deepcopy(registration)
    changed["registration_id"] = "2" * 32
    with pytest.raises(ValueError):
        register_fixture(path, changed)
    assert open_fixture(path, registration, authority)


def test_forged_table_request_or_external_hash_is_rejected(tmp_path):
    path = tmp_path / "synthetic-dispatch.sqlite"
    registration, authority, _ = register_fixture(path)
    with pytest.raises(ValueError):
        from evals.adapters.e_planning_journal import EPlanningDispatchJournal

        EPlanningDispatchJournal.open_existing(
            path,
            expected_registration_sha256=canonical_hash(registration),
            expected_authority_sha256="0" * 64,
        )
    with sqlite3.connect(path) as db:
        db.execute("DROP TRIGGER e_planning_slots_no_update")
        raw = db.execute(
            "SELECT request_json FROM analysis_import_planning_slots LIMIT 1"
        ).fetchone()[0]
        forged = json.loads(raw)
        forged["epoch_id"] = "synthetic-epoch-2"
        db.execute(
            "UPDATE analysis_import_planning_slots SET request_json=?",
            (json.dumps(forged),),
        )
    with pytest.raises(ValueError, match="registered"):
        open_fixture(path, registration, authority)


def test_host_cannot_replay_from_a_copied_journal(tmp_path):
    path = tmp_path / "synthetic-dispatch.sqlite"
    registration, authority, _ = register_fixture(path)
    copied = tmp_path / "copy.sqlite"
    shutil.copyfile(path, copied)
    with pytest.raises(ValueError, match="path|mount"):
        open_fixture(copied, registration, authority)


@pytest.mark.parametrize(
    "mutation", ["selection", "package", "original_reply", "budget_receipt"]
)
def test_rebound_full_receipt_and_request_cannot_replace_external_registered_pins(
    tmp_path, mutation
):
    from evals.adapters.e_planning_contracts import EPlanningRequest
    from evals.e_planning import planning_requests

    path = tmp_path / "synthetic-dispatch.sqlite"
    registration, authority, _ = register_fixture(path)
    journal = open_fixture(path, registration, authority)
    request = planning_requests(registration)[0].model_dump(mode="json")
    entry = request["selected_source_lineage"]["selected_sources"][0]
    if mutation == "selection":
        request["source_selection_receipt_sha256"] = "0" * 64
        request["selected_source_lineage"]["source_selection_receipt_sha256"] = "0" * 64
    elif mutation == "package":
        request["source_package_manifest_sha256"] = "0" * 64
        request["source"]["source_package_manifest_sha256"] = "0" * 64
        entry["source_package_manifest_sha256"] = "0" * 64
    elif mutation == "original_reply":
        request["analysis_output_sha256"] = "0" * 64
        request["source"]["analysis_output_sha256"] = "0" * 64
        entry["source_analysis_output_sha256"] = "0" * 64
    else:
        request["source_sha256"] = request["budget_source_receipt_sha256"] = "0" * 64
    request["selected_source_lineage_sha256"] = canonical_hash(
        request["selected_source_lineage"]
    )
    request["registration_sha256"] = canonical_hash(
        ["synthetic-rebound-registration", request]
    )
    # It is internally coherent JSON, but it is a different complete request from
    # the independently pinned registration/authority; no claim may be inserted.
    forged = EPlanningRequest.model_validate(request)
    assert canonical_hash(forged) != authority["request_sha256s"][0]
    with pytest.raises((ValueError, PermissionError), match="registered|registration"):
        journal.claim_planning_slot(forged)
    # Restoring only the outer registration hash cannot hide the substituted data.
    request["registration_sha256"] = canonical_hash(registration)
    with pytest.raises((ValueError, PermissionError), match="registered|request"):
        journal.claim_planning_slot(EPlanningRequest.model_validate(request))
    with sqlite3.connect(path) as db:
        assert (
            db.execute(
                "SELECT COUNT(*) FROM analysis_import_planning_claims"
            ).fetchone()[0]
            == 0
        )
