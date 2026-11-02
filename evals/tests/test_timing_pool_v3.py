"""Synthetic startup recovery authority and journal tests; no live admission."""

import json
import sqlite3
from copy import deepcopy
from datetime import datetime, timezone
from hashlib import sha256

import pytest

from evals import timing_pool
from evals.adapters import e_planning_journal as native
from evals.contracts import canonical_hash
from evals.e_planning import planning_requests
from evals.tests.test_e_planning_limited_authority import limited_fixture
from evals.tests.test_timing_pool_v2 import pool_fixture as v2_pool_fixture
from evals.timing_pool_controller import (
    PoolJournal,
    _raw,
    pool_scope_proposal,
    validate_pool_journal_evidence,
)

SCHEMA = "task13-e-timing-pool-registration-v3"
GRANT_SCHEMA = "task13-manual-startup-recovery-grant-v1"


def startup_grant(grant):
    grant = deepcopy(grant)
    grant.update(
        schema_version=GRANT_SCHEMA,
        consumed_logical=9,
        consumed_physical=27,
        remaining_logical=4,
        remaining_physical=12,
    )
    child = grant["children"][1]
    child["authorized_request_sha256s"] = child["request_sha256s"][:1]
    child["denied_request_sha256s"] = child["request_sha256s"][1:]
    return grant


def startup_fixture(tmp_path):
    registrations, authorities = limited_fixture(tmp_path)
    grant = startup_grant(authorities[0]["migration_grant"])
    for authority, child in zip(authorities, grant["children"], strict=True):
        authority.update(
            child,
            schema_version="task13-e-planning-authority-v3",
            migration_grant=deepcopy(grant),
            migration_grant_sha256=canonical_hash(grant),
        )
    return registrations, authorities


def pool_fixture(tmp_path):
    pool = v2_pool_fixture(tmp_path)
    pool.update(schema_version=SCHEMA, future_logical_limit=4, future_physical_limit=12)
    pool["migration_grant"] = startup_grant(pool["migration_grant"])
    pool["migration_grant_sha256"] = canonical_hash(pool["migration_grant"])
    order = pool["attempt_order"] + pool["denied_attempts"]
    pool["attempt_order"], pool["denied_attempts"] = order[:4], order[4:]
    return pool


def prepare(tmp_path, pool=None):
    pool = pool or pool_fixture(tmp_path)
    return PoolJournal.prepare(
        pool["execution_journal_path"],
        pool_sha256=canonical_hash(pool),
        attempts=[a["trial_id"] for a in pool["attempt_order"]],
        imported_trial_id=timing_pool.C10_TRIAL,
        now=datetime(2026, 11, 1, tzinfo=timezone.utc),
        policy=timing_pool.pool_policy(SCHEMA),
        migration_grant=pool["migration_grant"],
        quarantined_predecessor=pool["quarantined_predecessor"],
    )


def test_v3_claims_exactly_four_and_denies_two_structural_slots(tmp_path):
    registrations, authorities = startup_fixture(tmp_path)
    claimed = []
    for registration, authority in zip(registrations, authorities, strict=True):
        path = authority["journal_path"]
        native.register_planning_slots(
            path,
            registration,
            expected_registration_sha256=canonical_hash(registration),
            authority=authority,
            expected_authority_sha256=canonical_hash(authority),
        )
        journal = native.EPlanningDispatchJournal.open_existing(
            path,
            expected_registration_sha256=canonical_hash(registration),
            expected_authority_sha256=canonical_hash(authority),
        )
        for request in planning_requests(registration):
            if canonical_hash(request) in authority["authorized_request_sha256s"]:
                claimed.append(journal.claim_planning_slot(request))
            else:
                for operation in (
                    journal.validate_request,
                    journal.claim_planning_slot,
                ):
                    with pytest.raises(PermissionError, match="not authorized"):
                        operation(request)
        with sqlite3.connect(path) as db:
            assert (
                db.execute(
                    "SELECT COUNT(*) FROM analysis_import_planning_slots"
                ).fetchone()[0]
                == 3
            )
    assert len({claim["request_sha256"] for claim in claimed}) == 4


@pytest.mark.parametrize(
    "field",
    [
        "consumed_logical",
        "consumed_physical",
        "remaining_logical",
        "remaining_physical",
        "total_logical_limit",
        "total_physical_limit",
        "analysis_inclusive_limit",
    ],
)
@pytest.mark.parametrize("kind", ["bool", "float", "increment"])
def test_v3_grant_rejects_nonexact_integer_budgets(tmp_path, field, kind):
    _, authorities = startup_fixture(tmp_path)
    grant = authorities[0]["migration_grant"]
    grant[field] = (
        True
        if kind == "bool"
        else float(grant[field])
        if kind == "float"
        else grant[field] + 1
    )
    with pytest.raises(ValueError):
        native.parse_recovery_grant(grant)


@pytest.mark.parametrize(
    "change",
    [
        "old_grant",
        "old_authority",
        "extra_authorized",
        "duplicate_child",
        "duplicate_journal",
        "duplicate_digest",
        "empty_pin",
        "cap",
        "deadline",
    ],
)
def test_v3_authority_rejects_schema_partition_and_pin_drift(tmp_path, change):
    _, authorities = startup_fixture(tmp_path)
    authority = authorities[1]
    grant = authority["migration_grant"]
    if change == "old_grant":
        grant["schema_version"] = "task13-manual-recovery-grant-v1"
    elif change == "old_authority":
        authority["schema_version"] = "task13-e-planning-authority-v2"
    elif change == "extra_authorized":
        child = grant["children"][1]
        child["authorized_request_sha256s"] = child["request_sha256s"][:2]
        child["denied_request_sha256s"] = child["request_sha256s"][2:]
        authority.update(child)
    elif change == "duplicate_child":
        grant["children"][1]["registration_sha256"] = grant["children"][0][
            "registration_sha256"
        ]
    elif change == "duplicate_journal":
        grant["children"][1]["journal_path"] = grant["children"][0]["journal_path"]
    elif change == "duplicate_digest":
        child = grant["children"][1]
        child["request_sha256s"][0] = grant["children"][0]["request_sha256s"][0]
        child["authorized_request_sha256s"] = child["request_sha256s"][:1]
    elif change == "empty_pin":
        grant["predecessor_pool_head_sha256"] = "0" * 64
    else:
        grant["development_cap_yuan" if change == "cap" else "deadline"] = "changed"
    authority["migration_grant_sha256"] = canonical_hash(grant)
    with pytest.raises(ValueError):
        native.parse_authority(authority)


def test_explicit_grant_parser_preserves_legacy_canonical_value(tmp_path):
    _, authorities = limited_fixture(tmp_path)
    grant = authorities[0]["migration_grant"]
    assert native.parse_recovery_grant(grant).model_dump(mode="json") == grant
    for bad in (None, {}, {**grant, "schema_version": "unknown"}):
        with pytest.raises(ValueError):
            native.parse_recovery_grant(bad)


def test_v3_policy_structure_and_projection_keep_exact_four_plus_two(tmp_path):
    pool = pool_fixture(tmp_path)
    selected = timing_pool.pool_policy(pool)
    assert (
        selected.future_logical_limit,
        selected.future_physical_limit,
        selected.historical_logical,
        selected.historical_physical,
    ) == (4, 12, 9, 27)
    assert selected.receipt_schema == "task13-e-timing-pool-receipt-v3"
    assert timing_pool.validate_pool_structure(pool) == pool
    proposal = pool_scope_proposal(pool)
    assert [
        len(c["authorized_request_sha256s"])
        for c in proposal["migration_grant"]["children"]
    ] == [3, 1]
    assert proposal["migration_grant"]["scope_packet_sha256"] == "0" * 64
    assert proposal["migration_grant_sha256"] == canonical_hash(
        proposal["migration_grant"]
    )
    assert proposal["quarantined_predecessor"] == pool["quarantined_predecessor"]


@pytest.mark.parametrize(
    "change",
    [
        "five",
        "missing_denied",
        "old_grant",
        "old_pool",
        "wrong_head",
        "reordered_children",
    ],
)
def test_v3_pool_rejects_expansion_mixed_schemas_and_predecessor_drift(
    tmp_path, change
):
    pool = pool_fixture(tmp_path)
    if change == "five":
        pool["future_logical_limit"] = 5
        pool["attempt_order"].append(pool["denied_attempts"].pop(0))
    elif change == "missing_denied":
        pool["denied_attempts"].pop()
    elif change == "old_grant":
        pool["migration_grant"]["schema_version"] = "task13-manual-recovery-grant-v1"
    elif change == "old_pool":
        pool["schema_version"] = timing_pool.RECOVERY_REGISTRATION_SCHEMA
    elif change == "wrong_head":
        pool["quarantined_predecessor"]["pool_head_sha256"] = "b" * 64
    else:
        pool["children"].reverse()
    with pytest.raises(PermissionError):
        timing_pool.validate_pool_structure(pool)


def test_v3_genesis_consumes_history_nine_and_binds_full_grant(tmp_path):
    pool = pool_fixture(tmp_path)
    journal = prepare(tmp_path, pool)
    state = journal.status()
    assert (
        state["consumed_logical"],
        state["physical_upper_bound"],
        state["analysis_inclusive_upper_bound"],
        state["attempted"],
        state["pending"],
    ) == (9, 27, 28, 0, None)
    evidence = {
        "pool_journal": {
            "path": str(journal.path),
            "sha256": timing_pool.file_sha256(journal.path),
            "head_sha256": state["journal_head"],
        }
    }
    assert validate_pool_journal_evidence(evidence, pool)["state"] == state
    journal.begin(
        pool["attempt_order"][0]["trial_id"],
        now=datetime(2026, 11, 1, tzinfo=timezone.utc),
        quiescent=True,
        reserved_yuan="0.5",
    )
    assert journal.status()["consumed_logical"] == 10
    assert journal.status()["physical_upper_bound"] == 30
    with pytest.raises(PermissionError, match="pending|unknown"):
        journal.begin(
            pool["attempt_order"][0]["trial_id"],
            now=datetime(2026, 11, 1, tzinfo=timezone.utc),
            quiescent=True,
            reserved_yuan="0.5",
        )


def test_v3_journal_rejects_valid_but_mixed_v2_grant(tmp_path):
    pool = pool_fixture(tmp_path)
    _, authorities = limited_fixture(tmp_path)
    pool["migration_grant"] = authorities[0]["migration_grant"]
    with pytest.raises(PermissionError):
        prepare(tmp_path, pool)


def test_v3_rehashed_genesis_cannot_change_full_frozen_grant(tmp_path):
    pool = pool_fixture(tmp_path)
    journal = prepare(tmp_path, pool)
    event = json.loads(journal.path.read_bytes())
    event["payload"]["migration_grant"]["decision_record_sha256"] = "e" * 64
    event.pop("sha256")
    event["sha256"] = sha256(_raw(event)).hexdigest()
    journal.path.write_bytes(_raw(event) + b"\n")
    evidence = {
        "pool_journal": {
            "path": str(journal.path),
            "sha256": timing_pool.file_sha256(journal.path),
            "head_sha256": event["sha256"],
        }
    }
    with pytest.raises(PermissionError, match="genesis|grant"):
        validate_pool_journal_evidence(evidence, pool)


@pytest.mark.parametrize("change", [None, "activity", "missing", "duplicate", "extra"])
def test_v3_inventory_requires_two_untouched_denied_slots(change):
    from evals.timing_pool_evidence import validate_attempt_inventory

    order = [f"t{i}" for i in range(4)]
    denied = ["denied-0", "denied-1"]
    states = {
        trial: {"status": "not_started", "binding": None} for trial in order + denied
    }
    if change == "activity":
        states[denied[1]]["review_pending"] = True
    elif change == "missing":
        denied.pop()
    elif change == "duplicate":
        denied[1] = denied[0]
    elif change == "extra":
        states["unreported"] = {"status": "not_started", "binding": None}
    arguments = {
        "require_complete": False,
        "policy": timing_pool.pool_policy(SCHEMA),
        "denied_trial_ids": denied,
    }
    if change is None:
        assert validate_attempt_inventory(order, [], states, [], **arguments) == []
    else:
        with pytest.raises(PermissionError, match="denied|excluded"):
            validate_attempt_inventory(order, [], states, [], **arguments)


def test_v3_fresh_quiescence_requires_quarantined_predecessor_absence(
    tmp_path, monkeypatch
):
    from types import SimpleNamespace

    from evals.timing_pool_evidence import _quiescence

    termination = tmp_path / "termination"
    termination.mkdir()
    pool = pool_fixture(tmp_path)
    contexts = {
        "child": {
            "reader": SimpleNamespace(
                _termination=termination, _inputs={"pool_authority": pool}
            )
        }
    }
    monkeypatch.setattr(
        timing_pool,
        "validate_recovery_quarantine",
        lambda p: {"workers": [{"container_id": "old-container"}]},
    )
    proof = {"inspected_at": "2026-11-01T00:00:00+00:00", "proofs": []}
    with pytest.raises(PermissionError, match="quarantine predecessor"):
        _quiescence(proof, contexts)
    proof["quarantined_predecessor_workers"] = {
        "schema_version": "task13-manual-quarantine-worker-absence-v1",
        "status": "verified",
        "workers": [
            {
                "container_id": "old-container",
                "inspection": {
                    "argv": [
                        "docker",
                        "container",
                        "ls",
                        "--all",
                        "--no-trunc",
                        "--filter",
                        "id=old-container",
                        "--format",
                        "{{.ID}}",
                    ],
                    "returncode": 0,
                    "stdout_sha256": sha256(b"").hexdigest(),
                    "stderr_sha256": sha256(b"").hexdigest(),
                },
            }
        ],
    }
    assert _quiescence(proof, contexts).isoformat() == proof["inspected_at"]


@pytest.mark.parametrize(
    "host_schema", ["task13-e-timing-pool-host-v3", "task13-e-timing-pool-host-v2"]
)
def test_v3_controller_evidence_selects_explicit_host_schema(
    tmp_path, monkeypatch, host_schema
):
    from evals import timing_pool_evidence

    pool = pool_fixture(tmp_path)
    # Stop after the real version/raw-reference gate, before native evidence reads.
    marker = {"path": str(tmp_path / "marker.json"), "sha256": "b" * 64}
    pool["original_account_baseline"] = marker
    manifest = {
        "schema_version": host_schema,
        "pool_registration": "pool-pin",
        "hosts": {},
        "journal_path": pool["execution_journal_path"],
        "migration_marker": pool["quarantine_record"],
        "original_account_baseline": marker,
    }
    evidence = {
        "pool_host_manifest": "manifest-pin",
        "host_manifests": {},
        "pool_journal": {"path": pool["execution_journal_path"]},
        "migration_marker": pool["quarantine_record"],
    }
    monkeypatch.setattr(
        timing_pool_evidence,
        "_pin",
        lambda pin: manifest if pin == "manifest-pin" else pool,
    )
    monkeypatch.setattr(timing_pool, "_plain", lambda p: p)

    class ManifestAccepted(Exception):
        pass

    def after_manifest(*args):
        raise ManifestAccepted

    import evals.timing_pool_controller as controller

    monkeypatch.setattr(controller, "validate_pool_journal_evidence", after_manifest)
    expected = ManifestAccepted if host_schema.endswith("v3") else PermissionError
    with pytest.raises(expected):
        timing_pool_evidence.validate_controller_evidence(evidence, pool, {})


def test_v3_four_consumed_attempts_end_at_original_maxima(tmp_path):
    pool = pool_fixture(tmp_path)
    journal = prepare(tmp_path, pool)
    for index, attempt in enumerate(pool["attempt_order"]):
        journal.begin(
            attempt["trial_id"],
            now=datetime(2026, 11, 1, tzinfo=timezone.utc),
            quiescent=True,
            reserved_yuan="0.5",
        )
        journal.settle(
            attempt["trial_id"],
            outcome="ttl_infrastructure_failure",
            actual_yuan="0",
            quiescent=True,
            observed_max_seconds=0,
            evidence_sha256=str(index + 1) * 64,
        )
        journal.resume(quiescent=True, fresh_guard_sha256="a" * 64, guard_cost_yuan="0")
    state = journal.status()
    assert (
        state["attempted"],
        state["consumed_logical"],
        state["physical_upper_bound"],
        state["analysis_inclusive_upper_bound"],
    ) == (4, 13, 39, 40)
    with pytest.raises(PermissionError, match="exhausted"):
        journal.begin(
            "unauthorized-fifth",
            now=datetime(2026, 11, 1, tzinfo=timezone.utc),
            quiescent=True,
            reserved_yuan="0.5",
        )


@pytest.mark.parametrize("denied_index", [1, 2])
def test_v3_native_read_rejects_forged_claim_in_either_denied_slot(
    tmp_path, denied_index
):
    registrations, authorities = startup_fixture(tmp_path)
    registration, authority = registrations[1], authorities[1]
    path = authority["journal_path"]
    native.register_planning_slots(
        path,
        registration,
        expected_registration_sha256=canonical_hash(registration),
        authority=authority,
        expected_authority_sha256=canonical_hash(authority),
    )
    request = planning_requests(registration)[denied_index]
    with sqlite3.connect(path) as db:
        db.execute(
            "INSERT INTO analysis_import_planning_claims VALUES (?,?,?,'started')",
            (request.planning_slot_id, canonical_hash(request), request.incident_id),
        )
    with pytest.raises(ValueError, match="registered planning authority differs"):
        native.EPlanningDispatchJournal.open_existing(
            path,
            expected_registration_sha256=canonical_hash(registration),
            expected_authority_sha256=canonical_hash(authority),
        )


def test_v3_child_authority_join_rejects_other_child_and_v2_pool(tmp_path):
    pool = pool_fixture(tmp_path)
    _, authorities = startup_fixture(tmp_path)
    for authority, child in zip(
        authorities, pool["migration_grant"]["children"], strict=True
    ):
        authority.update(
            child,
            migration_grant=deepcopy(pool["migration_grant"]),
            migration_grant_sha256=pool["migration_grant_sha256"],
        )
    timing = pool["children"][0]["registration"]
    timing["planning_dispatch_registration_receipt"]["authority_sha256"] = (
        canonical_hash(authorities[0])
    )
    assert (
        type(timing_pool.require_recovery_child_authority(pool, timing, authorities[0]))
        is native.StartupLimitedEPlanningAuthority
    )
    for bad_pool, bad_authority in (
        (pool, authorities[1]),
        (
            {**pool, "schema_version": timing_pool.RECOVERY_REGISTRATION_SCHEMA},
            authorities[0],
        ),
    ):
        with pytest.raises(PermissionError, match="child|grant"):
            timing_pool.require_recovery_child_authority(
                bad_pool, timing, bad_authority
            )
