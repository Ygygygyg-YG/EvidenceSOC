"""Free synthetic limited authority; no Docker, providers or real registrations."""

import sqlite3
from copy import deepcopy

import pytest

from evals.adapters import e_planning_journal as native
from evals.contracts import canonical_hash
from evals.e_planning import _slots, planning_requests, validate_e_planning_registration
from evals.tests.test_e_planning_contracts import registration_fixture
from evals.tests.test_e_planning_journal import authority_fixture


def limited_fixture(tmp_path):
    registrations = [registration_fixture(), registration_fixture()]
    registrations[1]["registration_id"] = "2" * 32
    registrations[1]["slots"] = _slots("2" * 32, registrations[1]["source"]["case_id"])
    registrations[1] = validate_e_planning_registration(registrations[1])
    authorities = [
        authority_fixture(tmp_path / f"child-{i}.sqlite", registration)
        for i, registration in enumerate(registrations)
    ]
    children = [
        {
            "registration_sha256": authority["registration_sha256"],
            "journal_path": authority["journal_path"],
            "request_sha256s": authority["request_sha256s"],
            "authorized_request_sha256s": authority["request_sha256s"][: 3 - i],
            "denied_request_sha256s": authority["request_sha256s"][3 - i :],
        }
        for i, authority in enumerate(authorities)
    ]
    grant = {
        "schema_version": "task13-manual-recovery-grant-v1",
        "recovery_id": "9" * 32,
        "recovery_plan_sha256": "5" * 64,
        "quarantine_record_sha256": "6" * 64,
        "predecessor_pool_registration_sha256": "7" * 64,
        "predecessor_pool_journal_sha256": "8" * 64,
        "predecessor_pool_head_sha256": "9" * 64,
        "scope_packet_sha256": "3" * 64,
        "decision_record_sha256": "4" * 64,
        "consumed_logical": 8,
        "consumed_physical": 24,
        "remaining_logical": 5,
        "remaining_physical": 15,
        "total_logical_limit": 13,
        "total_physical_limit": 39,
        "analysis_inclusive_limit": 40,
        "development_cap_yuan": "6",
        "deadline": "2026-11-02T23:59:59+08:00",
        "children": children,
    }
    for authority, child in zip(authorities, children, strict=True):
        authority.update(
            schema_version="task13-e-planning-authority-v2",
            authorized_request_sha256s=child["authorized_request_sha256s"],
            denied_request_sha256s=child["denied_request_sha256s"],
            migration_grant=deepcopy(grant),
            migration_grant_sha256=canonical_hash(grant),
        )
    return registrations, authorities


def register_limited(tmp_path, child=1):
    registrations, authorities = limited_fixture(tmp_path)
    registration, authority = registrations[child], authorities[child]
    path = tmp_path / f"child-{child}.sqlite"
    receipt = native.register_planning_slots(
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
    return registration, authority, path, receipt, journal


def test_versioned_parser_preserves_v1_canonical_value(tmp_path):
    parse = getattr(native, "parse_authority", None)
    assert callable(parse), "native versioned authority parser is required"
    value = authority_fixture(tmp_path / "unused.sqlite", registration_fixture())
    original = deepcopy(value)
    parsed = parse(value)
    assert type(parsed) is native.EPlanningAuthority
    assert parsed.model_dump(mode="json") == original
    assert canonical_hash(parsed) == canonical_hash(original)
    assert value == original
    with pytest.raises(ValueError):
        parse({**value, "schema_version": "task13-e-planning-authority-v3"})


def test_v2_registers_three_native_slots_but_refuses_the_denied_slot(tmp_path):
    registration, authority, path, receipt, journal = register_limited(tmp_path)
    requests = planning_requests(registration)
    assert len(receipt["planning_slot_ids"]) == 3
    assert len(authority["authorized_request_sha256s"]) == 2
    with sqlite3.connect(path) as db:
        assert (
            db.execute(
                "SELECT COUNT(*) FROM analysis_import_planning_slots"
            ).fetchone()[0]
            == 3
        )
    for request in requests[:2]:
        assert journal.validate_request(request)["status"] == "unclaimed"
        assert journal.claim_planning_slot(request)["status"] == "started"
        assert request.response_call_limit.model_dump() == {"logical": 1, "physical": 3}
    for operation in (journal.validate_request, journal.claim_planning_slot):
        with pytest.raises(PermissionError, match="not authorized"):
            operation(requests[2])
    with sqlite3.connect(path) as db:
        assert (
            db.execute(
                "SELECT COUNT(*) FROM analysis_import_planning_claims"
            ).fetchone()[0]
            == 2
        )


def test_read_rejects_a_forged_claim_on_a_denied_slot(tmp_path):
    registration, authority, path, _, _ = register_limited(tmp_path)
    request = planning_requests(registration)[2]
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


@pytest.mark.parametrize(
    "change",
    [
        "grant_hash",
        "scope",
        "decision",
        "registration",
        "journal",
        "request",
        "authorized",
        "denied",
        "reordered",
        "overlap",
        "missing",
        "sixth",
        "duplicate_child",
        "duplicate_request",
        "empty_pin",
        "budget_bool",
        "consumed_logical",
        "consumed_physical",
        "remaining_logical",
        "remaining_physical",
        "total_logical_limit",
        "total_physical_limit",
        "analysis_inclusive_limit",
        "development_cap_yuan",
        "deadline",
    ],
)
def test_v2_rejects_rebinding_partition_and_migration_budget_drift(tmp_path, change):
    registrations, authorities = limited_fixture(tmp_path)
    value = deepcopy(authorities[1])
    grant = value["migration_grant"]
    if change == "grant_hash":
        value["migration_grant_sha256"] = "0" * 64
    elif change in {"scope", "decision", "registration"}:
        value[
            {
                "scope": "scope_packet_sha256",
                "decision": "decision_record_sha256",
                "registration": "registration_sha256",
            }[change]
        ] = "a" * 64
    elif change == "journal":
        value["journal_path"] = str(tmp_path / "other.sqlite")
    elif change == "request":
        value["request_sha256s"][0] = "a" * 64
    elif change == "authorized":
        value["authorized_request_sha256s"] = value["request_sha256s"][:1]
    elif change == "denied":
        value["denied_request_sha256s"] = []
    elif change == "reordered":
        value["authorized_request_sha256s"].reverse()
    elif change == "overlap":
        value["denied_request_sha256s"] = value["request_sha256s"][:1]
    elif change == "missing":
        value["request_sha256s"] = value["request_sha256s"][:2]
    elif change == "sixth":
        grant["children"][1]["authorized_request_sha256s"] = grant["children"][1][
            "request_sha256s"
        ]
        grant["children"][1]["denied_request_sha256s"] = []
    elif change == "duplicate_child":
        grant["children"][1] = deepcopy(grant["children"][0])
    elif change == "duplicate_request":
        grant["children"][1]["request_sha256s"][0] = grant["children"][0][
            "request_sha256s"
        ][0]
        grant["children"][1]["authorized_request_sha256s"][0] = grant["children"][0][
            "request_sha256s"
        ][0]
    elif change == "empty_pin":
        grant["predecessor_pool_head_sha256"] = "0" * 64
    elif change == "budget_bool":
        grant["remaining_logical"] = True
    elif change in {"development_cap_yuan", "deadline"}:
        grant[change] = "changed"
    else:
        grant[change] += 1
    if change != "grant_hash":
        value["migration_grant_sha256"] = canonical_hash(grant)
    with pytest.raises((ValueError, PermissionError)):
        native.register_planning_slots(
            tmp_path / "child-1.sqlite",
            registrations[1],
            expected_registration_sha256=canonical_hash(registrations[1]),
            authority=value,
            expected_authority_sha256=canonical_hash(value),
        )
    assert not (tmp_path / "child-1.sqlite").exists()


def test_native_three_plus_two_authorities_grant_exactly_five(tmp_path):
    claims = []
    for child in (0, 1):
        registration, _, _, _, journal = register_limited(tmp_path, child)
        for request in planning_requests(registration)[: 3 - child]:
            claims.append(journal.claim_planning_slot(request))
    assert len({claim["request_sha256"] for claim in claims}) == 5


def test_existing_host_journal_parser_accepts_limited_authority(tmp_path):
    from scripts.task13_e_trial import ETrialController

    registration, authority, _, receipt, _ = register_limited(tmp_path)
    host = object.__new__(ETrialController)
    host._planning = registration
    host._timing = {"planning_dispatch_registration_receipt": receipt}
    host._inputs = {"planning_authority": authority}
    host._manifest = {"synthetic": True}
    journal = host._journal()
    assert (
        journal.validate_request(planning_requests(registration)[1])["status"]
        == "unclaimed"
    )
