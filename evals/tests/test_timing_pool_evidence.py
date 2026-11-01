"""Pool evidence tests; local reads only, never execution or approval creation."""

from importlib import import_module, util
from pathlib import Path

import pytest

RAW = Path(
    r"D:\传智杯\data\task13\supplements\task13-repair-202610-v2\development\timing-v2-rebind-candidate-20261101-e5c49a24\host-output\timing"
)
GOOD = "b99f2588f98db830904ec9dd2e63944e"


def test_native_host_read_receipt_uses_exact_serialized_raw_bytes(tmp_path):
    from hashlib import sha256

    from evals.contracts import canonical_hash
    from evals.timing_pool_evidence import _native_host_read_receipt_path
    from scripts.task13_e_trial import _bytes

    receipt = {"schema_version": "task13-e-host-review-read-v1", "model_calls": 0}
    raw = _bytes(receipt)
    digest = sha256(raw).hexdigest()
    assert raw.endswith(b"\n") and digest != canonical_hash(receipt)
    path = tmp_path / "artifacts/host-review-read" / digest
    path.parent.mkdir(parents=True)
    path.write_bytes(raw)
    assert _native_host_read_receipt_path(tmp_path, receipt) == path
    # Equal decoded JSON cannot substitute different original bytes.
    path.write_bytes(raw.rstrip(b"\n"))
    with pytest.raises(PermissionError):
        _native_host_read_receipt_path(tmp_path, receipt)


@pytest.mark.parametrize(
    "field",
    [
        "source",
        "approval_packet",
        "approval_receipt",
        "operation",
        "request_id",
        "source_state_sha256",
        "planning_slot_id",
        "registration_sha256",
        "selected_source_lineage_sha256",
    ],
)
def test_review_wrapper_cannot_resign_fields_absent_from_original_stdout(field):
    """Changing wrapper JSON cannot change the independent captured worker reply."""
    from copy import deepcopy
    from types import SimpleNamespace

    pool = module()
    view = pool._view(RAW)
    trial = view.trials[GOOD]
    terminal = pool._json(
        RAW.parent
        / "slots"
        / trial["binding"]["planning_slot_id"]
        / "decision-terminal.json"
    )
    value = pool._json(terminal["runtime_result"]["path"])
    host = pool._json(RAW.parent / "host-binding.json")
    options = pool._json(host["inputs"]["runtime_options"]["path"])
    request = SimpleNamespace(
        schema_version="task13-e-planning-review-v1",
        request_id=value["request_id"],
        case_id=view.registration["trials"][0]["case_id"],
        source_commit=view.registration["source_commit"],
    )
    pool._validate_runtime_capture(value, terminal, options, request)
    forged = deepcopy(value)
    forged[field] = (
        {"SYNTHETIC_TAMPER": True}
        if isinstance(value[field], dict)
        else "SYNTHETIC_TAMPER"
    )
    with pytest.raises(PermissionError, match="stdout"):
        pool._validate_runtime_capture(forged, terminal, options, request)


def module():
    assert util.find_spec("evals.timing_pool"), "pool evidence module missing"
    return import_module("evals.timing_pool")


@pytest.fixture(scope="module")
def actual_c10():
    return module().read_native_observation(RAW, GOOD)


def test_c10_single_observation_keeps_native_identity_and_rejected_history(actual_c10):
    result = actual_c10
    assert result["duration_monotonic_seconds"] == 384.562
    assert result["duration_wall_seconds"] == pytest.approx(384.553890)
    assert (
        result["identity"]["source_commit"]
        == "e5c49a2496efe24817facdede7fef9859f022312"
    )
    assert [x["status"] for x in result["journal_trials"]] == [
        "completed",
        "rejected",
        "not_started",
    ]
    assert len(result["branches"]) == 6


@pytest.mark.parametrize("trial", ["1d17526adb3087277870d5dacc460b5c", "not-existing"])
def test_rejected_or_missing_trial_cannot_import(trial):
    with pytest.raises(PermissionError):
        module().read_native_observation(RAW, trial)


def test_no_fabricated_receipt_or_registration():
    with pytest.raises(PermissionError):
        module().validate_pool_receipt({}, {})
    with pytest.raises(PermissionError):
        module().validate_pool_registration({})


def test_entire_worker_manifest_anchored_not_self_declared():
    import json

    source = RAW.parent.parent / "source"
    files = json.loads((source / "source_receipt.json").read_text())["files"]
    pool = {
        "measurement_files": files,
        "original_measurement_files": files.copy(),
        "original_measurement_root": str(source),
        "measurement_root": str(Path(__file__).resolve().parents[2]),
    }
    assert module().validate_measurement_equivalence(pool) == files
    tampered = files.copy()
    key = next(iter(tampered))
    tampered[key] = "0" * 64
    pool["measurement_files"] = tampered
    pool["original_measurement_files"] = tampered.copy()
    with pytest.raises(PermissionError):
        module().validate_measurement_equivalence(pool)


@pytest.mark.parametrize("category", ["approvals", "host-receipts", "receipts"])
def test_missing_evidence_fails_closed(tmp_path, category):
    import shutil

    copy = tmp_path / "timing"
    shutil.copytree(RAW, copy)
    next((copy / category).iterdir()).unlink()
    with pytest.raises(PermissionError):
        module().read_native_observation(copy, GOOD)


def test_planning_model_and_environment_are_actual_observation_conditions(actual_c10):
    observation = actual_c10
    conditions = observation["actual_conditions"]
    assert conditions["received_model"] == {
        "response_model": "deepseek-flash",
        "fingerprint": "bc19ba97cbe016479903222bb1578db6",
    }
    assert conditions["image_id"].startswith("sha256:")
    assert conditions["dependencies_tree_sha256"]
    assert conditions["knowledge_sha256"]


def test_config_equivalence_only_disclosed_control_changes():
    from copy import deepcopy

    old = {
        "model": {"temperature": 0},
        "plan_ttl_seconds": 1800,
        "participation_policy": {"authorization_record_sha256": "a" * 64},
    }
    new = deepcopy(old)
    new["participation_policy"] = {"authorization_record_sha256": "b" * 64}
    disclosure = {
        "participation_policy": {
            "before": old["participation_policy"],
            "after": new["participation_policy"],
        }
    }
    module().validate_condition_equivalence(old, new, disclosure)
    with pytest.raises(PermissionError):
        module().validate_condition_equivalence(old, new, {})
    new["model"]["temperature"] = 1
    with pytest.raises(PermissionError):
        module().validate_condition_equivalence(old, new, disclosure)


def test_resigned_c10_history_not_new_eligible_provenance(tmp_path):
    import json
    import shutil

    from evals.contracts import canonical_hash

    copy = tmp_path / "timing"
    shutil.copytree(RAW, copy)
    path = max((copy / "events").iterdir())
    event = json.loads(path.read_text())
    event["payload"]["trial_patch"]["reason"] = "rewritten"
    path.unlink()
    (copy / "events" / f"00000015-{canonical_hash(event)}.json").write_text(
        json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=False),
        encoding="utf8",
    )
    with pytest.raises(PermissionError, match="snapshot"):
        module().read_native_observation(copy, GOOD)


def test_structural_validation_rejects_duplicate_or_skipped_order():
    with pytest.raises(PermissionError):
        module().validate_pool_structure(
            {"schema_version": "task13-e-timing-pool-registration-v1"}
        )


def test_old_observation_cannot_be_relabelled_as_new_host_identity():
    view = module()._view(RAW)
    view.identity["source_commit"] = "a" * 40
    with pytest.raises(
        (ValueError, PermissionError), match="isolated execution|binding differs"
    ):
        module()._branches(view, view.trials[GOOD], set(), set())


def test_duplicate_resources_and_approvals_rejected_across_imports():
    view = module()._view(RAW)
    resources = set()
    seen = set()
    module()._branches(view, view.trials[GOOD], resources, seen)
    with pytest.raises((PermissionError, ValueError)):
        module()._branches(view, view.trials[GOOD], resources, seen)


def test_selection_cannot_skip_earlier_qualified_attempt_for_speed():
    expected = [{"trial_id": "old"}, {"trial_id": "slow"}, {"trial_id": "fast"}]
    with pytest.raises(PermissionError):
        module()._validate_selection(
            expected,
            [expected[0], expected[2], {"trial_id": "later"}],
            ["old", "fast", "later"],
        )
    module()._validate_selection(expected, expected, ["old", "slow", "fast"])


def test_unified_max_includes_every_wall_and_monotonic_duration():
    rows = [
        {"duration_wall_seconds": 12.0, "duration_monotonic_seconds": 11.5},
        {"duration_wall_seconds": 10.0, "duration_monotonic_seconds": 10.5},
        {"duration_wall_seconds": 9.0, "duration_monotonic_seconds": 9.5},
    ]
    assert module()._unified_max(rows, 12.0) == 12.0
    with pytest.raises(PermissionError):
        module()._unified_max(rows, 11.5)


@pytest.mark.parametrize("relative", ["evals/timing_pool.py", "../timing_pool.py"])
def test_evidence_paths_must_be_explicit_absolute(relative):
    with pytest.raises(PermissionError):
        module()._plain(relative)


def test_evidence_hardlink_alias_is_not_independent(tmp_path):
    import os

    original = tmp_path / "original.json"
    original.write_text("{}")
    alias = tmp_path / "alias.json"
    os.link(original, alias)
    with pytest.raises(PermissionError):
        module()._plain(alias)


def test_full_current_host_coverage_includes_new_source_tests_and_protocol(tmp_path):
    from evals.verification_v2 import file_sha256

    old = tmp_path / "evals/old.py"
    old.parent.mkdir()
    old.write_text("original")
    test = tmp_path / "evals/tests/test_new.py"
    test.parent.mkdir()
    test.write_text("new")
    protocol = tmp_path / "docs/evaluations/protocol.md"
    protocol.parent.mkdir(parents=True)
    protocol.write_text("protocol")
    files = {str(old): file_sha256(old)}
    with pytest.raises(PermissionError):
        module()._validate_host_coverage(files, tmp_path, {"evals/old.py"})
    for path in (test, protocol):
        files[str(path)] = file_sha256(path)
    module()._validate_host_coverage(files, tmp_path, {"evals/old.py"})


def test_native_source_semantics_reject_relabelled_and_unsealed_source():
    from copy import deepcopy

    view = module()._view(RAW)
    trial = view.trials[GOOD]
    source = view._blob("sources", trial["binding"]["source_sha256"])
    module()._validate_source_semantics(view, trial, source)
    for field in ("source_commit", "config_sha256"):
        bad = deepcopy(source)
        bad[field] = "0" * len(bad[field])
        with pytest.raises(PermissionError):
            module()._validate_source_semantics(view, trial, bad)
    bad = deepcopy(source)
    bad["state"]["analysis_import_provenance"]["source_package_manifest_sha256"] = (
        "0" * 64
    )
    with pytest.raises(PermissionError):
        module()._validate_source_semantics(view, trial, bad)


def test_actual_native_scope_readiness_and_append_claim_semantics():
    from copy import deepcopy

    view = module()._view(RAW)
    host = module()._json(RAW.parent / "host-binding.json")
    inputs = {
        k: module()._artifact(v, RAW.parent.parent) for k, v in host["inputs"].items()
    }
    context = module()._validate_host_semantics(view, host, inputs)
    assert context["claims"][GOOD]["status"] == "started"
    bad = deepcopy(inputs)
    bad["readiness"]["status"] = "unverified"
    with pytest.raises(PermissionError):
        module()._validate_host_semantics(view, host, bad)
    bad = deepcopy(inputs)
    bad["planning_authority"]["decision_record_sha256"] = "0" * 64
    with pytest.raises(PermissionError):
        module()._validate_host_semantics(view, host, bad)


def test_archives_preserve_expected_raw_bytes_and_reject_unused_or_aliases(tmp_path):
    from hashlib import sha256

    original = str(tmp_path / "gone.json")
    copy = tmp_path / "history.json"
    copy.write_text('{"original":true}')
    digest = sha256(copy.read_bytes()).hexdigest()
    context = module()._archive_context(
        {original: {"path": str(copy), "sha256": digest}}
    )
    assert module()._archived_json({"path": original, "sha256": digest}, context) == {
        "original": True
    }
    module()._finish_archives(context)
    with pytest.raises(PermissionError):
        module()._archived_json({"path": original, "sha256": "0" * 64}, context)
    unused = module()._archive_context(
        {original: {"path": str(copy), "sha256": digest}}
    )
    with pytest.raises(PermissionError):
        module()._finish_archives(unused)
    with pytest.raises(PermissionError):
        module()._archive_context(
            {
                original: {"path": str(copy), "sha256": digest},
                str(tmp_path / "other.json"): {"path": str(copy), "sha256": digest},
            }
        )


def test_migration_marker_exact_parent_and_historical_membership():
    from evals.contracts import canonical_hash

    pool = {"attempt_order": [{"trial_id": f"new{i}"} for i in range(6)]}
    packet = {"sha256": "1" * 64}
    decision = {"sha256": "2" * 64}
    marker = {
        "schema_version": "task13-e-timing-pool-migration-v1",
        "pool_registration_sha256": canonical_hash(pool),
        "source_registration_sha256": module().C10_REGISTRATION,
        "source_journal_head_sha256": module().C10_IMPORT_PINS["journal_head_sha256"],
        "imported_trial_id": GOOD,
        "excluded_trial_ids": [
            t["trial_id"]
            for t in module()._json(RAW / "registration.json")["trials"][1:]
        ],
        "future_trial_ids": [f"new{i}" for i in range(6)],
        "parent_scope_packet_sha256": packet["sha256"],
        "parent_scope_decision_sha256": decision["sha256"],
    }
    module().validate_migration_marker(marker, pool, packet, decision)
    marker["excluded_trial_ids"] = []
    with pytest.raises(PermissionError):
        module().validate_migration_marker(marker, pool, packet, decision)


def test_full_attempt_inventory_never_skips_failure_or_later_work():
    from importlib import import_module

    helper = import_module("evals.timing_pool_evidence")
    order = ["a", "b", "c", "d", "e", "f"]
    status = {
        "a": "completed",
        "b": "completed",
        **{k: "not_started" for k in order[2:]},
    }
    settlements = [
        {"trial_id": "a", "outcome": "qualified"},
        {"trial_id": "b", "outcome": "qualified"},
    ]
    assert helper.validate_attempt_inventory(
        order, ["a", "b"], status, settlements
    ) == ["a", "b"]
    status["c"] = "completed"
    with pytest.raises(PermissionError):
        helper.validate_attempt_inventory(order, ["a", "b"], status, settlements)
    status["c"] = "not_started"
    status["a"] = "failed"
    with pytest.raises(PermissionError):
        helper.validate_attempt_inventory(order, ["a", "b"], status, settlements)
    with pytest.raises(PermissionError):
        helper.validate_attempt_inventory(order, ["b", "a"], status, settlements)


def test_migration_preserves_original_case_and_analysis_lineage():
    from copy import deepcopy

    original = module()._json(RAW / "registration.json")
    candidate = deepcopy(original)
    module()._validate_same_source(original, candidate)
    candidate["planning_registration"]["source"]["case_id"] = "other-case"
    with pytest.raises(PermissionError):
        module()._validate_same_source(original, candidate)
    candidate = deepcopy(original)
    candidate["planning_registration"]["recovery_lineage"][
        "original_analysis_output_sha256"
    ] = "0" * 64
    with pytest.raises(PermissionError):
        module()._validate_same_source(original, candidate)


def test_historical_settlement_snapshot_retains_verified_journal_prefix():
    from copy import deepcopy

    from evals.contracts import canonical_hash
    from evals.timing_pool_evidence import native_snapshot_matches

    view = module()._view(RAW)
    current = {
        "trial_id": GOOD,
        "duration_monotonic_seconds": 384.562,
        "journal_head_sha256": canonical_hash(view.events[-1]),
        "journal_trials": list(view.trials.values()),
    }
    older = deepcopy(current)
    older["journal_head_sha256"] = canonical_hash(view.events[-2])
    older["journal_trials"][1] = {
        "trial_id": view.registration["trials"][1]["trial_id"],
        "source_row_id": view.registration["trials"][1]["source_row_id"],
        "status": "not_started",
        "reason": None,
        "binding": None,
    }
    assert native_snapshot_matches(view, current, older)
    older["duration_monotonic_seconds"] = 1
    assert not native_snapshot_matches(view, current, older)


def test_guard_review_head_must_already_contain_all_six_completed_branches(actual_c10):
    from copy import deepcopy

    from evals.contracts import canonical_hash
    from evals.timing_pool_evidence import validate_native_guard_reviews

    pool = module()
    view = pool._view(RAW)
    reference = {
        "evidence_root": str(RAW),
        "trial_id": GOOD,
        "registration_sha256": pool.C10_REGISTRATION,
        **pool.C10_IMPORT_PINS,
    }
    registration = {"imported_observations": [reference], "children": []}
    observed = deepcopy(actual_c10)
    observed.pop("journal_head_sha256")
    observed.pop("journal_trials")
    entry = {
        "trial_id": GOOD,
        "reference": reference,
        "observation": observed,
        "native_journal_head_sha256": canonical_hash(view.events[-2]),
        "duration_wall_seconds": observed["duration_wall_seconds"],
        "duration_monotonic_seconds": observed["duration_monotonic_seconds"],
    }
    events = [
        {
            "kind": "guard_review",
            "payload": {
                "checked_at": "2026-11-01T02:00:00+00:00",
                "observations": [entry],
            },
        }
    ]
    # The subsequent native rejection is legitimate later history: a review of
    # the earlier completed prefix remains valid after that append.
    validate_native_guard_reviews(events, registration)
    entry["native_journal_head_sha256"] = canonical_hash(view.events[0])
    with pytest.raises(PermissionError):
        validate_native_guard_reviews(events, registration)


@pytest.mark.parametrize("remaining", [1600, 1650])
def test_actual_dispatch_rechecks_previous_shared_maximum(remaining):
    from copy import deepcopy
    from datetime import timedelta

    from evals.timing_pool_evidence import validate_dispatch_boundary

    pool = module()
    view = pool._view(RAW)
    first = next(r for r in view.records.values() if r["trial_id"] == GOOD)
    source = deepcopy(
        view._blob("sources", view.trials[GOOD]["binding"]["source_sha256"])
    )
    source["state"]["response_plan"]["expires_at"] = (
        pool._time(first["dispatched_at"]) + timedelta(seconds=remaining)
    ).isoformat()
    with pytest.raises(PermissionError, match="shared timing margin"):
        validate_dispatch_boundary(view, GOOD, source["state"], 900, qualified=True)
    # A settled known TTL failure keeps its history without earning credit.
    validate_dispatch_boundary(view, GOOD, source["state"], 900, qualified=False)
    source["state"]["response_plan"]["expires_at"] = (
        pool._time(first["dispatched_at"]) + timedelta(seconds=1650.001)
    ).isoformat()
    validate_dispatch_boundary(view, GOOD, source["state"], 900, qualified=True)


def test_actual_first_dispatch_must_precede_engineering_deadline():
    from copy import deepcopy
    from datetime import timedelta

    from evals.timing_pool_controller import DEADLINE
    from evals.timing_pool_evidence import validate_dispatch_boundary

    pool = module()
    view = pool._view(RAW)
    source = deepcopy(
        view._blob("sources", view.trials[GOOD]["binding"]["source_sha256"])
    )
    source["state"]["response_plan"]["expires_at"] = (
        DEADLINE + timedelta(seconds=2000)
    ).isoformat()
    for row in view.records.values():
        if row["trial_id"] == GOOD:
            row["dispatched_at"] = DEADLINE.isoformat()
    with pytest.raises(PermissionError, match="engineering deadline"):
        validate_dispatch_boundary(view, GOOD, source["state"], 384.562, qualified=True)
