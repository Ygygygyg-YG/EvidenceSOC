"""Actual file mutations must invalidate previously passing runtime evidence."""
from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from pathlib import Path

import pytest

from evals.datasets.dedale import audit
from evals.datasets.dedale.common import canonical
from evals.tests.test_dedale_manifests import build, event
from scripts.dedale_task12_live_check import dependency_tree_sha256


def runtime_fixture(root: Path):
    harness = root / "scripts/dedale_task12_live_check.py"
    bootstrap = root / "scripts/dedale_task12_runtime.py"
    backend = root / "services/backend/src"
    dependencies = root / "data/dedale/runtime/linux-packages"
    for path in (harness, bootstrap, backend / "service.py", dependencies / "dependency.py"):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"original\n")
    return {"runtime_artifacts": {
        "harness_sha256": hashlib.sha256(harness.read_bytes()).hexdigest(),
        "bootstrap_sha256": hashlib.sha256(bootstrap.read_bytes()).hexdigest(),
        "backend_source_sha256": dependency_tree_sha256(backend),
        "linux_dependencies_sha256": dependency_tree_sha256(dependencies),
    }}


@pytest.mark.parametrize("relative", [
    "scripts/dedale_task12_live_check.py", "scripts/dedale_task12_runtime.py",
    "services/backend/src/service.py", "data/dedale/runtime/linux-packages/dependency.py",
])
def test_actual_runtime_mutation_invalidates_old_report(tmp_path, monkeypatch, relative):
    report = runtime_fixture(tmp_path)
    monkeypatch.setattr(audit, "ROOT", tmp_path, raising=False)
    assert audit._runtime_hashes_match(report)
    (tmp_path / relative).write_bytes(b"changed\n")
    assert not audit._runtime_hashes_match(report)


def test_missing_runtime_manifest_fails_closed(tmp_path, monkeypatch):
    monkeypatch.setattr(audit, "ROOT", tmp_path, raising=False)
    assert not audit._runtime_hashes_match({})


def test_extra_agent_manifest_answer_field_is_rejected_after_rehash(tmp_path):
    selection = build(tmp_path, [event(label="1")])
    case = selection["cases"][0]
    path = tmp_path / "test" / case["case_id"] / "agent/manifest.json"
    value = json.loads(path.read_text(encoding="utf-8"))
    value["expected_attack"] = "hidden answer"
    path.write_text(canonical(value) + "\n", encoding="utf-8")
    case["artifacts"]["agent/manifest.json"] = hashlib.sha256(path.read_bytes()).hexdigest()
    score_path = path.parent.parent / "scoring/manifest.json"
    score = json.loads(score_path.read_text(encoding="utf-8"))
    score["artifacts"]["agent/manifest.json"] = case["artifacts"]["agent/manifest.json"]
    score_path.write_text(canonical(score) + "\n", encoding="utf-8")
    case["artifacts"]["scoring/manifest.json"] = hashlib.sha256(score_path.read_bytes()).hexdigest()
    case["agent_manifest_sha256"] = case["artifacts"]["agent/manifest.json"]
    case["scoring_manifest_sha256"] = case["artifacts"]["scoring/manifest.json"]
    assert not audit.audit_prepared(selection, tmp_path)["gates"]["artifacts"]


def test_case_counts_are_recomputed_from_actual_cases(tmp_path):
    selection = build(tmp_path, [event()])
    selection["counts"] = {"attack": 1, "normal": 1, "unscorable": 0}
    report = audit.audit_prepared(selection, tmp_path)
    assert not report["gates"]["minimum_size"]
    assert not report["gates"]["candidate_closure"]


def selection_with_excluded_candidate(tmp_path):
    attack, normal, extra = event(1, "1"), event(2), event(3)
    normal["observed_at"] = "2025-01-06T01:00:02Z"
    extra["observed_at"] = "2025-01-06T01:30:03Z"
    return build(tmp_path, [attack, normal, extra])


@pytest.mark.parametrize("field,value", [
    ("host", "wrong-host"), ("source", "winlogbeat"),
    ("time_from", "2030-01-01T00:00:00Z"), ("candidate_kind", "invented"),
    ("projected_count", 99), ("projected_labels", {"benign": 99}),
    ("reason", "selected_invented"),
])
def test_selected_ledger_metadata_must_match_case_and_gold(tmp_path, field, value):
    selection = selection_with_excluded_candidate(tmp_path)
    assert audit.audit_prepared(selection, tmp_path)["gates"]["candidate_closure"]
    row = next(row for row in selection["candidate_ledger"] if row.get("case_id"))
    row[field] = value
    assert not audit.audit_prepared(selection, tmp_path)["gates"]["candidate_closure"]


def test_dropped_excluded_grid_candidate_breaks_scan_row_closure(tmp_path):
    selection = selection_with_excluded_candidate(tmp_path)
    selection["candidate_ledger"] = [row for row in selection["candidate_ledger"] if row.get("case_id")]
    assert not audit.audit_prepared(selection, tmp_path)["gates"]["candidate_closure"]


def rehash_case(selection, root, case):
    case_root = root / "test" / case["case_id"]
    for relative in ("agent/events.jsonl", "agent/manifest.json", "scoring/gold.jsonl", "scoring/source-gold.json"):
        case["artifacts"][relative] = hashlib.sha256((case_root / relative).read_bytes()).hexdigest()
    score_path = case_root / "scoring/manifest.json"
    score = json.loads(score_path.read_text(encoding="utf-8"))
    score["artifacts"] = {key: value for key, value in case["artifacts"].items() if key != "scoring/manifest.json"}
    score_path.write_text(canonical(score) + "\n", encoding="utf-8")
    case["artifacts"]["scoring/manifest.json"] = hashlib.sha256(score_path.read_bytes()).hexdigest()
    case["agent_manifest_sha256"] = case["artifacts"]["agent/manifest.json"]
    case["scoring_manifest_sha256"] = case["artifacts"]["scoring/manifest.json"]


@pytest.mark.parametrize("label", ["unscorable", "malicious-related"])
def test_unknown_gold_cannot_satisfy_reliable_normal_minimum(tmp_path, label):
    selection = selection_with_excluded_candidate(tmp_path)
    case = next(case for case in selection["cases"] if case["is_attack"] is False)
    path = tmp_path / "test" / case["case_id"] / "scoring/gold.jsonl"
    truth = json.loads(path.read_text(encoding="utf-8"))
    truth.update({"source_label": label, "is_attack": None, "taxonomy_status": "unscorable",
                  "applicability": {key: False for key in truth["applicability"]}})
    path.write_text(canonical(truth) + "\n", encoding="utf-8")
    rehash_case(selection, tmp_path, case)
    report = audit.audit_prepared(selection, tmp_path)
    assert not report["gates"]["artifacts"]
    assert not report["gates"]["minimum_size"]


def full_scan_metadata_fixture(selection, monkeypatch):
    """Only metadata is synthesized; this cannot establish official sources."""
    manifests = {}
    for source in ("auditbeat", "winlogbeat"):
        manifests[f"system_logs_{source}.zip"] = {
            "member": f"daily_{source}/{source}_md5sum.sig", "unique_members": 672,
            "duplicate_entries": 0,
            "checksums": {f"daily_{source}/D{number}.jsonl.bz2": "0" * 32 for number in range(672)},
        }
    monkeypatch.setattr(audit, "read_archive_manifest", lambda path: deepcopy(manifests[path.name]), raising=False)
    monkeypatch.setattr(audit, "verify_sources", lambda *args: {"sources_sha256": "a" * 64, "archives": []})
    scan = selection["scan"]
    rows = scan["counts"]["parsed_rows"]
    scan["counts"].update({"raw_rows": rows, "invalid_rows": 0})
    scan.update({"full_archive_scan": True, "members_expected": 1344, "members_completed": 1344,
                 "invalid_rows": 0, "freeze_eligible": True, "invalid_examples": [], "archive_manifests": [],
                 "member_summaries": []})
    first = True
    for archive, manifest in manifests.items():
        scan["archive_manifests"].append({"archive": archive, **{key: manifest[key] for key in ("member", "unique_members", "duplicate_entries")},
            "checksums_sha256": hashlib.sha256(canonical(manifest["checksums"]).encode()).hexdigest()})
        for member in manifest["checksums"]:
            scan["member_summaries"].append({"archive": archive, "member": member,
                "raw_rows": rows if first else 0, "parsed_rows": rows if first else 0,
                "invalid_rows": 0, "jsonl_md5_verified": True})
            first = False


@pytest.mark.parametrize("change", ["missing_member", "duplicate_member", "unknown_member", "member_sum", "global_sum", "host_sum", "day_sum", "label_sum", "reversed_dates", "calibration_rows", "provider_sum", "invalid_type", "empty_day", "archive_manifest"])
def test_full_scan_claim_requires_manifest_coverage_and_consistent_counters(tmp_path, monkeypatch, change):
    selection = selection_with_excluded_candidate(tmp_path)
    full_scan_metadata_fixture(selection, monkeypatch)
    kwargs = {"sources": tmp_path / "sources.json", "data_root": tmp_path}
    assert audit.audit_prepared(selection, tmp_path, **kwargs)["gates"]["dates"]
    scan = selection["scan"]
    if change == "missing_member":
        scan["member_summaries"].pop()
    elif change == "duplicate_member":
        scan["member_summaries"][-1] = deepcopy(scan["member_summaries"][0])
    elif change == "unknown_member":
        scan["member_summaries"][0]["member"] = "daily_auditbeat/unknown.jsonl.bz2"
    elif change == "member_sum":
        scan["member_summaries"][0]["raw_rows"] += 1
    elif change == "global_sum":
        scan["counts"]["raw_rows"] += 1
    elif change == "host_sum":
        scan["hosts"]["auditbeat:internalserver"] += 1
    elif change == "day_sum":
        scan["days"]["2025-01-06"] += 1
    elif change == "label_sum":
        scan["original_labels"]["malicious"] += 1
    elif change == "reversed_dates":
        scan["observed_min"], scan["observed_max"] = scan["observed_max"], scan["observed_min"]
    elif change == "calibration_rows":
        scan["counts"]["calibration_rows"] = 1
    elif change == "provider_sum":
        first = scan["member_summaries"][0]
        other = next(row for row in scan["member_summaries"] if row["archive"] != first["archive"])
        first["raw_rows"] -= 1
        first["parsed_rows"] -= 1
        other["raw_rows"] += 1
        other["parsed_rows"] += 1
    elif change == "invalid_type":
        scan["invalid_rows"] = False
    elif change == "empty_day":
        scan["days"]["2025-01-05"] = 0
        scan["observed_min"] = "2025-01-05T00:00:00Z"
    else:
        scan["archive_manifests"][0]["checksums_sha256"] = "f" * 64
    assert not audit.audit_prepared(selection, tmp_path, **kwargs)["gates"]["dates"]


@pytest.mark.parametrize("field,value", [("window", {"reason": "invented"}), ("counts", {"selected": 999})])
def test_scoring_window_and_counts_must_match_selected_ledger_after_rehash(tmp_path, field, value):
    selection = selection_with_excluded_candidate(tmp_path)
    case = selection["cases"][0]
    path = tmp_path / "test" / case["case_id"] / "scoring/manifest.json"
    score = json.loads(path.read_text(encoding="utf-8"))
    score[field] = value
    path.write_text(canonical(score) + "\n", encoding="utf-8")
    case["artifacts"]["scoring/manifest.json"] = hashlib.sha256(path.read_bytes()).hexdigest()
    assert not audit.audit_prepared(selection, tmp_path)["gates"]["artifacts"]


def test_official_label_metadata_detects_missing_unobserved_attack_candidate(tmp_path, monkeypatch):
    from evals.tests.test_dedale_manifests import registered_labels, timed_event

    attack = timed_event("2025-01-06T00:20:00Z", label="1")
    missing = timed_event("2025-01-06T01:20:00Z", label="1", number=2)
    labels = registered_labels([attack, missing])
    labels.official_verified = True
    selection = build(tmp_path, [attack], labels=labels)
    monkeypatch.setattr(audit, "verify_sources", lambda *args: {"sources_sha256": "a" * 64, "archives": []})
    monkeypatch.setattr(audit, "load_label_index", lambda *args, **kwargs: labels)
    kwargs = {"sources": tmp_path / "sources.json", "data_root": tmp_path}
    assert audit.audit_prepared(selection, tmp_path, **kwargs)["gates"]["candidate_closure"]
    selection["candidate_ledger"] = [row for row in selection["candidate_ledger"] if row["reason"] != "registered_attack_not_observed"]
    selection["counts"]["unscorable"] = 0
    assert not audit.audit_prepared(selection, tmp_path, **kwargs)["gates"]["candidate_closure"]


def test_gold_is_rejoined_against_official_label_metadata(tmp_path, monkeypatch):
    from evals.tests.test_dedale_manifests import registered_labels, timed_event

    attack = timed_event("2025-01-06T00:20:00Z", label="1")
    labels = registered_labels([attack])
    labels.official_verified = True
    selection = build(tmp_path, [attack], labels=labels)
    monkeypatch.setattr(audit, "verify_sources", lambda *args: {"sources_sha256": "a" * 64, "archives": []})
    monkeypatch.setattr(audit, "load_label_index", lambda *args, **kwargs: labels)
    kwargs = {"sources": tmp_path / "sources.json", "data_root": tmp_path}
    assert audit.audit_prepared(selection, tmp_path, **kwargs)["gates"]["artifacts"]
    labels.classify = lambda *args, **kwargs: "unscorable"
    assert not audit.audit_prepared(selection, tmp_path, **kwargs)["gates"]["artifacts"]


@pytest.mark.parametrize("field", ["N_D", "M_D", "attack", "normal", "unscorable", "event_count"])
def test_boolean_cannot_replace_integer_case_counts(tmp_path, field):
    selection = build(tmp_path, [event(1, "1")]) if field in {"N_D", "M_D"} else selection_with_excluded_candidate(tmp_path)
    if field in {"N_D", "M_D"}:
        selection[field] = True
    elif field == "event_count":
        selection["cases"][0][field] = True
    else:
        selection["counts"][field] = bool(selection["counts"][field])
    report = audit.audit_prepared(selection, tmp_path)
    assert not report["gates"]["candidate_closure"] or not report["gates"]["artifacts"]


@pytest.mark.parametrize("label", ["malicious", "benign", "malicious-related"])
@pytest.mark.parametrize("change", ["taxonomy", "binary_mask", "integer_mask", "unsupported_masks"])
def test_gold_scoring_semantics_remain_bound_to_original_label_after_rehash(tmp_path, label, change):
    selection = build(tmp_path, [event(1, "1"), event(2), event(3, "2")])
    assert audit.audit_prepared(selection, tmp_path)["gates"]["artifacts"]
    case = selection["cases"][0]
    path = tmp_path / "test" / case["case_id"] / "scoring/gold.jsonl"
    gold = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    truth = next(row for row in gold if row["source_label"] == label)
    if change == "taxonomy":
        truth["taxonomy_status"] = "in_taxonomy"
    elif change == "binary_mask":
        truth["applicability"]["attack_binary"] = not truth["applicability"]["attack_binary"]
    elif change == "integer_mask":
        truth["applicability"]["attack_binary"] = int(truth["applicability"]["attack_binary"])
    else:
        truth["applicability"].update({"six_class": True, "phases": True, "techniques": True, "origin": True})
    path.write_text("".join(canonical(row) + "\n" for row in gold), encoding="utf-8")
    rehash_case(selection, tmp_path, case)
    assert not audit.audit_prepared(selection, tmp_path)["gates"]["artifacts"]


@pytest.mark.parametrize("change", ["attack_binary", "six_class", "phases", "techniques", "origin", "integer_mask", "missing_mask", "extra_mask", "stage_review"])
def test_case_scoring_masks_cannot_be_opened_by_metadata_after_rehash(tmp_path, change):
    selection = selection_with_excluded_candidate(tmp_path)
    assert audit.audit_prepared(selection, tmp_path)["gates"]["artifacts"]
    case = selection["cases"][0]
    path = tmp_path / "test" / case["case_id"] / "scoring/manifest.json"
    score = json.loads(path.read_text(encoding="utf-8"))
    if change == "stage_review":
        score["stage_review"] = "complete"
    elif change == "integer_mask":
        score["case_applicability"]["attack_binary"] = 1
    elif change == "missing_mask":
        score["case_applicability"].pop("phases")
    elif change == "extra_mask":
        score["case_applicability"]["invented_score"] = True
    else:
        score["case_applicability"][change] = not score["case_applicability"][change]
    path.write_text(canonical(score) + "\n", encoding="utf-8")
    case["artifacts"]["scoring/manifest.json"] = hashlib.sha256(path.read_bytes()).hexdigest()
    case["scoring_manifest_sha256"] = case["artifacts"]["scoring/manifest.json"]
    assert not audit.audit_prepared(selection, tmp_path)["gates"]["artifacts"]


@pytest.mark.parametrize("change", ["origin_mask", "integer_mask", "source_ips", "entry_candidates", "extra_mask", "reason"])
def test_unreviewed_source_attribution_cannot_be_added_after_rehash(tmp_path, change):
    selection = selection_with_excluded_candidate(tmp_path)
    assert audit.audit_prepared(selection, tmp_path)["gates"]["artifacts"]
    case = selection["cases"][0]
    path = tmp_path / "test" / case["case_id"] / "scoring/source-gold.json"
    source_gold = json.loads(path.read_text(encoding="utf-8"))
    if change == "origin_mask":
        source_gold["applicability"]["origin"] = True
    elif change == "integer_mask":
        source_gold["applicability"]["origin"] = 0
    elif change == "source_ips":
        source_gold["observed_source_ips"] = ["192.0.2.10"]
    elif change == "entry_candidates":
        source_gold["entry_candidates"] = ["unreviewed attribution"]
    elif change == "extra_mask":
        source_gold["applicability"]["six_class"] = True
    else:
        source_gold["reason"] = "Claimed reviewed source attribution gold"
    path.write_text(canonical(source_gold) + "\n", encoding="utf-8")
    rehash_case(selection, tmp_path, case)
    assert not audit.audit_prepared(selection, tmp_path)["gates"]["artifacts"]
