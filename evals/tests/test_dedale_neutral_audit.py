"""Final neutral cases must retain verifiable preparation lineage and controls."""
from __future__ import annotations

from copy import deepcopy

import pytest

from evals.datasets.dedale import audit
from evals.datasets.dedale.neutralize import (
    candidate_cut,
    canonical_clock,
    control_candidates,
    neutral_case_id,
    shift_seconds,
)
from evals.tests.test_dedale_manifests import build, event, registered_labels


def test_neutral_protocol_cannot_bypass_missing_preparation_lineage(tmp_path):
    selection = build(tmp_path, [event(1, "1"), event(2)])
    selection["protocol"] = "dedale-neutral-v3"
    report = audit.audit_prepared(selection, tmp_path)
    assert report["gates"].get("preparation_lineage") is False
    assert not report["accepted"]


def ledger_fixture(tmp_path):
    values = [event(1, "1"), event(2), event(3)]
    for row, time in zip(values, ("2025-01-06T00:02:00.123Z", "2025-01-06T02:00:00.123Z", "2025-01-06T03:00:00.456Z"), strict=True):
        row["observed_at"] = time
    preparation = build(tmp_path, values, labels=registered_labels(values[:1]))
    groups = control_candidates(preparation["candidate_ledger"])
    index = [{"archive": "system_logs_auditbeat.zip", "member": "daily_auditbeat/any.jsonl.bz2",
              "source": "auditbeat", "jsonl_md5": "a" * 32, "minimum": "2025-01-06T00:00:00Z",
              "maximum": "2025-01-06T23:59:59Z", "hosts": {"auditbeat:internalserver": 3},
              "raw_rows": 3, "parsed_rows": 3, "invalid_rows": 0, "jsonl_md5_verified": True}]
    receipt = {key: index[0][key] for key in ("archive", "member", "jsonl_md5", "raw_rows", "jsonl_md5_verified")}
    ledger = []
    for row in preparation["candidate_ledger"]:
        if row["reason"] == "selected_attack":
            ledger.append({**row, "time_from": canonical_clock(row["time_from"]), "time_to": canonical_clock(row["time_to"]),
                           "case_id": neutral_case_id(row["source"], row["host"], row["time_from"])})
    for candidates in groups.values():
        for i, candidate in enumerate(candidates):
            cut = candidate_cut(candidate)
            selected = i == 0
            start = shift_seconds(cut, 1) if selected else None
            row = {**candidate, "candidate_kind": "control", "cut": cut,
                   "original_anchor_timestamp": start,
                   "time_from": start, "time_to": shift_seconds(start, 1800) if selected else None,
                   "reason": "selected_normal" if selected else "not_evaluated_after_first_eligible",
                   "raw_window_count": 1 if selected else None, "projected_count": 1 if selected else None,
                   "source_labels": {"benign": 1} if selected else None,
                   "projected_labels": {"benign": 1} if selected else None,
                   "duplicate_retained_rows": 0 if selected else None,
                   "passes": {"anchor": [deepcopy(receipt)] if selected else None,
                              "window": [deepcopy(receipt)] if selected else None}}
            if selected:
                row["case_id"] = neutral_case_id(row["source"], row["host"], start)
            ledger.append(row)
    return preparation, {"candidate_ledger": ledger, "counts": {"unscorable": 0}}, index


def test_neutral_candidate_closure_uses_complete_ranked_preparation_universe(tmp_path):
    from evals.datasets.dedale.neutral_audit import validate_candidate_ledger

    preparation, selection, index = ledger_fixture(tmp_path)
    rows = validate_candidate_ledger(selection, preparation, index)
    assert len(rows) == 2


def test_normal_and_attack_public_clocks_share_one_lossless_format(tmp_path):
    from evals.datasets.dedale.neutral_audit import validate_candidate_ledger

    preparation, selection, index = ledger_fixture(tmp_path)
    attack = next(row for row in preparation["candidate_ledger"] if row["reason"] == "selected_attack")
    assert attack["time_from"].endswith(".123000Z")
    rows = validate_candidate_ledger(selection, preparation, index)
    final_attack = next(row for row in rows.values() if row["reason"] == "selected_attack")
    assert final_attack["time_from"].endswith(".123Z")


@pytest.mark.parametrize("change", ["drop", "wrong_cut", "skip_first", "fake_zero", "wrong_id", "missing_receipt", "wrong_member", "wrong_count", "attack_change", "false_benign", "cross_day"])
def test_neutral_control_tampering_fails_even_with_coherent_self_hashes(tmp_path, change):
    from evals.datasets.dedale.neutral_audit import validate_candidate_ledger

    preparation, selection, index = ledger_fixture(tmp_path)
    selected = next(row for row in selection["candidate_ledger"] if row["reason"] == "selected_normal")
    skipped = next(row for row in selection["candidate_ledger"] if row["reason"] == "not_evaluated_after_first_eligible")
    if change == "drop":
        selection["candidate_ledger"].remove(skipped)
    elif change == "wrong_cut":
        selected["cut"] = shift_seconds(selected["cut"], 1)
    elif change == "skip_first":
        selected["reason"] = "not_evaluated_after_first_eligible"
    elif change == "fake_zero":
        skipped["raw_window_count"] = 0
    elif change == "wrong_id":
        selected["case_id"] = "dedale-" + "0" * 16
    elif change == "missing_receipt":
        selected["passes"]["window"] = []
    elif change == "wrong_member":
        selected["passes"]["anchor"][0]["member"] = "daily_auditbeat/other.jsonl.bz2"
    elif change == "wrong_count":
        selected["passes"]["window"][0]["raw_rows"] += 1
    elif change == "attack_change":
        attack = next(row for row in selection["candidate_ledger"] if row["reason"] == "selected_attack")
        attack["raw_window_count"] += 1
    elif change == "false_benign":
        selected["source_labels"] = {"malicious-related": 1}
    else:
        selected["time_from"] = "2025-01-06T23:59:00.001Z"
        selected["time_to"] = shift_seconds(selected["time_from"], 1800)
        selected["case_id"] = neutral_case_id(selected["source"], selected["host"], selected["time_from"])
    with pytest.raises(ValueError):
        validate_candidate_ledger(selection, preparation, index)
