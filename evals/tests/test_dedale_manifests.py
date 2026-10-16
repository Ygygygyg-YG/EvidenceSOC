"""Selection and audit behavior; synthetic fixtures are never freeze evidence."""
import hashlib
import json
from pathlib import Path
from typing import ClassVar

import pytest

from evals.datasets.dedale.audit import audit_prepared
from evals.datasets.dedale.build_manifests import build_from_events, window_start
from evals.datasets.dedale.common import canonical, verify_sources


class Labels:
    official_verified = False
    entries: ClassVar[dict] = {}
    summary: ClassVar[dict] = {"fixture": True}

    def classify(self, source, fingerprint, *, host=None):
        return {"1": "malicious", "2": "malicious-related", "3": "unscorable"}.get(
            fingerprint[:1], "benign"
        )


def event(second=1, label="0", host="internalserver"):
    identifier = hashlib.sha256(f"{second}:{label}:{host}".encode()).hexdigest()
    return {
        "source": "auditbeat", "host": host, "event_type": "process.started",
        "observed_at": f"2025-01-06T00:00:{second:02d}Z",
        "dataset_id": "dedale-v2.1", "external_id": "dedale:" + identifier,
        "archive": "system_logs_auditbeat.zip", "relative_log_path": "daily_auditbeat/x.jsonl.bz2",
        "line_number": second, "raw_line_sha256": identifier,
        "event_fingerprint": label + identifier[1:],
        "message": "process.executable=/usr/bin/printf", "severity": "info",
    }


def config():
    return {
        "schema_version": 1, "dataset_id": "dedale-v2.1", "window_seconds": 1800,
        "max_records": 100, "seed": 42, "benign_per_host_day": 1,
        "periods": [
            {"split": "development", "purpose": "benign_calibration", "start": "2024-12-23T00:00:00Z", "end": "2025-01-06T00:00:00Z"},
            {"split": "test", "purpose": "external_test", "start": "2025-01-06T00:00:00Z", "end": "2025-01-20T00:00:00Z"},
        ],
    }


def build(tmp_path, events, splits=None, *, labels=None):
    return build_from_events(
        events, labels=labels or Labels(), splits=splits or config(), output_root=tmp_path,
        input_hashes={"sources": "a" * 64, "splits": "b" * 64, "label_policy": "c" * 64},
    )


def registered_labels(events):
    labels = Labels()
    labels.entries = {
        (row["source"], row["event_fingerprint"]): {
            "source": row["source"], "host": row["host"],
            "timestamp": row["observed_at"], "label": "malicious",
        }
        for row in events
    }
    return labels


def timed_event(timestamp, *, label="0", number=1):
    row = event(number, label)
    row["observed_at"] = timestamp
    return row


def attack_candidates(selection):
    return [row for row in selection["candidate_ledger"] if row["candidate_kind"] == "attack"]


def test_registered_attack_start_remains_observable_with_bounded_projection(tmp_path):
    earlier = timed_event("2025-01-06T00:00:01Z")
    attack = timed_event("2025-01-06T00:20:00Z", label="1", number=2)
    splits = {**config(), "max_records": 1}
    selection = build(tmp_path, [earlier, attack], splits, labels=registered_labels([attack]))
    assert selection["counts"]["attack"] == selection["N_D"] == selection["M_D"] == 1
    candidate = attack_candidates(selection)[0]
    assert candidate["time_from"] == "2025-01-06T00:20:00Z"
    assert candidate["projected_labels"] == {"malicious": 1}
    assert candidate["reason"] == "selected_attack"
    case_root = tmp_path / "test" / selection["cases"][0]["case_id"]
    manifest = json.loads((case_root / "agent/manifest.json").read_text())
    assert manifest["alert"]["created_at"] == "2025-01-06T00:35:00Z"
    assert manifest["time_to"] == "2025-01-06T00:50:00Z"
    assert "malicious" not in (case_root / "agent/events.jsonl").read_text()


def test_registered_windows_use_utc_greedy_nonoverlap_and_half_open_endpoints(tmp_path):
    first = timed_event("2025-01-06T01:20:00+01:00", label="1")
    interior = timed_event("2025-01-06T00:30:00Z", label="1", number=2)
    before_end = timed_event("2025-01-06T00:49:59.999Z", number=3)
    at_end = timed_event("2025-01-06T00:50:00Z", label="1", number=4)
    before_start = timed_event("2025-01-06T00:19:59.999Z", number=5)
    selection = build(tmp_path, [at_end, interior, before_end, first, before_start],
                      labels=registered_labels([at_end, interior, first]))
    candidates = attack_candidates(selection)
    assert [(r["time_from"], r["time_to"], r["raw_window_count"]) for r in candidates] == [
        ("2025-01-06T00:20:00Z", "2025-01-06T00:50:00Z", 3),
        ("2025-01-06T00:50:00Z", "2025-01-06T01:20:00Z", 1),
    ]
    assert all(row["reason"] == "selected_attack" for row in candidates)
    assert selection["N_D"] == 2


def test_grid_overlapping_registered_attack_is_excluded_before_benign_sampling(tmp_path):
    attack = timed_event("2025-01-06T00:20:00Z", label="1")
    events = [attack, timed_event("2025-01-06T00:01:00Z", number=2),
              timed_event("2025-01-06T00:40:00Z", number=3),
              timed_event("2025-01-06T01:00:00Z", number=4)]
    selection = build(tmp_path, events, labels=registered_labels([attack]))
    grid = [row for row in selection["candidate_ledger"] if row["candidate_kind"] == "grid"]
    assert [(r["time_from"], r["reason"]) for r in grid] == [
        ("2025-01-06T00:00:00Z", "overlaps_registered_attack_window"),
        ("2025-01-06T00:30:00Z", "overlaps_registered_attack_window"),
        ("2025-01-06T01:00:00Z", "selected_normal"),
    ]
    assert selection["counts"]["attack"] == selection["counts"]["normal"] == 1
    assert selection["candidate_closure"]


def test_window_dispatch_preserves_global_counts_and_per_window_duplicates(tmp_path):
    attack = timed_event("2025-01-06T00:20:00Z", label="1")
    normal = timed_event("2025-01-06T00:21:00Z", number=2)
    selection = build(tmp_path, [attack, attack, normal], labels=registered_labels([attack]))
    assert selection["scan"]["counts"]["parsed_rows"] == 3
    assert selection["scan"]["hosts"] == {"auditbeat:internalserver": 3}
    assert selection["scan"]["days"] == {"2025-01-06": 3}
    assert selection["scan"]["original_labels"] == {"benign": 1, "malicious": 2}
    assert selection["scan"]["label_fingerprints_matched"] == 1
    assert len(selection["candidate_ledger"]) == 2
    assert sum(row["raw_window_count"] for row in selection["candidate_ledger"]) == 6
    assert all(row["raw_window_count"] == 3 for row in selection["candidate_ledger"])
    assert all(row["duplicate_retained_rows"] == 1 for row in selection["candidate_ledger"])
    assert all(row["projected_count"] == 2 for row in selection["candidate_ledger"])


def test_registered_candidates_are_independent_of_label_input_order(tmp_path):
    events = [timed_event("2025-01-06T00:20:00Z", label="1"),
              timed_event("2025-01-06T00:30:00Z", label="1", number=2),
              timed_event("2025-01-06T00:50:00Z", label="1", number=3)]
    left = build(tmp_path / "left", events, labels=registered_labels(events))
    right = build(tmp_path / "right", reversed(events), labels=registered_labels(reversed(events)))
    assert left == right


@pytest.mark.parametrize("timestamp", ["2025-01-05T23:50:00Z", "2025-01-19T23:50:00Z"])
def test_registered_attack_crossing_test_boundary_is_excluded_and_recorded(tmp_path, timestamp):
    attack = timed_event(timestamp, label="1")
    events = [attack] if timestamp.startswith("2025-01-19") else []
    selection = build(tmp_path, events, labels=registered_labels([attack]))
    assert selection["N_D"] == selection["M_D"] == 0
    assert attack_candidates(selection)[0]["reason"] == "crosses_test_boundary"
    assert selection["candidate_closure"]


def test_registered_attack_on_grid_start_keeps_both_candidates(tmp_path):
    attack = timed_event("2025-01-06T00:30:00Z", label="1")
    selection = build(tmp_path, [attack], labels=registered_labels([attack]))
    assert len(selection["candidate_ledger"]) == 2
    assert {row["reason"] for row in selection["candidate_ledger"]} == {
        "selected_attack", "overlaps_registered_attack_window",
    }
    assert selection["N_D"] == 1


def test_unmatched_registered_attack_is_accounted_as_unobserved(tmp_path):
    attack = timed_event("2025-01-06T00:20:00Z", label="1")
    selection = build(tmp_path, [], labels=registered_labels([attack]))
    assert selection["N_D"] == 0
    assert attack_candidates(selection)[0]["reason"] == "registered_attack_not_observed"
    assert selection["scan"]["label_fingerprints_unmatched"] == 1


def test_window_uses_utc_and_half_open_boundaries():
    assert window_start("2025-01-06T01:30:00+01:00") == "2025-01-06T00:30:00Z"
    assert window_start("2025-01-06T00:29:59.999Z") == "2025-01-06T00:00:00Z"
    with pytest.raises(ValueError):
        window_start("2025-01-06T00:00:00")


def test_build_is_path_independent_and_separates_gold(tmp_path):
    events = [event(2), event(1, "1")]
    left = build(tmp_path / "one", events)
    right = build(tmp_path / "other-root", reversed(events))
    assert left == right
    assert left["counts"] == {"attack": 1, "normal": 0, "unscorable": 0}
    assert left["N_D"] == left["M_D"] == 1
    row = left["cases"][0]
    root = tmp_path / "one" / "test" / row["case_id"]
    agent = json.loads((root / "agent/manifest.json").read_text())
    assert agent["title"] == "Historical event review"
    assert agent["alert"]["created_at"] == "2025-01-06T00:15:00Z"
    assert agent["filters"]["dataset_id"].endswith(row["case_id"])
    assert agent["filters"]["host"] == "internalserver"
    assert "malicious" not in (root / "agent/events.jsonl").read_text()
    gold = [json.loads(x) for x in (root / "scoring/gold.jsonl").read_text().splitlines()]
    assert gold[0]["is_attack"] is True
    assert gold[0]["taxonomy_status"] == "out_of_taxonomy"
    assert not gold[0]["applicability"]["six_class"]
    assert left["status"] == "prepared_not_frozen"


@pytest.mark.parametrize("label,reason", [("2", "related_or_unknown"), ("3", "related_or_unknown")])
def test_related_or_unknown_windows_never_become_normal(tmp_path, label, reason):
    selection = build(tmp_path, [event(label=label)])
    assert selection["N_D"] == 0
    assert selection["counts"]["unscorable"] == 1
    assert selection["candidate_ledger"][0]["reason"] == reason


def test_truncation_cannot_select_invisible_attack(tmp_path):
    splits = config()
    splits["max_records"] = 1
    selection = build(tmp_path, [event(1), event(2, "1")], splits)
    assert not selection["cases"]
    assert selection["candidate_ledger"][0]["reason"] == "attack_outside_projection"


def test_duplicate_rows_and_ties_are_deterministic(tmp_path):
    one = event(label="1")
    selection = build(tmp_path, [one, one, event(2)])
    assert selection["cases"][0]["event_count"] == 2
    assert selection["candidate_ledger"][0]["duplicate_retained_rows"] == 1


def test_explicit_agent_allowlist_drops_answer_fields(tmp_path):
    raw = event(label="1")
    raw.update({"source_label": "malicious", "stage": "answer", "expected_answer": "hidden"})
    selection = build(tmp_path, [raw])
    path = tmp_path / "test" / selection["cases"][0]["case_id"] / "agent/events.jsonl"
    payload = json.loads(path.read_text())
    assert {"source_label", "stage", "expected_answer"}.isdisjoint(payload)


def test_calibration_with_positive_labels_fails_closed(tmp_path):
    raw = event(label="1")
    raw["observed_at"] = "2025-01-05T23:59:59Z"
    with pytest.raises(ValueError, match="calibration"):
        build(tmp_path, [raw])


def test_benign_sampling_closes_candidate_ledger(tmp_path):
    first, second = event(), event(2)
    second["observed_at"] = "2025-01-06T00:30:01Z"
    selection = build(tmp_path, [first, second])
    assert len(selection["candidate_ledger"]) == 2
    assert len(selection["cases"]) == 1
    assert {r["reason"] for r in selection["candidate_ledger"]} == {"selected_normal", "seeded_benign_not_selected"}


def test_unapproved_source_host_is_counted_not_selected(tmp_path):
    selection = build(tmp_path, [event(host="other-host")])
    assert not selection["cases"]
    assert selection["excluded_host_rows"] == 1


def test_existing_outputs_are_never_silently_overwritten(tmp_path):
    build(tmp_path, [event(label="1")])
    with pytest.raises(FileExistsError):
        build(tmp_path, [event(label="1")])


def test_official_source_verification_rejects_missing_or_modified_archive(tmp_path):
    source = Path(__file__).resolve().parents[2] / "data/manifests/dedale-sources.json"
    with pytest.raises((ValueError, FileNotFoundError)):
        verify_sources(source, tmp_path)


def test_audit_never_accepts_synthetic_or_missing_evidence(tmp_path):
    selection = build(tmp_path, [event(label="1")])
    report = audit_prepared(selection, tmp_path)
    assert report["accepted"] is False
    assert not report["gates"]["official_sources"]
    assert not report["gates"]["live_context"]
    assert not report["gates"]["scoring_filesystem_isolation"]
    assert not report["gates"]["cross_path_rebuild"]


def test_audit_detects_post_build_agent_tampering(tmp_path):
    selection = build(tmp_path, [event(label="1")])
    root = tmp_path / "test" / selection["cases"][0]["case_id"]
    (root / "agent/events.jsonl").write_text('{"source_label":"malicious"}\n')
    report = audit_prepared(selection, tmp_path)
    assert not report["gates"]["artifacts"]


def test_canonical_rejects_nan():
    with pytest.raises(ValueError):
        canonical({"nan": float("nan")})


def test_nested_scoring_fields_are_never_projected(tmp_path):
    row = event(label="1")
    row["process"] = {"name": "printf", "expected_answer": "gold", "args": ["printf", "ok"]}
    row["user"] = {"name": "employee", "labels": ["gold"]}
    selected = build(tmp_path, [row])
    path = tmp_path / "test" / selected["cases"][0]["case_id"] / "agent/events.jsonl"
    result = json.loads(path.read_text())
    assert result["process"] == {"name": "printf", "args": ["printf", "ok"]}
    assert result["user"] == {"name": "employee"}


def test_same_source_event_keeps_stable_minimum_provenance(tmp_path):
    first = event(label="1")
    second = {**first, "external_id": "dedale:" + "0" * 64, "line_number": 2}
    left = build(tmp_path / "left", [first, second])
    right = build(tmp_path / "right", [second, first])
    assert left == right


def test_audit_cannot_accept_self_asserted_evidence_booleans(tmp_path):
    attack, normal = event(label="1"), event()
    normal["observed_at"] = "2025-01-06T01:00:00Z"
    selection = build(tmp_path, [attack, normal])
    selection["official_label_archive_verified"] = True
    selection["scan"].update({"full_archive_scan": True, "label_fingerprints_expected": 1,
        "label_fingerprints_unmatched": 0, "observed_min": "2024-12-23T00:00:00Z", "observed_max": "2025-01-19T23:59:59Z"})
    report = audit_prepared(selection, tmp_path,
        source_report={"verified": True, "archives": [{"crc_checked": True}] * 3},
        live_report={"technical_chain_passed": True, "scoring_filesystem_isolation": "passed"},
        cross_path_report={"all_equal": True, "different_absolute_roots": True},
        review_report={"complete": True, "selection_sha256": "not-a-hash"})
    assert report["accepted"] is False
    assert not report["gates"]["official_sources"]
    assert not report["gates"]["stage_coverage"]
    assert not report["gates"]["cross_path_rebuild"]


def test_audit_rejects_changed_alert_scope_even_after_rehash(tmp_path):
    selection = build(tmp_path, [event(label="1")])
    case = selection["cases"][0]
    manifest = tmp_path / "test" / case["case_id"] / "agent/manifest.json"
    value = json.loads(manifest.read_text())
    value["alert"]["created_at"] = "2030-01-01T00:00:00Z"
    value["filters"] = {"host": "wrong-host", "dataset_id": "wrong-case"}
    value["limit"] = 10000
    manifest.write_text(canonical(value) + "\n", encoding="utf-8")
    case["artifacts"]["agent/manifest.json"] = hashlib.sha256(manifest.read_bytes()).hexdigest()
    assert not audit_prepared(selection, tmp_path)["gates"]["artifacts"]
