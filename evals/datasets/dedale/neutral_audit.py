"""Fail-closed acceptance of neutral v3 cases and their own raw-scan lineage."""
from __future__ import annotations

from collections import defaultdict
from pathlib import Path

from .common import canonical, read_json, safe_file, sha256
from .join_labels import load_label_index
from .neutralize import (
    PROTOCOL,
    _line_json,
    candidate_cut,
    canonical_clock,
    control_candidates,
    digest,
    eligible_members,
    implementation_hashes,
    instant,
    load_member_index,
    neutral_case_id,
    shift_seconds,
    start_exclusion,
    validate_neutral_policy,
)

_EMPTY = ("raw_window_count", "projected_count", "source_labels", "projected_labels", "duplicate_retained_rows")
_CONTROL_FIELDS = {"source", "host", "base_start", "base_end", "preparation_grid_raw_count", "candidate_kind", "original_anchor_timestamp",
                   "cut", "time_from", "time_to", "reason", *_EMPTY, "passes"}
_NORMAL_POLICY = {
    "candidate_basis": "v2 pure-benign grid rows with reason selected_normal or seeded_benign_not_selected",
    "group": ["source", "host", "UTC day"], "rank": "sha256(canonical([42,source,host,base_start]))",
    "jitter_context": "dedale-normal-control-v3", "jitter_milliseconds_mod": 1800000,
    "anchor_rule": "first actual observation at or after cut and before base_end", "width_seconds": 1800,
    "reject_cross_day": True, "reject_attack_overlap": True, "require_all_raw_labels": "benign",
    "choose": "first eligible candidate per source/host/UTC day", "after_selected": "not_evaluated_after_first_eligible",
}
_CASE_IDENTITY = {"excludes": ["kind", "label", "stage"],
                  "formula": "sha256(canonical([source,host,start]))[:16]", "prefix": "dedale-"}


def _require(condition, detail):
    if not condition:
        raise ValueError(detail)


def _positive(value):
    return type(value) is int and value > 0


def _receipts(actual, expected):
    wanted = [{key: row[key] for key in ("archive", "member", "jsonl_md5", "raw_rows", "jsonl_md5_verified")}
              for row in expected]
    _require(canonical(actual) == canonical(wanted), "target member receipt inventory or counters differ")


def _window_counts(row):
    from .audit import _histogram, _nonnegative

    raw, projected, duplicates = (row[name] for name in ("raw_window_count", "projected_count", "duplicate_retained_rows"))
    _require(_positive(raw) and _positive(projected) and projected <= min(raw, 100)
             and _nonnegative(duplicates) and duplicates <= raw - projected, "invalid targeted window counters")
    source, retained = row["source_labels"], row["projected_labels"]
    _require(_histogram(source, labels=True) and _histogram(retained, labels=True)
             and all(_positive(count) for counter in (source, retained) for count in counter.values())
             and sum(source.values()) == raw and sum(retained.values()) == projected
             and all(count <= source.get(label, 0) for label, count in retained.items()), "invalid targeted label counters")


def validate_candidate_ledger(selection, preparation, member_index):
    """Close every ranked candidate and receipt against the own-root v2 basis.

    Receipts alone are not authenticity evidence. Acceptance additionally requires
    fresh official source verification, actual checkpoint loading and a separate
    raw-derived cross-path rebuild of every final artifact.
    """
    ledger = selection["candidate_ledger"]
    _require(isinstance(ledger, list) and all(isinstance(row, dict) for row in ledger), "invalid final candidate ledger")
    expected_attacks = []
    registered = defaultdict(list)
    for row in preparation["candidate_ledger"]:
        if row["candidate_kind"] == "attack":
            registered[(row["source"], row["host"])].append((row["time_from"], row["time_to"]))
        if row["reason"] == "selected_attack":
            expected_attacks.append({**row, "time_from": canonical_clock(row["time_from"]),
                                    "time_to": canonical_clock(row["time_to"]),
                                    "case_id": neutral_case_id(row["source"], row["host"], row["time_from"])})
    actual_attacks = [row for row in ledger if row.get("candidate_kind") == "attack"]
    _require(canonical(sorted(actual_attacks, key=canonical)) == canonical(sorted(expected_attacks, key=canonical)),
             "final attacks differ from verified preparation observations")
    selected = {row["case_id"]: row for row in actual_attacks}
    groups = control_candidates(preparation["candidate_ledger"])
    actual_controls = [row for row in ledger if row.get("candidate_kind") == "control"]
    expected_candidates = [candidate for candidates in groups.values() for candidate in candidates]
    _require(len(ledger) == len(actual_attacks) + len(actual_controls)
             and len(actual_controls) == len(expected_candidates), "final candidate universe differs")
    chosen_groups = set()
    unscorable = 0
    for row, candidate in zip(actual_controls, expected_candidates, strict=True):
        selected_normal = row.get("reason") == "selected_normal"
        _require(set(row) == _CONTROL_FIELDS | ({"case_id"} if selected_normal else set())
                 and all(row.get(name) == value for name, value in candidate.items())
                 and row["cut"] == candidate_cut(candidate), "control identity, fields or registered cut differ")
        group = row["source"], row["host"], row["base_start"][:10]
        reason, start = row["reason"], row["time_from"]
        _require(isinstance(row["passes"], dict) and set(row["passes"]) == {"anchor", "window"}, "invalid control pass fields")
        if group in chosen_groups:
            _require(reason == "not_evaluated_after_first_eligible" and start is None and row["time_to"] is None
                     and row["original_anchor_timestamp"] is None
                     and all(row[name] is None for name in _EMPTY)
                     and row["passes"] == {"anchor": None, "window": None}, "unevaluated control must retain null statistics")
            continue
        _require(reason != "not_evaluated_after_first_eligible", "control skipped before first eligible candidate")
        _receipts(row["passes"]["anchor"], eligible_members(member_index, row["source"], row["host"], row["cut"], row["base_end"]))
        if start is None:
            _require(reason == "no_event_after_cut" and row["time_to"] is None
                     and row["original_anchor_timestamp"] is None
                     and all(row[name] is None for name in _EMPTY) and row["passes"]["window"] is None,
                     "missing anchor has invented statistics")
            unscorable += 1
            continue
        _require(instant(row["cut"]) <= instant(start) < instant(row["base_end"])
                 and start == canonical_clock(row["original_anchor_timestamp"])
                 and row["time_to"] == canonical_clock(shift_seconds(start, 1800)), "anchor outside registered search interval")
        exclusion = start_exclusion(start, registered[group[:2]])
        if exclusion:
            _require(reason == exclusion and all(row[name] is None for name in _EMPTY)
                     and row["passes"]["window"] is None, "excluded anchor has wrong reason or invented window counts")
            unscorable += 1
            continue
        _receipts(row["passes"]["window"], eligible_members(member_index, row["source"], row["host"], start, row["time_to"]))
        _window_counts(row)
        expected_reason = "selected_normal" if set(row["source_labels"]) == {"benign"} else "window_not_entirely_benign"
        _require(reason == expected_reason, "control decision contradicts complete raw label counts")
        if selected_normal:
            case_id = neutral_case_id(row["source"], row["host"], start)
            _require(row["case_id"] == case_id and case_id not in selected, "case identity contains class or collides")
            selected[case_id] = row
            chosen_groups.add(group)
        else:
            unscorable += 1
    _require(type(selection["counts"].get("unscorable")) is int
             and selection["counts"]["unscorable"] == unscorable, "excluded candidate count differs")
    return selected


def _policy_and_lineage(selection, preparation, *, sources, splits, scan_splits, label_policy, prepared_root):
    from .checkpoint import code_hashes
    from .scan import _validate_policy, _validate_scan_splits

    policy, old_splits, labels_policy = (read_json(path) for path in (splits, scan_splits, label_policy))
    _validate_scan_splits(old_splits)
    _validate_policy(labels_policy)
    old_inputs = preparation["input_sha256"]
    validate_neutral_policy(policy, old_splits, old_inputs["splits"])
    for name, path in (("sources", sources), ("splits", scan_splits), ("label_policy", label_policy)):
        _require(sha256(path) == old_inputs[name], "preparation configuration has changed: " + name)
    prepared_hash = sha256(safe_file(prepared_root, "selection.json"))
    expected_inputs = {**old_inputs, "splits": sha256(splits), "preparation_splits": old_inputs["splits"],
                       "preparation_selection": prepared_hash}
    _require(canonical(selection["input_sha256"]) == canonical(expected_inputs), "final inputs differ from own preparation and v3 policy")
    for name in ("dataset_id", "window_seconds", "max_records", "seed", "benign_per_host_day", "periods", "bounds"):
        _require(canonical(policy.get(name)) == canonical(old_splits[name]), "v3 investigation scope changed: " + name)
    _require(type(policy.get("schema_version")) is int and policy["schema_version"] == 1
             and policy.get("protocol") == PROTOCOL and policy.get("timezone") == "UTC"
             and policy.get("status") == "preregistered_not_frozen"
             and canonical(policy.get("normal_control")) == canonical(_NORMAL_POLICY)
             and canonical(policy.get("case_identity")) == canonical(_CASE_IDENTITY)
             and policy.get("preparation_splits_sha256") == old_inputs["splits"]
             and policy.get("preparation_code_sha256") == code_hashes(), "v3 neutral sampling protocol changed")
    revision = policy["preregistration_revision"]
    _require(all(type(revision.get(name)) is int for name in ("revision", "formal_model_runs", "accepted_cases"))
             and revision["revision"] == 3 and revision["formal_model_runs"] == revision["accepted_cases"] == 0
             and revision.get("previous_split_sha256") == old_inputs["splits"], "invalid v3 preregistration lineage")
    _require(selection.get("protocol") == PROTOCOL and selection.get("status") == "prepared_not_frozen"
             and selection.get("dataset_id") == "dedale-v2.1" and selection.get("split") == "test"
             and type(selection.get("schema_version")) is int and selection["schema_version"] == 1,
             "invalid final preparation status or protocol")
    lineage = selection["preparation"]
    _require(set(lineage) == {"selection_sha256", "input_sha256", "checkpoint_binding", "member_index",
                              "member_index_sha256", "scan_protocol", "attack_reuse"}
             and lineage["selection_sha256"] == prepared_hash
             and canonical(lineage["input_sha256"]) == canonical(old_inputs)
             and lineage["member_index_sha256"] == digest(lineage["member_index"])
             and lineage["scan_protocol"] == "independent v2 full archive scan, not relabeled as a v3 full scan"
             and lineage["attack_reuse"] == "This root's independently prepared, artifact-verified attack observations only",
             "final preparation lineage differs")
    for name in ("scan", "source_verification", "source_label_summary", "official_label_archive_verified", "excluded_host_rows"):
        _require(canonical(selection[name]) == canonical(preparation[name]), "transported full-scan lineage differs: " + name)
    _require(canonical(selection["preparation_ledger"]) == canonical(preparation["candidate_ledger"]), "transported v2 candidate ledger differs")
    _require(selection.get("finalizer_code_sha256") == implementation_hashes(), "finalizer code changed after preparation")
    return old_splits


def _observation_lineage(selection, preparation, cases_root, prepared_root, selected):
    """Check attack reuse byte-for-byte and real control-anchor provenance."""
    old_attacks = {}
    for case in preparation["cases"]:
        if case["is_attack"] is True:
            old_attacks[(case["host"], instant(case["time_from"]), instant(case["time_to"]))] = case
    for case in selection["cases"]:
        row = selected[case["case_id"]]
        records = _line_json(safe_file(cases_root, "test/" + case["case_id"] + "/agent/events.jsonl"))
        _require(len({(record["source"], record["event_fingerprint"]) for record in records}) == len(records),
                 "final projection repeats a canonical event")
        order = [(instant(record["observed_at"]), record["external_id"]) for record in records]
        _require(order == sorted(order) and len(set(order)) == len(order), "final projection sort changed")
        if row["candidate_kind"] == "attack":
            old = old_attacks[(case["host"], instant(case["time_from"]), instant(case["time_to"]))]
            original = _line_json(safe_file(prepared_root, "test/" + old["case_id"] + "/agent/events.jsonl"))
            normalized = lambda values: [{**value, "dataset_id": "dedale-v2.1"} for value in values]
            _require(canonical(normalized(records)) == canonical(normalized(original)), "final attack observations changed")
        else:
            _require(records and instant(records[0]["observed_at"]) == instant(row["time_from"])
                     and instant(row["original_anchor_timestamp"]) == instant(records[0]["observed_at"]),
                     "control anchor is not a retained actual observation")
            allowed = {(receipt["archive"], receipt["member"]): receipt for receipt in row["passes"]["window"]}
            for record in records:
                receipt = allowed[(record["archive"], record["relative_log_path"])]
                _require(type(record["line_number"]) is int and 1 <= record["line_number"] <= receipt["raw_rows"],
                         "control observation provenance outside re-read members")


def _final_cross_path_check(report, selection, cases_root, source_report, data_root, prepared_root, scan_splits):
    from scripts.dedale_task12_crosspath_check import compare_artifacts

    from .audit import _cross_path_check

    if not _cross_path_check(report, selection, cases_root, source_report, data_root):
        return False
    try:
        first, second = (Path(report[name]).resolve() for name in ("original_prepared_root", "rebuild_prepared_root"))
        other_raw = Path(report["rebuild_data_root"]).resolve()
        _require(first == Path(prepared_root).resolve() and first != second, "cross-path preparation roots do not match")
        _require(not first.is_relative_to(second) and not second.is_relative_to(first), "cross-path preparations overlap")
        inputs = report["preparation_input_files"]
        _require(set(inputs) == {"scan_splits"}, "cross-path preparation config inventory differs")
        row = inputs["scan_splits"]
        expected = selection["input_sha256"]["preparation_splits"]
        _require(row["sha256"] == expected and Path(row["original_path"]).resolve() == Path(scan_splits).resolve()
                 and sha256(Path(row["original_path"])) == sha256(Path(row["rebuild_path"])) == expected
                 and Path(row["rebuild_path"]).resolve().is_relative_to(other_raw), "cross-path scan policy binding differs")
        old = read_json(safe_file(first, "selection.json"))
        _require(sha256(safe_file(first, "selection.json")) == sha256(safe_file(second, "selection.json"))
                 == selection["preparation"]["selection_sha256"], "independent preparations differ")
        return compare_artifacts(first, second, old)["all_equal"] is True
    except (KeyError, ValueError, TypeError, OSError):
        return False


def audit_neutral_prepared(selection, cases_root, *, sources=None, data_root=None, prepared_root=None,
                           preparation_checkpoints=None, splits=None, scan_splits=None, label_policy=None,
                           live_report=None, cross_path_report=None, review_report=None, live_events_path=None,
                           live_raw_events_path=None, resource_report=None, freeze_date=None):
    from .audit import _audit_cases, _stage_review, audit_prepared

    gates = dict.fromkeys(("official_sources", "official_labels", "artifacts", "candidate_closure", "minimum_size",
                           "dates", "complete_label_join", "stage_coverage", "live_context", "scoring_filesystem_isolation",
                           "cross_path_rebuild", "resource_measurement", "preparation_lineage", "neutral_policy",
                           "targeted_member_receipts", "finalizer_code"), False)
    errors, source_report, gold = [], None, {}
    try:
        _require(all(value is not None for value in (sources, data_root, prepared_root, preparation_checkpoints,
                                                    splits, scan_splits, label_policy)), "required final lineage paths missing")
        cases_root, prepared_root, data_root = map(Path, (cases_root, prepared_root, data_root))
        _require(cases_root.resolve() != prepared_root.resolve()
                 and not cases_root.resolve().is_relative_to(prepared_root.resolve())
                 and not prepared_root.resolve().is_relative_to(cases_root.resolve()), "final and preparation roots overlap")
        _require(canonical(read_json(safe_file(cases_root, "selection.json"))) == canonical(selection), "final selection differs from actual file")
        preparation = read_json(safe_file(prepared_root, "selection.json"))
        _require(preparation.get("protocol") != PROTOCOL, "v3 cannot serve as its own v2 preparation")
        old_splits = _policy_and_lineage(selection, preparation, sources=sources, splits=splits,
            scan_splits=scan_splits, label_policy=label_policy, prepared_root=prepared_root)
        gates["neutral_policy"] = gates["finalizer_code"] = True
        old = audit_prepared(preparation, prepared_root, sources=sources, data_root=data_root,
            live_report=live_report, live_events_path=live_events_path, live_raw_events_path=live_raw_events_path,
            resource_report=resource_report, freeze_date=freeze_date)
        source_report = old["source_verification"]
        for name in ("official_sources", "official_labels", "dates", "complete_label_join", "live_context",
                     "scoring_filesystem_isolation", "resource_measurement"):
            gates[name] = old["gates"][name]
        _require(all(old["gates"][name] for name in ("official_sources", "official_labels", "artifacts",
                 "candidate_closure", "dates", "complete_label_join")), "own v2 preparation failed fresh raw and artifact audit")
        _require(canonical(selection["source_verification"]) == canonical(source_report),
                 "transported source verification differs from fresh official-byte verification")
        labels = load_label_index(safe_file(data_root, "system_logs_labels.zip"), exhaustive=True)
        _require(labels.official_verified and labels.exhaustive, "final labels lack official exhaustive verification")
        index, binding = load_member_index(data_root=data_root, prepared_root=prepared_root,
            preparation_checkpoints=Path(preparation_checkpoints), selection=preparation, labels=labels, scan_splits=old_splits)
        _require(canonical(index) == canonical(selection["preparation"]["member_index"])
                 and canonical(binding) == canonical(selection["preparation"]["checkpoint_binding"]), "actual own checkpoints differ from final member lineage")
        gates["preparation_lineage"] = True
        selected = validate_candidate_ledger(selection, preparation, index)
        gates["targeted_member_receipts"] = True
        artifact_gates, gold, artifact_errors = _audit_cases(selection, cases_root, selected,
            labels=labels, official_labels=True, precise=True)
        gates.update(artifact_gates)
        gates["candidate_closure"] = gates["candidate_closure"] and selection.get("candidate_closure") is True
        errors.extend(artifact_errors)
        _observation_lineage(selection, preparation, cases_root, prepared_root, selected)
        gates["cross_path_rebuild"] = _final_cross_path_check(cross_path_report, selection, cases_root,
            source_report, data_root, prepared_root, scan_splits)
    except (KeyError, ValueError, TypeError, OSError, AttributeError, OverflowError) as exc:
        errors.append({"neutral_acceptance": type(exc).__name__, "detail": str(exc)})
        # A failure after artifact hashes pass still invalidates the raw-to-case lineage.
        gates["candidate_closure"] = False
    gates["stage_coverage"] = _stage_review(review_report, selection, gold)
    return {"schema_version": 1, "protocol": PROTOCOL, "accepted": all(gates.values()), "gates": gates,
            "failed_gates": [name for name, passed in gates.items() if not passed], "errors": errors,
            "N_D": selection.get("N_D", 0), "M_D": selection.get("M_D", 0),
            "source_verification": source_report, "model_invocations": 0}
