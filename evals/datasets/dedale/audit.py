"""Fail-closed validation of prepared DEDALE data and acceptance evidence."""
from __future__ import annotations

import calendar
import hashlib
from collections import Counter, defaultdict
from datetime import UTC, datetime, timedelta, timezone
from itertools import pairwise
from pathlib import Path

from .build_manifests import project_observations, stamp, utc, window_start
from .common import canonical, read_json, safe_file, sha256, verify_sources
from .join_labels import EXHAUSTIVE_HOSTS, load_label_index
from .parse import read_archive_manifest

STAGES = frozenset({"initial_access", "execution", "persistence", "command_and_control", "discovery", "lateral_movement", "collection", "exfiltration"})
ROOT = Path(__file__).resolve().parents[3]
AGENT_MANIFEST_FIELDS = frozenset({"schema_version", "case_id", "dataset_id", "scenario", "split", "title", "events_file", "events_sha256", "event_count", "time_from", "time_to", "bounds", "filters", "limit", "alert"})
SOURCE_LABELS = frozenset({"benign", "malicious", "malicious-related", "unscorable"})
TEST_START, TEST_END = utc("2025-01-06T00:00:00Z"), utc("2025-01-20T00:00:00Z")


def _nonnegative(value):
    return type(value) is int and value >= 0


def _histogram(value, *, labels=False):
    return (isinstance(value, dict) and all(isinstance(key, str) and _nonnegative(count) for key, count in value.items())
            and (not labels or set(value) <= SOURCE_LABELS))


def _scan_metadata_consistent(scan, data_root):
    """Read only small MD5 manifests, then reconcile every transported counter."""
    try:
        expected, archive_rows = set(), []
        for source in sorted(EXHAUSTIVE_HOSTS):
            archive = f"system_logs_{source}.zip"
            manifest = read_archive_manifest(safe_file(Path(data_root), archive))
            if manifest is None or manifest["unique_members"] != 672 or len(manifest["checksums"]) != 672:
                return False
            expected.update((archive, member) for member in manifest["checksums"])
            archive_rows.append({"archive": archive, **{key: manifest[key] for key in ("member", "unique_members", "duplicate_entries")},
                                 "checksums_sha256": hashlib.sha256(canonical(manifest["checksums"]).encode()).hexdigest()})
        if (type(scan.get("members_expected")) is not int or scan["members_expected"] != 1344
                or type(scan.get("members_completed")) is not int or scan["members_completed"] != 1344
                or canonical(sorted(scan["archive_manifests"], key=lambda row: row["archive"])) != canonical(archive_rows)):
            return False
        summaries = scan["member_summaries"]
        seen, totals, provider_totals = set(), Counter(), Counter()
        for row in summaries:
            key = (row["archive"], row["member"])
            if key in seen or key not in expected or row.get("jsonl_md5_verified") is not True:
                return False
            seen.add(key)
            if not all(_nonnegative(row.get(name)) for name in ("raw_rows", "parsed_rows", "invalid_rows")):
                return False
            if row["raw_rows"] != row["parsed_rows"] + row["invalid_rows"]:
                return False
            totals.update({name: row[name] for name in ("raw_rows", "parsed_rows", "invalid_rows")})
            provider_totals[row["archive"]] += row["parsed_rows"]
        counts = scan["counts"]
        if (seen != expected or len(summaries) != 1344 or not _histogram(counts)
                or any(counts.get(name) != totals[name] for name in ("raw_rows", "parsed_rows", "invalid_rows"))
                or not _nonnegative(scan.get("invalid_rows")) or scan["invalid_rows"] != totals["invalid_rows"] or totals["parsed_rows"] <= 0):
            return False
        parsed = totals["parsed_rows"]
        if (not all(_histogram(scan.get(name), labels=name == "original_labels")
                    and all(value > 0 for value in scan[name].values())
                    and sum(scan[name].values()) == parsed for name in ("hosts", "days", "original_labels"))):
            return False
        minimum, maximum = utc(scan["observed_min"]), utc(scan["observed_max"])
        if minimum > maximum or minimum.date().isoformat() != min(scan["days"]) or maximum.date().isoformat() != max(scan["days"]):
            return False
        calibration = outside = 0
        first = utc("2024-12-23T00:00:00Z")
        for day, count in scan["days"].items():
            observed = utc(day + "T00:00:00Z")
            if observed.date().isoformat() != day:
                return False
            if not first <= observed < TEST_END:
                outside += count
            elif observed < TEST_START:
                calibration += count
        excluded, host_provider_totals = 0, Counter()
        for provider_host, count in scan["hosts"].items():
            provider, separator, host = provider_host.partition(":")
            if not separator or provider not in EXHAUSTIVE_HOSTS or not host:
                return False
            host_provider_totals[f"system_logs_{provider}.zip"] += count
            if host not in EXHAUSTIVE_HOSTS[provider]:
                excluded += count
        # Host totals also cover calibration. An excluded host may occur in
        # calibration, so only the test-row upper bound is available here.
        return (counts.get("calibration_rows", 0) == calibration and counts.get("outside_period_rows", 0) == outside
                and provider_totals == host_provider_totals
                and counts.get("excluded_host_rows", 0) <= excluded
                and counts.get("excluded_host_rows", 0) <= parsed - calibration - outside)
    except (KeyError, ValueError, TypeError, OSError, AttributeError):
        return False


def _ledger_consistent(selection, labels=None):
    """Grid rows partition eligible input; attack rows have separate accounting."""
    selected = {}
    try:
        if (not all(_nonnegative(selection.get(name)) for name in ("N_D", "M_D"))
                or not all(_nonnegative(selection.get("counts", {}).get(name)) for name in ("attack", "normal", "unscorable"))):
            return False, selected
        ledger, seen = selection["candidate_ledger"], set()
        attacks, benign, grid_labels = defaultdict(list), defaultdict(list), Counter()
        grid_rows, unscorable = 0, 0
        for row in ledger:
            source, host, start, kind = (row[name] for name in ("source", "host", "time_from", "candidate_kind"))
            key = (source, host, start, kind)
            begin, end = utc(start), utc(row["time_to"])
            if (key in seen or host not in EXHAUSTIVE_HOSTS.get(source, ()) or kind not in {"grid", "attack"}
                    or start != stamp(begin) or end - begin != timedelta(seconds=1800)):
                return False, selected
            seen.add(key)
            raw, projected, duplicates = (row[name] for name in ("raw_window_count", "projected_count", "duplicate_retained_rows"))
            if (not all(_nonnegative(value) for value in (raw, projected, duplicates)) or not 0 <= projected <= min(raw, 100)
                    or duplicates > raw - projected or not _histogram(row["source_labels"], labels=True)
                    or not _histogram(row["projected_labels"], labels=True)
                    or sum(row["source_labels"].values()) != raw or sum(row["projected_labels"].values()) != projected
                    or any(value > row["source_labels"].get(label, 0) for label, value in row["projected_labels"].items())):
                return False, selected
            if kind == "grid":
                if raw <= 0 or window_start(start) != start or not TEST_START <= begin < TEST_END:
                    return False, selected
                grid_rows += raw
                grid_labels.update(row["source_labels"])
            else:
                attacks[(source, host)].append((begin, end))
        if labels is not None:
            registered = set()
            groups = defaultdict(set)
            for entry in labels.entries.values():
                if entry["label"] == "malicious":
                    groups[(entry["source"], entry["host"])].add(utc(entry["timestamp"]))
            for (source, host), times in groups.items():
                previous_end = None
                for begin in sorted(times):
                    if previous_end is None or begin >= previous_end:
                        registered.add((source, host, stamp(begin), "attack"))
                        previous_end = begin + timedelta(seconds=1800)
            if {key for key in seen if key[3] == "attack"} != registered:
                return False, selected
        for windows in attacks.values():
            windows.sort()
            if any(left[1] > right[0] for left, right in pairwise(windows)):
                return False, selected
        overlaps = set()
        for row in ledger:
            key = (row["source"], row["host"], row["time_from"], row["candidate_kind"])
            begin, end = utc(row["time_from"]), utc(row["time_to"])
            if key[3] == "grid" and any(begin < last and first < end for first, last in attacks[key[:2]]):
                overlaps.add(key)
            elif key[3] == "grid" and set(row["source_labels"]) == {"benign"}:
                benign[(key[0], key[1], key[2][:10])].append(key)
        sampled = {min(keys, key=lambda key: hashlib.sha256(canonical([42, *key[:3]]).encode()).hexdigest()) for keys in benign.values()}
        for row in ledger:
            key = (row["source"], row["host"], row["time_from"], row["candidate_kind"])
            begin, end = utc(row["time_from"]), utc(row["time_to"])
            raw_labels, projected_labels = row["source_labels"], row["projected_labels"]
            if key[3] == "attack" and (begin < TEST_START < end or begin < TEST_END < end):
                reason = "crosses_test_boundary"
            elif key[3] == "attack" and not TEST_START <= begin < TEST_END:
                reason = "outside_test_period"
            elif key in overlaps:
                reason = "overlaps_registered_attack_window"
            elif key[3] == "attack" and not raw_labels.get("malicious", 0):
                reason = "registered_attack_not_observed"
            elif raw_labels.get("malicious", 0):
                reason = "selected_attack" if projected_labels.get("malicious", 0) else "attack_outside_projection"
            elif set(raw_labels) != {"benign"}:
                reason = "related_or_unknown"
            else:
                reason = "selected_normal" if key in sampled else "seeded_benign_not_selected"
            if row["reason"] != reason:
                return False, selected
            if reason in {"selected_attack", "selected_normal"}:
                identifier = "dedale-" + hashlib.sha256(canonical(key).encode()).hexdigest()[:16]
                if row.get("case_id") != identifier or identifier in selected:
                    return False, selected
                selected[identifier] = row
            elif row.get("case_id") is not None:
                return False, selected
            elif reason not in {"seeded_benign_not_selected", "overlaps_registered_attack_window"}:
                unscorable += 1
        scan, counts = selection["scan"], selection["scan"]["counts"]
        eligible = counts["parsed_rows"] - sum(counts.get(name, 0) for name in ("calibration_rows", "outside_period_rows", "excluded_host_rows"))
        if (grid_rows != eligible or any(count > scan["original_labels"].get(label, 0) for label, count in grid_labels.items())
                or selection["counts"].get("unscorable") != unscorable):
            return False, selected
        return True, selected
    except (KeyError, ValueError, TypeError, AttributeError):
        return False, selected


def _runtime_hashes_match(report: dict) -> bool:
    try:
        from scripts.dedale_task12_live_check import dependency_tree_sha256

        hashes = report["runtime_artifacts"]
        return (sha256(ROOT / "scripts/dedale_task12_live_check.py") == hashes["harness_sha256"]
                and sha256(ROOT / "scripts/dedale_task12_runtime.py") == hashes["bootstrap_sha256"]
                and dependency_tree_sha256(ROOT / "services/backend/src") == hashes["backend_source_sha256"]
                and dependency_tree_sha256(ROOT / "data/dedale/runtime/linux-packages") == hashes["linux_dependencies_sha256"])
    except (KeyError, OSError, TypeError, ValueError):
        return False


def _live_checks(report, *, events_path=None, raw_events_path=None):
    if (not isinstance(report, dict) or report.get("status") != "passed"
            or report.get("live_acceptance_passed") is not True):
        return False, False
    checks = report.get("checks", {})
    required = {"source_projection", "duplicate_import", "get_alert_context", "search_security_events",
                "mcp_negative_probes", "half_open_window", "real_service_chain", "isolated_resource_cleanup",
                "container_cleanup"}
    if (not isinstance(checks, dict) or not required.issubset(checks)
            or any(not isinstance(row, dict) or row.get("status") != "passed" for row in checks.values())):
        return False, False
    if events_path is None or raw_events_path is None:
        return False, False
    try:
        bound = sha256(events_path) == report["input_sha256"] and sha256(raw_events_path) == report["original_input_sha256"]
    except (KeyError, OSError):
        return False, False
    if not bound or report.get("model_invocations") != 0 or not report.get("content_hashes") or not _runtime_hashes_match(report):
        return False, False
    isolation = checks.get("scoring_filesystem_isolation", {})
    probe = isolation.get("same_process_probe", {})
    inspect = isolation.get("container_inspection", {})
    mounts = inspect.get("mounts", [])
    denied = probe.get("forbidden_reads", [])
    allowed_targets = {"/app/agent", "/app/backend/src", "/app/runtime.py", "/opt/dedale-deps"}
    isolated = (isolation.get("status") == "passed" and isolation.get("host_scoring_canary_exists") is True
                and probe.get("agent_readable") is True and probe.get("pid") == 1
                and bool(probe.get("nonce")) and bool(probe.get("hostname"))
                and probe.get("hostname") == inspect.get("hostname")
                and inspect.get("container_id", "").startswith(probe.get("hostname", "missing"))
                and probe.get("agent_sha256") == report.get("runtime_artifacts", {}).get("agent_events_sha256")
                and len(denied) >= 5 and all(r.get("readable") is False and r.get("error_type") in {"FileNotFoundError", "PermissionError"} for r in denied)
                and inspect.get("root_read_only") is True and inspect.get("privileged") is False
                and "ALL" in inspect.get("capabilities_dropped", []) and inspect.get("no_new_privileges") is True
                and inspect.get("private_pid_namespace") is True and inspect.get("user") == "65532:65532"
                and len(mounts) == 4 and {r.get("target") for r in mounts} == allowed_targets
                and all(r.get("read_only") is True for r in mounts))
    return True, isolated


def _stage_review(report, selection, gold_by_case):
    if not isinstance(report, dict) or report.get("complete") is not True:
        return False
    digest = hashlib.sha256((canonical(selection) + "\n").encode()).hexdigest()
    if report.get("selection_sha256") != digest or not report.get("reviewer"):
        return False
    stages = report.get("stages", [])
    if len(stages) != len(STAGES) or {r.get("stage") for r in stages} != STAGES:
        return False
    for row in stages:
        if not row.get("basis_url") or not row.get("reason"):
            return False
        if row.get("observable") is True:
            if not row.get("evidence"):
                return False
            for evidence in row["evidence"]:
                gold = gold_by_case.get(evidence.get("case_id"), {})
                if gold.get(evidence.get("external_id"), {}).get("is_attack") is not True:
                    return False
        elif row.get("observable") is not False:
            return False
    return True


def _cross_path_check(report, selection, cases_root, source_report, data_root):
    if not isinstance(report, dict) or not source_report or data_root is None:
        return False
    try:
        other = Path(report["rebuild_cases_root"]).resolve()
        other_data = Path(report["rebuild_data_root"]).resolve()
        if not other.is_absolute() or other == Path(cases_root).resolve() or other_data == Path(data_root).resolve():
            return False
        if Path(report["original_cases_root"]).resolve() != Path(cases_root).resolve():
            return False
        if Path(report["original_data_root"]).resolve() != Path(data_root).resolve():
            return False
        if read_json(other / "selection.json") != selection:
            return False
        input_files = report["input_files"]
        if set(input_files) != {"sources", "splits", "label_policy"}:
            return False
        for name, row in input_files.items():
            digest = selection["input_sha256"][name]
            if row["sha256"] != digest or sha256(Path(row["original_path"])) != digest or sha256(Path(row["rebuild_path"])) != digest:
                return False
            if not Path(row["rebuild_path"]).resolve().is_relative_to(other_data):
                return False
        copied_source = read_json(Path(input_files["sources"]["rebuild_path"]))
        if sha256(safe_file(other_data, copied_source["metadata_snapshot"]["path"])) != source_report["metadata_sha256"]:
            return False
        for row in source_report["archives"]:
            if sha256(safe_file(other_data, row["path"])) != row["sha256"]:
                return False
        from scripts.dedale_task12_crosspath_check import compare_artifacts

        if compare_artifacts(Path(cases_root), other, selection)["all_equal"] is not True:
            return False
    except (KeyError, ValueError, TypeError, OSError):
        return False
    return True


def _audit_cases(selection, cases_root, selected_rows, *, labels=None, official_labels=False, precise=False):
    """Re-read all five artifacts with the same strict rules for every protocol."""
    if precise:
        from .neutralize import instant, shift_seconds
        clock = instant
        middle = lambda value: shift_seconds(value, 900)
        width_ok = lambda begin, end: shift_seconds(begin, 1800) == end
    else:
        clock = utc
        middle = lambda value: stamp(utc(value) + timedelta(seconds=900))
        width_ok = lambda begin, end: utc(end) - utc(begin) == timedelta(seconds=1800)
    gates = {"artifacts": bool(selection.get("cases")), "candidate_closure": True, "minimum_size": False}
    errors = []
    cases = selection.get("cases", [])
    if (not all(_nonnegative(selection.get(name)) for name in ("N_D", "M_D"))
            or not all(_nonnegative(selection.get("counts", {}).get(name)) for name in ("attack", "normal", "unscorable"))
            or len({row.get("case_id") for row in cases}) != len(cases)
            or set(selected_rows) != {row.get("case_id") for row in cases}
            or selection.get("N_D") != len(cases) or selection.get("M_D") != len(cases)
            or selection.get("ablation_case_ids") != sorted(row["case_id"] for row in cases)):
        gates["candidate_closure"] = False
    previous, gold_by_case = {}, {}
    actual_attack_count = actual_normal_count = 0
    for case in cases:
        try:
            if not _nonnegative(case.get("event_count")) or not 1 <= case["event_count"] <= 100:
                raise ValueError("case event_count must be an integer in the investigation scope")
            root = safe_file(cases_root, "test/" + case["case_id"])
            expected_files = {"agent/events.jsonl", "agent/manifest.json", "scoring/gold.jsonl", "scoring/source-gold.json", "scoring/manifest.json"}
            if set(case["artifacts"]) != expected_files:
                raise ValueError("missing artifact hashes")
            for relative, digest in case["artifacts"].items():
                if sha256(safe_file(root, relative)) != digest:
                    raise ValueError("artifact hash mismatch")
            manifest = read_json(root / "agent/manifest.json")
            score = read_json(root / "scoring/manifest.json")
            source_gold = read_json(root / "scoring/source-gold.json")
            expected_source_gold = {"observed_source_ips": [], "entry_candidates": [],
                                    "applicability": {"origin": False}, "reason": "No reviewed source attribution gold"}
            expected_case_applicability = {"attack_binary": True, "six_class": False,
                                           "phases": False, "techniques": False, "origin": False}
            # A separate coverage review does not supply event-level stage or
            # source attribution gold, so it cannot open these scoring masks.
            if (canonical(source_gold) != canonical(expected_source_gold)
                    or canonical(score.get("case_applicability")) != canonical(expected_case_applicability)
                    or score.get("stage_review") != "pending"):
                raise ValueError("unreviewed scoring dimensions must remain inapplicable")
            if (set(manifest) != AGENT_MANIFEST_FIELDS or type(manifest.get("schema_version")) is not int
                    or manifest["schema_version"] != 1 or manifest.get("scenario") != "dedale"
                    or manifest.get("events_file") != "events.jsonl" or manifest.get("event_count") != case["event_count"]):
                raise ValueError("agent manifest has unapproved fields or metadata")
            with (root / "agent/events.jsonl").open(encoding="utf-8") as stream:
                import json
                events = [json.loads(row) for row in stream]
            with (root / "scoring/gold.jsonl").open(encoding="utf-8") as stream:
                gold = [json.loads(row) for row in stream]
            row = selected_rows[case["case_id"]]
            projected_labels = Counter(truth["source_label"] for truth in gold)
            expected_counts = {"selected": len(gold), "attack": projected_labels["malicious"], "normal": projected_labels["benign"],
                               "unknown": projected_labels["malicious-related"] + projected_labels["unscorable"]}
            if (any(case[name] != row[name] for name in ("host", "time_from", "time_to"))
                    or case["event_count"] != row["projected_count"] or dict(projected_labels) != row["projected_labels"]
                    or any(observation["source"] != row["source"] for observation in events)
                    or canonical(score.get("window")) != canonical({key: value for key, value in row.items() if key != "case_id"})
                    or canonical(score.get("counts")) != canonical(expected_counts)):
                gates["candidate_closure"] = False
                raise ValueError("candidate, scoring window, and projected gold differ")
            gold_by_case[case["case_id"]] = {r["external_id"]: r for r in gold}
            if manifest["case_id"] != case["case_id"] or manifest["events_sha256"] != case["artifacts"]["agent/events.jsonl"]:
                raise ValueError("agent identity mismatch")
            dataset_id = "dedale-v2.1:" + case["case_id"]
            expected_filters = {"host": case["host"], "dataset_id": dataset_id}
            expected_alert = {"title": "Historical event review", "host": case["host"],
                              "created_at": middle(case["time_from"])}
            if (manifest.get("filters") != expected_filters or manifest.get("alert") != expected_alert
                    or manifest.get("dataset_id") != dataset_id or manifest.get("limit") != 100
                    or manifest.get("time_from") != case["time_from"] or manifest.get("time_to") != case["time_to"]
                    or manifest.get("bounds") != "[start,end)" or manifest.get("split") != "test"
                    or not width_ok(case["time_from"], case["time_to"])):
                raise ValueError("alert or query scope differs from frozen window")
            expected_artifacts = {k: v for k, v in case["artifacts"].items() if k != "scoring/manifest.json"}
            if score.get("case_id") != case["case_id"] or score.get("artifacts") != expected_artifacts or score.get("input_sha256") != selection.get("input_sha256"):
                raise ValueError("scoring source ledger mismatch")
            if not events or len(events) > 100 or len(events) != case["event_count"] or len(gold) != len(events):
                raise ValueError("invalid projected counts")
            identifiers = [row["external_id"] for row in events]
            if len(set(identifiers)) != len(events) or identifiers != [row["external_id"] for row in gold]:
                raise ValueError("event/gold identity mismatch")
            if (case.get("is_attack") is not any(row.get("source_label") == "malicious" for row in gold)
                    or score.get("case_is_attack") is not case.get("is_attack")):
                raise ValueError("case attack decision contradicts observable gold")
            if case["is_attack"] is False and set(projected_labels) != {"benign"}:
                raise ValueError("a reliable normal case requires exclusively benign gold")
            for observation, truth in zip(events, gold, strict=True):
                label = truth["source_label"]
                decision = {"malicious": True, "benign": False, "malicious-related": None, "unscorable": None}[label]
                if truth.get("is_attack") is not decision or truth.get("attack_types") != []:
                    raise ValueError("original label semantics changed")
                expected_taxonomy = "out_of_taxonomy" if decision is True else "not_applicable" if decision is False else "unscorable"
                expected_applicability = {"attack_binary": decision is not None, "six_class": False,
                                          "techniques": False, "phases": False, "origin": False}
                if (truth.get("taxonomy_status") != expected_taxonomy
                        or canonical(truth.get("applicability")) != canonical(expected_applicability)):
                    raise ValueError("original label taxonomy or scoring applicability changed")
                if truth["provenance"] != {k: observation[k] for k in ("archive", "relative_log_path", "line_number", "raw_line_sha256", "event_fingerprint")}:
                    raise ValueError("gold provenance differs from observable input")
                if official_labels and labels.classify(observation["source"], observation["event_fingerprint"], host=observation["host"]) != label:
                    raise ValueError("projected gold contradicts official label membership")
            for event in events:
                if project_observations(event) != event:
                    raise ValueError("scoring field in agent projection")
                if event["host"] != case["host"] or event["dataset_id"] != "dedale-v2.1:" + case["case_id"]:
                    raise ValueError("case entity scope mismatch")
                if not clock(case["time_from"]) <= clock(event["observed_at"]) < clock(case["time_to"]):
                    raise ValueError("event outside historical half-open window")
            host = case["host"]
            previous.setdefault(host, []).append((clock(case["time_from"]), clock(case["time_to"])))
            if manifest["title"] != "Historical event review" or {p.name for p in (root / "agent").iterdir()} != {"manifest.json", "events.jsonl"}:
                raise ValueError("agent directory contains unapproved files/title")
            actual_attack_count += int(case["is_attack"])
            actual_normal_count += int(not case["is_attack"])
        except (KeyError, ValueError, TypeError, FileNotFoundError, OSError) as exc:
            gates["artifacts"] = False
            errors.append({"case_id": case.get("case_id"), "error": type(exc).__name__})
    for intervals in previous.values():
        intervals.sort()
        if any(left[1] > right[0] for left, right in pairwise(intervals)):
            gates["candidate_closure"] = False
    if (selection.get("counts", {}).get("attack") != actual_attack_count
            or selection.get("counts", {}).get("normal") != actual_normal_count):
        gates["candidate_closure"] = False
    gates["minimum_size"] = actual_attack_count >= 1 and actual_normal_count >= 1
    return gates, gold_by_case, errors


def audit_prepared(selection: dict, cases_root: Path, *, source_report=None, live_report=None,
                   cross_path_report=None, review_report=None, sources=None, data_root=None,
                   live_events_path=None, live_raw_events_path=None, resource_report=None,
                   freeze_date=None, prepared_root=None, splits=None,
                   scan_splits=None, label_policy=None, preparation_checkpoints=None) -> dict:
    if selection.get("protocol") == "dedale-neutral-v3":
        from .neutral_audit import audit_neutral_prepared
        return audit_neutral_prepared(
            selection, cases_root, sources=sources, data_root=data_root,
            live_report=live_report, cross_path_report=cross_path_report,
            review_report=review_report, live_events_path=live_events_path,
            live_raw_events_path=live_raw_events_path, resource_report=resource_report,
            freeze_date=freeze_date, prepared_root=prepared_root, splits=splits,
            scan_splits=scan_splits, label_policy=label_policy,
            preparation_checkpoints=preparation_checkpoints)

    # Reports are claims, not verification. Re-read the official source files;
    # a caller-supplied {verified: true} dictionary can never establish a freeze.
    source_report = None
    source_error = None
    if sources is not None and data_root is not None:
        try:
            source_report = verify_sources(Path(sources), Path(data_root))
        except (KeyError, ValueError, TypeError, OSError) as exc:
            source_error = type(exc).__name__
    labels = None
    if source_report is not None:
        try:
            labels = load_label_index(safe_file(Path(data_root), "system_logs_labels.zip"), exhaustive=True)
        except (KeyError, ValueError, TypeError, OSError):
            pass
    live_ok, filesystem_ok = _live_checks(live_report, events_path=live_events_path, raw_events_path=live_raw_events_path)
    gates = {
        "official_sources": source_report is not None,
        "official_labels": (source_report is not None and labels is not None and labels.official_verified
                            and selection.get("official_label_archive_verified") is True),
        "artifacts": bool(selection.get("cases")), "candidate_closure": selection.get("candidate_closure") is True,
        "minimum_size": all(type(selection.get("counts", {}).get(k)) is int and selection["counts"][k] >= 1 for k in ("attack", "normal")),
        "dates": False, "complete_label_join": False, "stage_coverage": False,
        "live_context": live_ok, "scoring_filesystem_isolation": filesystem_ok,
        "cross_path_rebuild": False, "resource_measurement": False,
    }
    errors = []
    if source_error:
        errors.append({"source_verification": source_error})
    scan = selection.get("scan", {})
    if gates["official_labels"]:
        expected_coverage = {source: {label: {"expected": 0, "matched": 0, "unmatched": 0}
                             for label in ("malicious", "malicious-related")} for source in sorted(EXHAUSTIVE_HOSTS)}
        expected_labels = Counter()
        for entry in labels.entries.values():
            expected_coverage[entry["source"]][entry["label"]]["expected"] += 1
            expected_coverage[entry["source"]][entry["label"]]["matched"] += 1
            expected_labels[entry["label"]] += 1
        gates["complete_label_join"] = (len(labels.entries) == 15783
            and type(scan.get("label_fingerprints_expected")) is int and scan["label_fingerprints_expected"] == len(labels.entries)
            and type(scan.get("label_fingerprints_matched")) is int and scan["label_fingerprints_matched"] == len(labels.entries)
            and type(scan.get("label_fingerprints_unmatched")) is int and scan["label_fingerprints_unmatched"] == 0
            and canonical(scan.get("label_coverage")) == canonical(expected_coverage)
            and canonical(selection.get("source_label_summary")) == canonical(labels.summary)
            and all(scan.get("original_labels", {}).get(label, 0) >= count for label, count in expected_labels.items()))
    if source_report:
        inputs = selection.get("input_sha256", {})
        if inputs.get("sources") != source_report["sources_sha256"] or any(inputs.get("archive:" + r["path"]) != r["sha256"] for r in source_report["archives"]):
            gates["official_sources"] = False
    frozen_on = freeze_date or datetime.now(timezone(timedelta(hours=8))).date()
    recent = datetime(frozen_on.year - 2, frozen_on.month, min(frozen_on.day, calendar.monthrange(frozen_on.year - 2, frozen_on.month)[1]), tzinfo=UTC)
    scan_metadata_ok = _scan_metadata_consistent(scan, data_root)
    gates["complete_label_join"] = gates["complete_label_join"] and gates["official_sources"] and scan_metadata_ok
    try:
        gates["dates"] = (scan_metadata_ok and utc(scan["observed_min"]) >= utc("2024-12-23T00:00:00Z")
                          and utc(scan["observed_min"]) >= recent
                          and utc(scan["observed_max"]) < utc("2025-01-20T00:00:00Z")
                          and scan.get("counts", {}).get("outside_period_rows", 0) == 0
                          and scan.get("full_archive_scan") is True and scan.get("invalid_rows", 0) == 0
                          and gates["official_sources"])
    except (ValueError, KeyError, TypeError):
        pass
    if isinstance(resource_report, dict):
        gates["resource_measurement"] = (resource_report.get("records", 0) > 0
             and resource_report.get("errors") == 0 and resource_report.get("elapsed_seconds", 0) > 0
             and resource_report.get("host_free_bytes", 0) > 0 and resource_report.get("docker_storage_checked") is True)
    cases, ledger = selection.get("cases", []), selection.get("candidate_ledger", [])
    ledger_ok, selected_rows = _ledger_consistent(selection, labels if gates["official_labels"] else None)
    gates["candidate_closure"] = gates["candidate_closure"] and ledger_ok
    selected_ledger_ids = [r.get("case_id") for r in ledger if r.get("reason", "").startswith("selected_")]
    if (len({r.get("case_id") for r in cases}) != len(cases) or sorted(selected_ledger_ids) != sorted(r.get("case_id") for r in cases)
            or selection.get("N_D") != len(cases) or selection.get("M_D") != len(cases)
            or selection.get("ablation_case_ids") != sorted(r["case_id"] for r in cases)):
        gates["candidate_closure"] = False
    artifact_gates, gold_by_case, artifact_errors = _audit_cases(
        selection, cases_root, selected_rows, labels=labels, official_labels=gates["official_labels"])
    gates["artifacts"] = artifact_gates["artifacts"]
    gates["candidate_closure"] = gates["candidate_closure"] and artifact_gates["candidate_closure"]
    gates["minimum_size"] = artifact_gates["minimum_size"]
    errors.extend(artifact_errors)
    gates["stage_coverage"] = _stage_review(review_report, selection, gold_by_case)
    gates["cross_path_rebuild"] = _cross_path_check(cross_path_report, selection, cases_root, source_report, data_root)
    return {"schema_version": 1, "accepted": all(gates.values()), "gates": gates,
            "failed_gates": [key for key, value in gates.items() if not value], "errors": errors,
            "N_D": selection.get("N_D", 0), "M_D": selection.get("M_D", 0),
            "source_verification": source_report}
