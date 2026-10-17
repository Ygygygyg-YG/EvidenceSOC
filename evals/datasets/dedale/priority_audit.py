"""Independent, fail-closed acceptance of public-priority v4 observations.

The finalizer's receipts and ranking implementation are never acceptance
evidence by themselves. This module independently ranks freshly decoded raw
events, and checks actual source, preparation, cross-root and review bytes.
"""
from __future__ import annotations

from bisect import insort
from collections import Counter, defaultdict
from pathlib import Path
from zipfile import BadZipFile

from .build_manifests import project_observations
from .common import canonical, read_json, safe_file, sha256
from .join_labels import load_label_index
from .neutral_audit import _require
from .neutralize import (
    _decoded_instant,
    _decoded_pass,
    _line_json,
    digest,
    eligible_members,
    instant,
    load_member_index,
    neutral_case_id,
)

PROTOCOL = "dedale-public-priority-v4"
POLICY_SHA256 = "a00cf4abf7b5a54a0d35dc2298d7ca5e5f4eb6ccd9cab2d757baeb23e2325f08"
OBSERVABLE_STAGES = frozenset({"execution", "persistence", "discovery", "lateral_movement", "collection"})
_PRIORITY_ZERO = frozenset({"execute a remote command", "executed", "executing pipeline",
    "pipeline execution details", "process create (rule: processcreate)", "process.start"})
_PRIORITY_ONE = frozenset({"acquired-credentials", "authentication.start", "bound-socket",
    "changed-identity-of", "connected-to", "dns query (rule: dnsquery)",
    "network connection detected (rule: networkconnect)", "network.connection", "started-session", "was-authorized"})
_PROJECTION = {
    "anchor": "minimum(observed_at,external_id) within the actual window",
    "applies_to": "all selected attack and normal windows identically",
    "dedup_key": "source+canonical_event_fingerprint",
    "duplicate_choice": "lowest(observed_at,external_id) for a fingerprint",
    "event_sort": ["observed_at", "external_id"], "fallback_priority": 2, "max_records": 100,
    "priority_0_event_types": sorted(_PRIORITY_ZERO), "priority_1_event_types": sorted(_PRIORITY_ONE),
    "remaining": "lowest99(priority(event_type),observed_at,external_id) excluding anchor fingerprint",
    "unscorable_attack_rule": "Exclude registered attack window if selected observations retain no malicious original label; keep exclusion in candidate ledger",
    "uses_source_labels_case_kind_or_stage_for_ranking": False,
}
_GEOMETRY = ("case_id", "source", "host", "time_from", "time_to", "candidate_kind")
_ACCOUNTING = ("raw_window_count", "projected_count", "source_labels", "projected_labels",
               "duplicate_retained_rows", "priority_pass", "sampling_counts")
_HIT_IDENTITY_FIELDS = ("case_id", "file", "rule", "external_id", "path_sha256", "location", "value_sha256", "line_number")


def _priority(value):
    normalized = value.strip().casefold()
    return 0 if normalized in _PRIORITY_ZERO else 1 if normalized in _PRIORITY_ONE else 2


def window_inventory(selection):
    """The fixed geometry is derived from the actual v3 ledger, in its order."""
    return [{key: row[key] for key in _GEOMETRY} for row in selection["candidate_ledger"]
            if row["reason"] in {"selected_attack", "selected_normal"}]


class _Replay:
    """Bounded independent order statistic; labels never enter either order."""

    def __init__(self, window, labels):
        self.window, self.labels = window, labels
        self.start, self.end = instant(window["time_from"]), instant(window["time_to"])
        self.raw = self.duplicates = 0
        self.raw_labels, self.raw_priorities = Counter(), [0, 0, 0]
        self.best, self.anchor = [], None

    def add(self, decoded):
        observed = _decoded_instant(decoded.timestamp)
        if (decoded.source != self.window["source"] or decoded.host != self.window["host"]
                or not self.start <= observed < self.end):
            return
        priority = _priority(decoded.event_type)
        self.raw += 1
        self.raw_priorities[priority] += 1
        fingerprint = decoded.fingerprint
        label = self.labels.classify(decoded.source, fingerprint, host=decoded.host)
        self.raw_labels[label] += 1
        order = observed, decoded.external_id
        rank = priority, *order
        identity = decoded.source, fingerprint
        duplicate = next((item for item in self.best if item[1] == identity), None)
        anchor_duplicate = self.anchor is not None and self.anchor[1] == identity
        self.duplicates += int(duplicate is not None or anchor_duplicate)
        item = rank, identity, decoded, label
        if self.anchor is None or order < self.anchor[0][1:]:
            self.anchor = item
        if duplicate is not None:
            if rank >= duplicate[0]:
                return
            self.best.remove(duplicate)
        elif len(self.best) == 100 and rank >= self.best[-1][0]:
            return
        insort(self.best, item, key=lambda value: value[0])
        if len(self.best) > 100:
            self.best.pop()

    def finish(self, receipts):
        _require(self.anchor is not None and self.raw > 0, "verified neutral window vanished in raw replay")
        chosen = [self.anchor, *(row for row in self.best if row[1] != self.anchor[1])][:100]
        chosen.sort(key=lambda row: row[0][1:])
        projected_labels, priorities = Counter(), [0, 0, 0]
        records = []
        for rank, _, decoded, label in chosen:
            projected_labels[label] += 1
            priorities[rank[0]] += 1
            records.append((rank[1:], project_observations(decoded.project()), label))
        anchor = self.anchor[2]
        return {"raw_window_count": self.raw, "projected_count": len(chosen),
                "source_labels": dict(sorted(self.raw_labels.items())),
                "projected_labels": dict(sorted(projected_labels.items())),
                "duplicate_retained_rows": self.duplicates, "priority_pass": receipts,
                "sampling_counts": {"raw_priority_counts": self.raw_priorities,
                                    "retained_priority_counts": priorities,
                                    "anchor_external_id": anchor.external_id,
                                    "anchor_fingerprint": anchor.fingerprint}, "records": records}


def replay_windows(windows, *, data_root, index, labels):
    """Exhaust each relevant raw member once, including rows outside windows.

    JSONL MD5, raw-row counts and ZIP CRC are enforced by the shared streaming
    transport. Selection, ranking, deduplication and counters are independent
    of public_priority.py and of every stored receipt.
    """
    states, members, window_members = {}, {}, {}
    for window in windows:
        identifier = window["case_id"]
        _require(identifier not in states, "duplicate neutral window identity")
        states[identifier] = _Replay(window, labels)
        selected = eligible_members(index, window["source"], window["host"], window["time_from"], window["time_to"])
        window_members[identifier] = [(row["archive"], row["member"]) for row in selected]
        for row in selected:
            key = row["archive"], row["member"]
            if key in members:
                _require(members[key][0] == row, "conflicting raw member inventory")
            members.setdefault(key, (row, []))[1].append(states[identifier])
    receipts = {}
    for key, (row, interested) in sorted(members.items()):
        by_host = defaultdict(list)
        for state in interested:
            by_host[(state.window["source"], state.window["host"])].append(state)

        def consume(decoded, by_host=by_host):
            for state in by_host.get((decoded.source, decoded.host), ()):
                state.add(decoded)

        receipts[key] = _decoded_pass(Path(data_root), [row], consume)[0]
    return {identifier: state.finish([receipts[key] for key in window_members[identifier]])
            for identifier, state in states.items()}


def validate_candidate_ledger(selection, neutral, index, replay):
    """Close every v4 candidate against actual v3 geometry and fresh raw replay."""
    ledger, previous = selection["candidate_ledger"], neutral["candidate_ledger"]
    _require(isinstance(ledger, list) and len(ledger) == len(previous), "v4 candidate universe differs from own neutral basis")
    inventory = window_inventory(neutral)
    _require(set(replay) == {row["case_id"] for row in inventory}, "raw replay does not close over all neutral windows")
    selected, excluded = {}, 0
    for actual, old in zip(ledger, previous, strict=True):
        _require(isinstance(actual, dict), "invalid v4 candidate row")
        if old["reason"] not in {"selected_attack", "selected_normal"}:
            _require(canonical(actual) == canonical(old), "unselected neutral candidate changed")
            continue
        expected = {**old, **{key: replay[old["case_id"]][key] for key in _ACCOUNTING}}
        _require(expected["raw_window_count"] == old["raw_window_count"]
                 and expected["source_labels"] == old["source_labels"], "raw replay contradicts verified neutral counts")
        if old["candidate_kind"] == "attack" and not expected["projected_labels"].get("malicious", 0):
            expected["reason"] = "no_retained_malicious"
            expected.pop("case_id")
            excluded += 1
        elif old["candidate_kind"] == "control":
            _require(set(expected["source_labels"]) == {"benign"}
                     and set(expected["projected_labels"]) == {"benign"}, "neutral control raw labels changed")
        _require(canonical(actual) == canonical(expected), "priority candidate, receipts, anchor or ranking counters differ from raw replay")
        if "case_id" in expected:
            identifier = expected["case_id"]
            _require(identifier == neutral_case_id(expected["source"], expected["host"], expected["time_from"])
                     and identifier not in selected, "priority identity depends on class or collides")
            selected[identifier] = actual
    _require(type(selection["counts"].get("unscorable")) is int
             and selection["counts"]["unscorable"] == neutral["counts"]["unscorable"] + excluded,
             "v4 excluded-window accounting differs")
    return selected


def _policy_and_lineage(selection, neutral, *, splits, neutral_policy, scan_splits, neutral_root):
    from .checkpoint import code_hashes
    from .public_priority import implementation_hashes as priority_hashes

    policy, base, scan = (read_json(path) for path in (splits, neutral_policy, scan_splits))
    _require(sha256(splits) == POLICY_SHA256, "v4 policy differs from fixed preregistered bytes")
    _require(policy.get("protocol") == PROTOCOL and policy.get("status") == "preregistered_not_frozen"
             and type(policy.get("schema_version")) is int and policy["schema_version"] == 1
             and canonical(policy.get("event_projection")) == canonical(_PROJECTION), "public priority rule changed")
    for name in ("dataset_id", "window_seconds", "max_records", "seed", "benign_per_host_day", "periods", "bounds",
                 "timezone", "event_sort", "dedup_key", "campaign_id", "recent_months", "normal_control",
                 "case_identity", "timestamp_representation", "preparation_splits_sha256"):
        _require(canonical(policy.get(name)) == canonical(base.get(name)), "v4 changes fixed neutral scope: " + name)
    _require(policy.get("neutral_policy_sha256") == sha256(neutral_policy)
             and policy.get("preparation_splits_sha256") == sha256(scan_splits)
             and policy.get("preparation_selection_sha256") == neutral["preparation"]["selection_sha256"]
             and policy.get("preparation_code_sha256") == code_hashes(), "v4 code or configuration lineage differs")
    revision = policy["preregistration_revision"]
    _require(type(revision.get("revision")) is int and revision["revision"] == 4
             and type(revision.get("formal_model_runs")) is int and revision["formal_model_runs"] == 0
             and type(revision.get("accepted_cases")) is int and revision["accepted_cases"] == 0
             and revision.get("previous_policy_sha256") == sha256(neutral_policy), "invalid v4 preregistration lineage")
    _require(selection.get("protocol") == PROTOCOL and selection.get("status") == "prepared_not_frozen"
             and selection.get("dataset_id") == "dedale-v2.1" and selection.get("split") == "test"
             and type(selection.get("schema_version")) is int and selection["schema_version"] == 1,
             "invalid v4 preparation protocol or status")
    neutral_hash = sha256(safe_file(neutral_root, "selection.json"))
    inputs = {**neutral["input_sha256"], "splits": sha256(splits),
              "neutral_policy": sha256(neutral_policy), "neutral_selection": neutral_hash}
    _require(canonical(selection["input_sha256"]) == canonical(inputs), "v4 inputs differ from actual own neutral basis")
    expected = {"selection_sha256": neutral_hash, "input_sha256": neutral["input_sha256"],
                "window_inventory_sha256": digest(window_inventory(neutral)), "raw_scan_preparation": neutral["preparation"]}
    _require(canonical(selection.get("neutral_preparation")) == canonical(expected), "neutral window or preparation binding differs")
    for name in ("scan", "source_verification", "source_label_summary", "official_label_archive_verified", "excluded_host_rows",
                 "preparation_ledger"):
        _require(canonical(selection.get(name)) == canonical(neutral.get(name)), "transported neutral full-scan lineage differs: " + name)
    raw_preparation = {**neutral["preparation"], "attack_reuse": "No v3 observation reuse; every selected attack and normal window is reprojected from original raw members"}
    _require(canonical(selection.get("preparation")) == canonical(raw_preparation), "v4 raw preparation declaration differs")
    _require(canonical(selection.get("sampling")) == canonical(_PROJECTION), "v4 sampling declaration differs")
    _require(selection.get("finalizer_code_sha256") == priority_hashes(), "v4 finalizer code changed")
    return scan


def priority_stage_review(report, selection, gold):
    """Known source-observable stages cannot be signed as all unobservable."""
    from .audit import _stage_review

    try:
        if not _stage_review(report, selection, gold):
            return False
        for row in report["stages"]:
            if row["observable"] is not (row["stage"] in OBSERVABLE_STAGES):
                return False
            if row["observable"]:
                for evidence in row["evidence"]:
                    if not any(isinstance(evidence.get(key), str) and evidence[key].strip()
                               for key in ("reason", "action_rationale", "evidence_rationale")):
                        return False
        return True
    except (KeyError, ValueError, TypeError, AttributeError):
        return False


def _stage_source_bindings(report, selection, data_root):
    from scripts.dedale_task12_stage_inventory import _review_sources

    context = report["source_context"]
    root = Path(context["scoring_source_root"])
    _require(root.is_absolute(), "stage review source root must be absolute")
    verified, _ = _review_sources(root)
    expected = [{"path": row["path"], "sha256": row["sha256"]} for row in verified["bindings"]]
    _require(canonical(sorted(context["files"], key=canonical)) == canonical(sorted(expected, key=canonical)),
             "stage review source inventory differs from pinned official bytes")
    _require(context["official_label_sha256"] == selection["input_sha256"]["archive:system_logs_labels.zip"]
             == sha256(safe_file(data_root, "system_logs_labels.zip")), "stage review label archive binding differs")
    return {safe_file(root, row["path"]): row["sha256"] for row in expected}


def _leak_review(report, selection, cases_root):
    from scripts.dedale_task12_leak_inventory import build_inventory

    _require(isinstance(report, dict) and report.get("complete") is True
             and isinstance(report.get("reviewer"), str) and bool(report["reviewer"].strip())
             and isinstance(report.get("reason"), str) and bool(report["reason"].strip()), "independent leak review missing")
    packet_ref = report["inventory"]
    packet_path = Path(packet_ref["path"])
    _require(packet_path.is_absolute() and sha256(safe_file(packet_path.parent, packet_path.name)) == packet_ref["sha256"],
             "leak inventory bytes changed")
    packet, actual = read_json(packet_path), build_inventory(cases_root=cases_root)
    _require(canonical(packet) == canonical(actual), "leak inventory differs from freshly inspected selected bytes")
    _require(report.get("selection_sha256") == actual["selection_sha256"]
             and report.get("selection_file_sha256") == actual["selection_file_sha256"]
             and canonical(report.get("public_file_bindings")) == canonical(actual["public_file_bindings"]),
             "leak review is not bound to actual selected public bytes")
    count = actual["statistics"]["candidate_hits_total"]
    _require(type(report.get("candidate_hits_total")) is int and report["candidate_hits_total"] == count
             and type(report.get("reviewed_candidate_hits_total")) is int and report["reviewed_candidate_hits_total"] == count
             and report.get("publisher_answer_annotations_present") is False
             and report.get("factual_content_preserved") is True
             and report.get("all_selected_public_text_reviewed") is True, "leak review is incomplete or reports answer annotations")
    _validate_leak_dispositions(report, actual)
    _require(sha256(packet_path) == packet_ref["sha256"], "leak inventory changed while reading")
    return {packet_path: packet_ref["sha256"]}


def _validate_leak_dispositions(report, actual):
    """Require one reviewed, evidence-bound disposition for every full hit group."""
    groups, dispositions = actual["candidate_groups"], report.get("dispositions")
    _require(isinstance(groups, list) and isinstance(dispositions, list) and len(dispositions) == len(groups),
             "leak dispositions do not cover the complete candidate group inventory")
    expected = {}
    for group in groups:
        coverage = {key: group[key] for key in ("case_id", "file", "rule", "count", "sha256")}
        key = group["case_id"], group["file"], group["rule"]
        _require(key not in expected and type(group["count"]) is int and group["count"] > 0,
                 "invalid actual leak candidate group")
        example = {key: group["example_hit"][key] for key in _HIT_IDENTITY_FIELDS if key in group["example_hit"]}
        expected[key] = coverage, example
    _require(sum(group["count"] for group in groups) == actual["statistics"]["candidate_hits_total"],
             "leak groups do not close over every actual hit")
    seen = set()
    for disposition in dispositions:
        _require(isinstance(disposition, dict) and isinstance(disposition.get("coverage"), dict)
                 and any(isinstance(disposition.get(key), str) and disposition[key].strip()
                         for key in ("reason", "rationale")), "leak disposition lacks reviewed coverage or rationale")
        coverage = disposition["coverage"]
        key = coverage.get("case_id"), coverage.get("file"), coverage.get("rule")
        _require(key in expected and key not in seen and canonical(coverage) == canonical(expected[key][0]),
                 "leak disposition group count, digest or identity differs from actual full scan")
        evidence = disposition.get("evidence")
        _require(isinstance(evidence, list) and bool(evidence)
                 and all(isinstance(reference, dict) and canonical(reference) == canonical(expected[key][1])
                         for reference in evidence), "leak disposition evidence is not an actual group example identity")
        seen.add(key)
    _require(seen == set(expected), "leak dispositions omit actual candidate groups")


def _checked_root(root):
    """Check the supplied spelling before resolve can hide a filesystem link."""
    root = Path(root).absolute()
    safe_file(root, "selection.json")
    _require(root.is_dir(), "independent root is not an actual directory")
    return root


def _checked_file(path):
    path = Path(path).absolute()
    path = safe_file(path.parent, path.name)
    _require(path.is_file(), "independent input is not an actual file")
    status = path.stat(follow_symlinks=False)
    _require(status.st_nlink == 1, "independent input has a hardlink alias")
    return path, status


def _independent_inventory(root):
    from scripts.dedale_task12_crosspath_check import _inventory

    root = _checked_root(root)
    inventory = _inventory(root)
    for relative in inventory:
        _checked_file(safe_file(root, relative))
    return inventory


def _verify_bound_files(files):
    """Recheck bytes, link counts, original paths and identities at acceptance."""
    identities = {}
    for original, expected in files.items():
        path, before = _checked_file(original)
        identity = before.st_dev, before.st_ino
        previous = identities.get(identity) if before.st_ino else None
        _require(previous is None or previous == path or not previous.samefile(path),
                 "independent input paths alias the same file")
        if before.st_ino:
            identities[identity] = path
        _require(sha256(path) == expected, "source, policy, review, code or prepared artifacts changed during audit")
        _, after = _checked_file(path)
        _require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                 == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
                 "independent input changed while rechecking file identity")


def _extend_bound_files(files, additions):
    """Extend commitments atomically without replacing an earlier digest."""
    expected_by_path = {}
    for original, expected in [*files.items(), *additions.items()]:
        path = Path(original).absolute()
        _require(path not in expected_by_path or expected_by_path[path] == expected,
                 "previously bound input changed during audit")
        expected_by_path[path] = expected
    for path, expected in expected_by_path.items():
        files.setdefault(path, expected)


def _cross_path_check(report, selection, cases_root, source_report, data_root, prepared_root, neutral_root,
                      *, sources, splits, label_policy, scan_splits, neutral_policy,
                      preparation_checkpoints, labels, index, binding, bound_files=None):
    from scripts.dedale_task12_crosspath_check import compare_artifacts

    from .audit import _cross_path_check as basic_cross
    from .public_priority import implementation_hashes as priority_hashes

    try:
        _require(isinstance(report, dict) and report.get("all_equal") is True and report.get("errors") == [],
                 "cross-root report is not complete")
        _require(report.get("protocol") == PROTOCOL and report.get("code_sha256") == priority_hashes(), "cross-root protocol or code binding differs")
        own = {name: _checked_root(root) for name, root in (("cases_root", cases_root), ("data_root", data_root),
               ("prepared_root", prepared_root), ("neutral_root", neutral_root), ("preparation_checkpoints", preparation_checkpoints))}
        other = {name: _checked_root(report["rebuild_" + name]) for name in own}
        for name, root in own.items():
            _require(_checked_root(report["original_" + name]).resolve() == root.resolve(), "cross-root own path mismatch: " + name)
        _disjoint([root.resolve() for root in [*own.values(), *other.values()]])
        pairs = [(own[name], other[name]) for name in ("cases_root", "prepared_root", "neutral_root")]
        own_checkpoints, second_checkpoints = own["preparation_checkpoints"], other["preparation_checkpoints"]
        local_bound = {}
        for root in (own["data_root"], other["data_root"]):
            metadata = read_json(_checked_file(sources)[0])["metadata_snapshot"]["path"]
            local_bound[_checked_file(safe_file(root, metadata))[0]] = source_report["metadata_sha256"]
            for row in source_report["archives"]:
                local_bound[_checked_file(safe_file(root, row["path"]))[0]] = row["sha256"]
        _require(set(report["preparation_input_files"]) == {"scan_splits", "neutral_policy"}, "cross-root preparation config inventory differs")
        configs = {**report["input_files"], **report["preparation_input_files"]}
        for name, original in {"sources": sources, "splits": splits, "label_policy": label_policy,
                               "scan_splits": scan_splits, "neutral_policy": neutral_policy}.items():
            row = configs[name]
            actual, second = _checked_file(row["original_path"])[0], _checked_file(row["rebuild_path"])[0]
            _require(actual.resolve() == _checked_file(original)[0].resolve() and not actual.samefile(second)
                     and row["sha256"] == sha256(actual) == sha256(second)
                     and second.resolve().is_relative_to(other["data_root"].resolve()), "cross-root actual configuration mismatch: " + name)
        _require(basic_cross(report, selection, cases_root, source_report, data_root), "priority cross-root output or official source verification failed")
        for first, second in pairs:
            _independent_inventory(first)
            _independent_inventory(second)
            old = read_json(safe_file(first, "selection.json"))
            _require(compare_artifacts(first, second, old)["all_equal"] is True, "actual independent preparation or final artifacts differ")
        actual_checkpoints = {"original": _independent_inventory(own_checkpoints), "rebuild": _independent_inventory(second_checkpoints)}
        for name, actual in actual_checkpoints.items():
            claimed = report["checkpoint_verification"][name]
            _require(type(claimed.get("members_verified")) is int and claimed["members_verified"] == 1344
                     and type(claimed.get("checkpoint_files_verified")) is int and claimed["checkpoint_files_verified"] == 1344
                     and canonical(claimed["files_sha256"]) == canonical(actual), "cross-root actual checkpoint inventory differs")
        second_index, second_binding = load_member_index(
            data_root=Path(report["rebuild_data_root"]), prepared_root=pairs[1][1],
            preparation_checkpoints=second_checkpoints, selection=read_json(safe_file(pairs[1][1], "selection.json")),
            labels=labels, scan_splits=read_json(configs["scan_splits"]["rebuild_path"]))
        _require(len(index) == len(second_index) == 1344 and canonical(index) == canonical(second_index)
                 and canonical(binding) == canonical(report["checkpoint_verification"]["original"]["binding"])
                 and canonical(second_binding) == canonical(report["checkpoint_verification"]["rebuild"]["binding"])
                 and canonical(binding) == canonical(second_binding), "cross-root actual checkpoint semantics differ")
        for name, root in (("original", own_checkpoints), ("rebuild", second_checkpoints)):
            _require(_independent_inventory(root) == actual_checkpoints[name], "cross-root checkpoint bytes changed during validation")
        _extend_bound_files(local_bound, _bound_files([root for pair in pairs for root in pair],
                            [row[which] for row in configs.values() for which in ("original_path", "rebuild_path")]))
        for name, root in (("original", own_checkpoints), ("rebuild", second_checkpoints)):
            _extend_bound_files(local_bound, {safe_file(root, relative): expected for relative, expected in actual_checkpoints[name].items()})
        _verify_bound_files(local_bound)
        if bound_files is not None:
            _extend_bound_files(bound_files, local_bound)
        return True
    except (KeyError, ValueError, TypeError, OSError, AttributeError):
        return False


def _disjoint(roots):
    for i, root in enumerate(roots):
        for other in roots[i + 1:]:
            _require(root != other and not root.is_relative_to(other) and not other.is_relative_to(root),
                     "raw, preparation and case roots must be independent")


def _bound_files(roots, configs):
    files = {_checked_file(path)[0]: sha256(path) for path in configs}
    for root in roots:
        root = _checked_root(root)
        files.update({safe_file(root, relative): expected for relative, expected in _independent_inventory(root).items()})
        path = safe_file(root, "selection.json")
        files[path] = sha256(path)
        for case in read_json(path)["cases"]:
            for relative, expected in case["artifacts"].items():
                artifact = safe_file(root, "test/" + case["case_id"] + "/" + relative)
                _require(sha256(artifact) == expected, "actual prepared artifact hash differs before audit")
                files[artifact] = expected
    return files


def audit_priority_prepared(selection, cases_root, *, sources=None, data_root=None, prepared_root=None,
                            preparation_checkpoints=None, neutral_root=None, neutral_policy=None,
                            splits=None, scan_splits=None, label_policy=None, live_report=None,
                            stage_review=None, cross_path_report=None, review_report=None, leak_review=None,
                            resource_report=None, live_events_path=None, live_raw_events_path=None, freeze_date=None):
    from .audit import _audit_cases
    from .neutral_audit import audit_neutral_prepared
    from .public_priority import implementation_hashes as priority_hashes

    gates = dict.fromkeys(("official_sources", "official_labels", "artifacts", "candidate_closure", "minimum_size",
        "dates", "complete_label_join", "stage_coverage", "live_context", "scoring_filesystem_isolation",
        "cross_path_rebuild", "resource_measurement", "preparation_lineage", "neutral_policy", "priority_policy",
        "targeted_member_receipts", "raw_priority_replay", "finalizer_code", "annotation_leak_review", "unchanged_inputs"), False)
    errors, source_report, gold, snapshots = [], None, {}, {}
    stage = stage_review if stage_review is not None else review_report
    try:
        _require(all(value is not None for value in (sources, data_root, prepared_root, preparation_checkpoints,
                 neutral_root, neutral_policy, splits, scan_splits, label_policy)), "required v4 lineage paths missing")
        cases_root, prepared_root, neutral_root, data_root = map(Path, (cases_root, prepared_root, neutral_root, data_root))
        _disjoint([_checked_root(path).resolve() for path in (cases_root, prepared_root, neutral_root, data_root, preparation_checkpoints)])
        _require(canonical(read_json(safe_file(cases_root, "selection.json"))) == canonical(selection), "v4 selection differs from actual file")
        code_before = priority_hashes()
        audit_code_before = {Path(__file__): sha256(Path(__file__)),
                             Path(__file__).with_name("audit.py"): sha256(Path(__file__).with_name("audit.py")),
                             Path(__file__).with_name("neutral_audit.py"): sha256(Path(__file__).with_name("neutral_audit.py"))}
        for name in ("dedale_task12_crosspath_check.py", "dedale_task12_stage_inventory.py", "dedale_task12_leak_inventory.py"):
            code = Path(__file__).resolve().parents[3] / "scripts" / name
            audit_code_before[code] = sha256(code)
        snapshots = _bound_files([cases_root, prepared_root, neutral_root], [sources, splits, scan_splits, neutral_policy, label_policy])
        _extend_bound_files(snapshots, audit_code_before)
        source_config = read_json(_checked_file(sources)[0])
        for row in source_config["archives"]:
            _checked_file(safe_file(data_root, row["path"]))
        _checked_file(safe_file(data_root, source_config["metadata_snapshot"]["path"]))
        neutral = read_json(safe_file(neutral_root, "selection.json"))
        _require(neutral.get("protocol") == "dedale-neutral-v3", "v4 needs its own actual neutral v3 preparation")
        scan = _policy_and_lineage(selection, neutral, splits=splits, neutral_policy=neutral_policy,
                                   scan_splits=scan_splits, neutral_root=neutral_root)
        gates["priority_policy"] = gates["finalizer_code"] = True
        base = audit_neutral_prepared(neutral, neutral_root, sources=sources, data_root=data_root,
            prepared_root=prepared_root, preparation_checkpoints=preparation_checkpoints, splits=neutral_policy,
            scan_splits=scan_splits, label_policy=label_policy, live_report=live_report,
            live_events_path=live_events_path, live_raw_events_path=live_raw_events_path,
            resource_report=resource_report, freeze_date=freeze_date)
        source_report = base["source_verification"]
        inherited = ("official_sources", "official_labels", "dates", "complete_label_join", "live_context",
                     "scoring_filesystem_isolation", "resource_measurement", "neutral_policy")
        for name in inherited:
            gates[name] = base["gates"][name]
        required = {name: passed for name, passed in base["gates"].items() if name not in {"stage_coverage", "cross_path_rebuild"}}
        _require(all(required.values()), "own neutral v3 preparation failed acceptance: " + ",".join(name for name, passed in required.items() if not passed))
        _require(canonical(selection["source_verification"]) == canonical(source_report), "v4 source verification differs from fresh official bytes")
        metadata = read_json(sources)["metadata_snapshot"]
        _extend_bound_files(snapshots, {
            safe_file(data_root, metadata["path"]): source_report["metadata_sha256"],
            **{safe_file(data_root, row["path"]): row["sha256"] for row in source_report["archives"]},
        })
        labels = load_label_index(safe_file(data_root, "system_logs_labels.zip"), exhaustive=True)
        _require(labels.official_verified is True and labels.exhaustive is True, "v4 official labels lack exhaustive verification")
        preparation = read_json(safe_file(prepared_root, "selection.json"))
        index, binding = load_member_index(data_root=data_root, prepared_root=prepared_root,
            preparation_checkpoints=Path(preparation_checkpoints), selection=preparation, labels=labels, scan_splits=scan)
        _require(canonical(index) == canonical(neutral["preparation"]["member_index"])
                 and canonical(binding) == canonical(neutral["preparation"]["checkpoint_binding"]), "actual own checkpoints differ from neutral lineage")
        gates["preparation_lineage"] = True
        replay = replay_windows(window_inventory(neutral), data_root=data_root, index=index, labels=labels)
        selected = validate_candidate_ledger(selection, neutral, index, replay)
        gates["targeted_member_receipts"] = gates["raw_priority_replay"] = True
        artifact_gates, gold, artifact_errors = _audit_cases(selection, cases_root, selected,
            labels=labels, official_labels=True, precise=True)
        gates.update(artifact_gates)
        gates["candidate_closure"] = gates["candidate_closure"] and selection.get("candidate_closure") is True
        errors.extend(artifact_errors)
        for identifier in selected:
            actual = _line_json(safe_file(cases_root, "test/" + identifier + "/agent/events.jsonl"))
            expected = [{**record, "dataset_id": "dedale-v2.1:" + identifier} for _, record, _ in replay[identifier]["records"]]
            _require(canonical(actual) == canonical(expected), "actual selected observations differ from independent raw public ranking")
        gates["cross_path_rebuild"] = _cross_path_check(cross_path_report, selection, cases_root, source_report,
            data_root, prepared_root, neutral_root, sources=sources, splits=splits, label_policy=label_policy,
            scan_splits=scan_splits, neutral_policy=neutral_policy, preparation_checkpoints=preparation_checkpoints,
            labels=labels, index=index, binding=binding, bound_files=snapshots)
        if priority_stage_review(stage, selection, gold):
            _require(stage.get("selection_file_sha256") == sha256(safe_file(cases_root, "selection.json")), "stage review selection byte binding differs")
            _extend_bound_files(snapshots, _stage_source_bindings(stage, selection, data_root))
            gates["stage_coverage"] = True
        _extend_bound_files(snapshots, _leak_review(leak_review, selection, cases_root))
        gates["annotation_leak_review"] = True
        _require(priority_hashes() == code_before, "v4 builder code changed during audit")
        _verify_bound_files(snapshots)
        gates["unchanged_inputs"] = True
    except (KeyError, ValueError, TypeError, OSError, AttributeError, OverflowError, BadZipFile) as exc:
        errors.append({"priority_acceptance": type(exc).__name__, "detail": str(exc)})
        gates["candidate_closure"] = False
    return {"schema_version": 1, "protocol": PROTOCOL, "accepted": all(gates.values()), "gates": gates,
            "failed_gates": [name for name, passed in gates.items() if not passed], "errors": errors,
            "N_D": selection.get("N_D", 0), "M_D": selection.get("M_D", 0),
            "source_verification": source_report, "model_invocations": 0}
