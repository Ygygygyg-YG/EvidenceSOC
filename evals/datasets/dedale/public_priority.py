"""Registered public-action sampling of verified neutral-v3 window geometry.

The candidate set is bounded to 100 public-ranked representatives and one
chronological anchor. Original labels account for every raw row and determine
validity only after sampling; they never enter a ranking key.
"""
from __future__ import annotations

import os
import re
import time
import uuid
from collections import Counter
from concurrent.futures import ProcessPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

from . import neutralize
from .build_manifests import project_observations
from .checkpoint import MAX_CHECKPOINT_BYTES, MemberCheckpoints, _read
from .common import canonical, read_json, safe_file, sha256, write_new
from .join_labels import EXHAUSTIVE_HOSTS, LabelIndex, load_label_index
from .neutralize import (
    _decoded_instant,
    _decoded_pass,
    _emit_case,
    digest,
    eligible_members,
    instant,
    load_member_index,
    publish_staging,
)
from .scan import (
    _check_output_root,
    _require_labels,
    _validate_policy,
    _validate_scan_splits,
)

PROTOCOL = "dedale-public-priority-v4"
_P0 = ("execute a remote command", "executed", "executing pipeline", "pipeline execution details",
       "process create (rule: processcreate)", "process.start")
_P1 = ("acquired-credentials", "authentication.start", "bound-socket", "changed-identity-of",
       "connected-to", "dns query (rule: dnsquery)", "network connection detected (rule: networkconnect)",
       "network.connection", "started-session", "was-authorized")
_PROJECTION = {
    "anchor": "minimum(observed_at,external_id) within the actual window",
    "applies_to": "all selected attack and normal windows identically",
    "dedup_key": "source+canonical_event_fingerprint",
    "duplicate_choice": "lowest(observed_at,external_id) for a fingerprint",
    "event_sort": ["observed_at", "external_id"], "fallback_priority": 2, "max_records": 100,
    "priority_0_event_types": list(_P0), "priority_1_event_types": list(_P1),
    "remaining": "lowest99(priority(event_type),observed_at,external_id) excluding anchor fingerprint",
    "unscorable_attack_rule": "Exclude registered attack window if selected observations retain no malicious original label; keep exclusion in candidate ledger",
    "uses_source_labels_case_kind_or_stage_for_ranking": False,
}
_SELECTED = {"selected_attack", "selected_normal"}
_POLICY_FIELDS = {
    "attack_rule", "benign_per_host_day", "bounds", "campaign_id", "case_identity", "dataset_id",
    "dedup_key", "event_projection", "event_sort", "max_records", "neutral_policy_sha256",
    "normal_control", "periods", "preparation_code_sha256", "preparation_selection_sha256",
    "preparation_splits_sha256", "preregistration_revision", "protocol", "recent_months",
    "schema_version", "seed", "status", "timestamp_representation", "timezone", "window_seconds",
}
_WORKER = None


def public_priority(event_type: str) -> int:
    action = event_type.strip().casefold()
    return 0 if action in _P0 else 1 if action in _P1 else 2


def implementation_hashes() -> dict[str, str]:
    return {**neutralize.implementation_hashes(), "public_priority.py": sha256(Path(__file__))}


def validate_priority_policy(policy: dict, neutral_policy: dict, scan_config: dict,
                             scan_sha256: str, neutral_sha256: str) -> None:
    neutralize.validate_neutral_policy(neutral_policy, scan_config, scan_sha256)
    expected_keys = _POLICY_FIELDS
    if not isinstance(policy, dict) or set(policy) != expected_keys:
        raise ValueError("priority policy fields differ from preregistration")
    changed = {"protocol", "attack_rule", "event_projection", "neutral_policy_sha256",
               "preregistration_revision", "preparation_selection_sha256"}
    for key in expected_keys - changed:
        if canonical(policy[key]) != canonical(neutral_policy[key]):
            raise ValueError("priority policy changes fixed neutral scope: " + key)
    if (policy["protocol"] != PROTOCOL or policy["neutral_policy_sha256"] != neutral_sha256
            or canonical(policy["event_projection"]) != canonical(_PROJECTION)
            or policy["attack_rule"] != "Reuse own neutral-v3 registered window geometry only; reread original raw observations for every selected window"):
        raise ValueError("priority policy event projection or lineage differs")
    revision = policy["preregistration_revision"]
    fields = {"accepted_cases", "date", "formal_model_runs", "observed_gap_report_sha256",
              "previous_policy_sha256", "reason", "registered_at", "revision"}
    if (not isinstance(revision, dict) or set(revision) != fields
            or any(type(revision.get(name)) is not int for name in ("accepted_cases", "formal_model_runs", "revision"))
            or revision["revision"] != 4 or revision["accepted_cases"] != 0 or revision["formal_model_runs"] != 0
            or revision["previous_policy_sha256"] != neutral_sha256
            or revision["date"] != "2026-10-17"
            or revision["observed_gap_report_sha256"] != "3e84b2c755326e93133d425b008ff37e27cd2afb9d41d046dd504b0cb8d27404"
            or revision["reason"] != "Actual earliest100 projection retained only execution and persistence; source-observable discovery/lateral/collection evidence was truncated. One public-action rule is applied identically to both classes without source labels/stages/model outputs in event ranking."
            or not isinstance(policy["preparation_selection_sha256"], str)
            or re.fullmatch(r"[0-9a-f]{64}", policy["preparation_selection_sha256"]) is None):
        raise ValueError("priority policy preregistration revision differs")
    try:
        registered = datetime.fromisoformat(revision["registered_at"])
        if registered.tzinfo is None or registered.date().isoformat() != revision["date"]:
            raise ValueError("invalid registration time")
    except (ValueError, TypeError) as exc:
        raise ValueError("priority policy registration timestamp differs") from exc


def window_inventory(selection: dict) -> list[dict]:
    """Fixed v3 selected ledger order, with no projected observation content."""
    keys = ("case_id", "source", "host", "time_from", "time_to", "candidate_kind")
    return [{key: row[key] for key in keys} for row in selection["candidate_ledger"] if row["reason"] in _SELECTED]


class PriorityCollector:
    """One anchor plus the best 100 distinct public-ranked representatives.

    A discarded representative cannot improve a later duplicate's rank. Thus a
    retained-only dictionary suffices even when input members arrive unordered.
    Duplicate accounting follows arrival against this bounded candidate set.
    """

    def __init__(self):
        self.best = {}
        self.anchor = None
        self.raw_count = 0
        self.labels = Counter()
        self.raw_priority_counts = [0, 0, 0]
        self.duplicate_retained_rows = 0
        self.worst = None

    @property
    def retained_size(self):
        return len(self.best) + int(self.anchor is not None and self.anchor[1] not in self.best)

    def add(self, decoded, label):
        priority = public_priority(decoded.event_type)
        self.raw_count += 1
        self.labels[label] += 1
        self.raw_priority_counts[priority] += 1
        order = (_decoded_instant(decoded.timestamp), decoded.external_id)
        key = decoded.source, decoded.fingerprint
        duplicate = key in self.best or self.anchor is not None and key == self.anchor[1]
        self.duplicate_retained_rows += int(duplicate)
        rank = priority, order
        is_anchor = self.anchor is None or order < self.anchor[0]
        previous = self.best.get(key)
        enter = (previous is not None and order < previous[0]
                 or previous is None and (len(self.best) < 100 or rank < self.worst))
        if not is_anchor and not enter:
            return
        record = (order, project_observations(decoded.project()), label)
        if is_anchor:
            self.anchor = order, key, record
        if enter:
            self.best[key] = record
            if len(self.best) > 100:
                worst_key = max(self.best, key=lambda item: (public_priority(self.best[item][1]["event_type"]), self.best[item][0]))
                del self.best[worst_key]
            self.worst = max((public_priority(row[1]["event_type"]), row[0]) for row in self.best.values())

    def records(self):
        if self.anchor is None:
            return []
        ranked = sorted((row for key, row in self.best.items() if key != self.anchor[1]),
                        key=lambda row: (public_priority(row[1]["event_type"]), row[0]))
        return sorted([self.anchor[2], *ranked[:99]], key=lambda row: row[0])


def scan_window(window: dict, *, data_root: Path, index: list[dict], labels) -> dict:
    source, host, start, end = (window[key] for key in ("source", "host", "time_from", "time_to"))
    start_order, end_order = instant(start), instant(end)
    collector = PriorityCollector()
    verified = isinstance(labels, LabelIndex) and labels.official_verified and labels.exhaustive
    label_clocks = {(row["source"], row["host"], row["timestamp"]) for row in labels.entries.values()} if verified else set()

    def account(decoded):
        if decoded.source != source or decoded.host != host or not start_order <= _decoded_instant(decoded.timestamp) < end_order:
            return
        if verified and (source, host, decoded.original_timestamp) not in label_clocks:
            label = "benign" if host in EXHAUSTIVE_HOSTS.get(source, ()) else "unscorable"
        else:
            label = labels.classify(source, decoded.fingerprint, host=host)
        collector.add(decoded, label)

    receipts = _decoded_pass(data_root, eligible_members(index, source, host, start, end), account)
    records = collector.records()
    if not records:
        raise ValueError("verified neutral window has no raw priority anchor")
    projected = Counter(row[2] for row in records)
    kind = window["candidate_kind"]
    reason = ("selected_attack" if projected["malicious"] else "no_retained_malicious") if kind == "attack" else "selected_normal"
    if kind != "attack" and set(collector.labels) != {"benign"}:
        raise ValueError("verified neutral normal window is no longer entirely benign")
    # Fixed raw accounting must agree with the verified old window, regardless
    # of how its projection changes.
    if ("raw_window_count" in window and (window["raw_window_count"] != collector.raw_count
            or canonical(window["source_labels"]) != canonical(dict(sorted(collector.labels.items()))))):
        raise ValueError("priority raw window counts differ from neutral preparation")
    return {**{key: value for key, value in window.items() if key != "case_id"},
            "reason": reason, "raw_window_count": collector.raw_count, "projected_count": len(records),
            "source_labels": dict(sorted(collector.labels.items())), "projected_labels": dict(sorted(projected.items())),
            "duplicate_retained_rows": collector.duplicate_retained_rows, "priority_pass": receipts,
            "sampling_counts": {"raw_priority_counts": collector.raw_priority_counts,
                "retained_priority_counts": [sum(public_priority(row[1]["event_type"]) == priority for row in records) for priority in range(3)],
                "anchor_external_id": collector.anchor[2][1]["external_id"],
                "anchor_fingerprint": collector.anchor[2][1]["event_fingerprint"]}, "records": records}


def _atomic_write(path: Path, value, maximum=MAX_CHECKPOINT_BYTES):
    payload = (canonical(value) + "\n").encode("utf-8")
    if len(payload) > maximum:
        raise ValueError("priority work serialized JSON exceeds bound")
    pending = safe_file(path.parent, path.name + ".pending")
    with pending.open("wb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    for attempt in range(6):
        try:
            pending.replace(path)
            return
        except PermissionError as exc:
            if getattr(exc, "winerror", None) not in {5, 32, 33} or attempt == 5:
                raise
            time.sleep(min(0.1 * 2**attempt, 1.0))


class PriorityWork(MemberCheckpoints):
    """Exclusive same-owner, implementation-bound per-window resume storage."""

    def __init__(self, root, *, owner_paths, binding, windows, index, labels):
        self._lease = None
        try:
            self.root = Path(root).absolute()
            for path in [*self.root.parents, self.root]:
                if path.is_symlink() or path.is_junction():
                    raise ValueError("priority work root traverses a filesystem link")
            roots = {name: str(Path(path).resolve()) for name, path in owner_paths.items()}
            if any(self.root.resolve().is_relative_to(Path(path)) or Path(path).is_relative_to(self.root.resolve()) for path in roots.values()):
                raise ValueError("priority work root overlaps input or output")
            self.root.mkdir(parents=True, exist_ok=True)
            self._acquire()
            self.binding, self.windows, self.index, self.labels = binding, windows, index, labels
            owner = {"schema_version": 1, "protocol": PROTOCOL, "binding": binding, **roots}
            names = {"owner.json", "owner.json.pending", "active.lock"}
            for key in windows:
                names.update({self._case_name(key), self._case_name(key) + ".pending"})
            if any(path.name not in names or path.is_symlink() or path.is_junction() or not path.is_file() for path in self.root.iterdir()):
                raise ValueError("priority work root contains unexpected files or links")
            owner_path = safe_file(self.root, "owner.json")
            if owner_path.exists():
                if canonical(_read(owner_path, 128 * 1024)) != canonical(owner):
                    raise ValueError("priority work owner or implementation binding changed")
            elif any(path.name != "active.lock" for path in self.root.iterdir()):
                raise ValueError("priority work owner missing")
            else:
                _atomic_write(owner_path, owner, 128 * 1024)
        except BaseException:
            self.close()
            raise

    @staticmethod
    def _case_name(key):
        return "case-" + digest(key) + ".json"

    def load_case(self, key):
        path = safe_file(self.root, self._case_name(key))
        if not path.exists():
            return None
        envelope = _read(path, MAX_CHECKPOINT_BYTES)
        if (not isinstance(envelope, dict) or set(envelope) != {"binding", "case_id", "result", "payload_sha256"}
                or envelope["binding"] != self.binding or envelope["case_id"] != key
                or envelope["payload_sha256"] != digest({name: value for name, value in envelope.items() if name != "payload_sha256"})):
            raise ValueError("priority work payload or binding changed")
        result = envelope["result"]
        self._validate_result(key, result)
        result["records"] = [((tuple(order[0]), order[1]), event, label) for order, event, label in result["records"]]
        return result

    def _validate_result(self, key, result):
        window = self.windows[key]
        changed = {"case_id", "reason", "projected_count", "projected_labels", "duplicate_retained_rows"}
        expected_fields = (set(window) - {"case_id"}) | {"priority_pass", "sampling_counts", "records"}
        if (not isinstance(result, dict) or set(result) != expected_fields
                or any(canonical(result.get(name)) != canonical(value) for name, value in window.items() if name not in changed)):
            raise ValueError("priority work fixed window geometry or source counts differ")
        expected = [{name: member[name] for name in ("archive", "member", "jsonl_md5", "raw_rows", "jsonl_md5_verified")}
                    for member in eligible_members(self.index, window["source"], window["host"], window["time_from"], window["time_to"])]
        if canonical(result["priority_pass"]) != canonical(expected):
            raise ValueError("priority work target member receipts differ")
        records = result["records"]
        if not isinstance(records, list) or not 1 <= len(records) <= 100 or result["projected_count"] != len(records):
            raise ValueError("priority work projected counts differ")
        orders, fingerprints, projected = [], set(), Counter()
        retained = [0, 0, 0]
        allowed = {(row["archive"], row["member"]): row for row in expected}
        for item in records:
            if not isinstance(item, (list, tuple)) or len(item) != 3:
                raise ValueError("priority work invalid observation tuple")
            order, event, label = item
            actual_order = [list(instant(event["observed_at"])), event["external_id"]]
            receipt = allowed.get((event.get("archive"), event.get("relative_log_path")))
            fingerprint = event.get("source"), event.get("event_fingerprint")
            if (canonical(order) != canonical(actual_order) or project_observations(event) != event
                    or event.get("source") != window["source"] or event.get("host") != window["host"]
                    or event.get("dataset_id") != "dedale-v2.1" or fingerprint in fingerprints
                    or not instant(window["time_from"]) <= instant(event["observed_at"]) < instant(window["time_to"])
                    or receipt is None or type(event.get("line_number")) is not int or not 1 <= event["line_number"] <= receipt["raw_rows"]
                    or event["external_id"] != "dedale:" + digest(["dedale-v2.1", event["archive"], event["relative_log_path"], event["line_number"]])
                    or re.fullmatch(r"[0-9a-f]{64}", event.get("event_fingerprint", "")) is None
                    or re.fullmatch(r"[0-9a-f]{64}", event.get("raw_line_sha256", "")) is None
                    or label != self.labels.classify(event["source"], event["event_fingerprint"], host=event["host"])):
                raise ValueError("priority work observation identity, labels, or provenance differs")
            fingerprints.add(fingerprint)
            orders.append((instant(event["observed_at"]), event["external_id"]))
            projected[label] += 1
            retained[public_priority(event["event_type"])] += 1
        counts = result["sampling_counts"]
        if (orders != sorted(orders) or len(set(orders)) != len(orders)
                or canonical(result["projected_labels"]) != canonical(dict(sorted(projected.items())))
                or not isinstance(counts, dict) or set(counts) != {"raw_priority_counts", "retained_priority_counts", "anchor_external_id", "anchor_fingerprint"}
                or counts["retained_priority_counts"] != retained
                or not isinstance(counts["raw_priority_counts"], list) or len(counts["raw_priority_counts"]) != 3
                or any(type(value) is not int or value < retained[i] for i, value in enumerate(counts["raw_priority_counts"]))
                or sum(counts["raw_priority_counts"]) != result["raw_window_count"]
                or counts["anchor_external_id"] != records[0][1]["external_id"]
                or counts["anchor_fingerprint"] != records[0][1]["event_fingerprint"]
                or type(result["duplicate_retained_rows"]) is not int
                or not 0 <= result["duplicate_retained_rows"] <= result["raw_window_count"] - len(records)):
            raise ValueError("priority work sampling counts or anchor differs")
        reason = ("selected_attack" if projected["malicious"] else "no_retained_malicious") if window["candidate_kind"] == "attack" else "selected_normal"
        if (result["reason"] != reason or any(count > result["source_labels"].get(label, 0) for label, count in projected.items())
                or reason == "selected_normal" and result["source_labels"] != {"benign": result["raw_window_count"]}):
            raise ValueError("priority work validity contradicts original labels")

    def save_case(self, key, result):
        self._validate_result(key, result)
        payload = {"binding": self.binding, "case_id": key, "result": result}
        _atomic_write(safe_file(self.root, self._case_name(key)), {**payload, "payload_sha256": digest(payload)})
        self.load_case(key)


def _initialize(label_archive, data_root, index):
    global _WORKER
    labels = load_label_index(Path(label_archive), exhaustive=True)
    _require_labels(labels)
    _WORKER = labels, Path(data_root), index


def _worker_window(window):
    labels, data_root, index = _WORKER
    return scan_window(window, data_root=data_root, index=index, labels=labels)


def _progress(output_root, stage, **values):
    path = output_root.with_name(output_root.name + "-progress.json")
    path.parent.mkdir(parents=True, exist_ok=True)
    _atomic_write(path, {"schema_version": 1, "protocol": PROTOCOL, "pid": os.getpid(), "stage": stage, **values}, 128 * 1024)


def _source_state(data_root):
    """Bind ongoing work to stable raw files without claiming a new full scan.

    Official complete archive verification remains inherited v2 lineage and a
    separate audit gate; every targeted member also executes MD5 and ZIP CRC.
    """
    result = {}
    for archive in sorted(neutralize.OFFICIAL):
        stat = safe_file(data_root, archive).stat()
        result[archive] = {"bytes": stat.st_size, "modified_ns": stat.st_mtime_ns,
                           "changed_ns": stat.st_ctime_ns, "file_id": stat.st_ino}
    return result


def emit_priority_cases(*, output_root, neutral, neutral_selection_sha256, results,
                        input_hashes, finalizer_code_sha256, policy):
    cases, ledger = [], []
    for original in neutral["candidate_ledger"]:
        if original["reason"] not in _SELECTED:
            ledger.append(original)
            continue
        result = results[original["case_id"]]
        row = {name: value for name, value in result.items() if name != "records"}
        if row["reason"] in _SELECTED:
            case = _emit_case(output_root, window=row, records=result["records"], input_hashes=input_hashes)
            cases.append(case)
            row["case_id"] = case["case_id"]
        ledger.append(row)
    if len({case["case_id"] for case in cases}) != len(cases):
        raise ValueError("priority case identity collision")
    cases.sort(key=lambda row: row["case_id"])
    selection = {**{name: neutral[name] for name in ("schema_version", "dataset_id", "split", "scan", "source_verification",
                    "source_label_summary", "official_label_archive_verified", "excluded_host_rows", "preparation_ledger", "stage_coverage")},
        "protocol": PROTOCOL, "status": "prepared_not_frozen", "N_D": len(cases), "M_D": len(cases),
        "counts": {"attack": sum(case["is_attack"] for case in cases), "normal": sum(not case["is_attack"] for case in cases),
            "unscorable": neutral["counts"]["unscorable"] + sum(row["reason"] == "no_retained_malicious" for row in ledger)},
        "cases": cases, "ablation_case_ids": [case["case_id"] for case in cases], "candidate_ledger": ledger,
        "candidate_closure": True, "input_sha256": input_hashes, "sampling": policy["event_projection"],
        "preparation": {**neutral["preparation"], "attack_reuse": "No v3 observation reuse; every selected attack and normal window is reprojected from original raw members"},
        "neutral_preparation": {"selection_sha256": neutral_selection_sha256, "input_sha256": neutral["input_sha256"],
            "window_inventory_sha256": digest(window_inventory(neutral)), "raw_scan_preparation": neutral["preparation"]},
        "finalizer_code_sha256": finalizer_code_sha256}
    write_new(output_root / "selection.json", selection)
    return selection


def finalize_dataset(*, sources: Path, scan_splits: Path, splits: Path, neutral_policy: Path, label_policy: Path,
                     data_root: Path, prepared_root: Path, preparation_checkpoints: Path, neutral_root: Path,
                     output_root: Path, workers: int = 4, work_root: Path | None = None) -> dict:
    from .audit import _audit_cases
    from .neutral_audit import (
        _observation_lineage,
        _policy_and_lineage,
        validate_candidate_ledger,
    )

    if type(workers) is not int or not 1 <= workers <= 8:
        raise ValueError("priority workers must be an integer from 1 to 8")
    data_root, prepared_root, neutral_root, output_root = map(Path, (data_root, prepared_root, neutral_root, output_root))
    _check_output_root(output_root, data_root)
    for root in (prepared_root, neutral_root, Path(preparation_checkpoints)):
        if output_root.resolve().is_relative_to(root.resolve()) or root.resolve().is_relative_to(output_root.resolve()):
            raise ValueError("priority output root overlaps preparation")
    _progress(output_root, "verifying_neutral_preparation")
    source_state = _source_state(data_root)
    config_paths = {"sources": sources, "scan_splits": scan_splits, "splits": splits,
                    "neutral_policy": neutral_policy, "label_policy": label_policy}
    config_hashes = {name: sha256(path) for name, path in config_paths.items()}
    scan_config, policy, neutral_config, label_config = map(read_json, (scan_splits, splits, neutral_policy, label_policy))
    _validate_scan_splits(scan_config)
    _validate_policy(label_config)
    validate_priority_policy(policy, neutral_config, scan_config, config_hashes["scan_splits"], config_hashes["neutral_policy"])
    prepared_path, neutral_path = (safe_file(root, "selection.json") for root in (prepared_root, neutral_root))
    prepared_hash, neutral_hash = sha256(prepared_path), sha256(neutral_path)
    preparation, neutral = read_json(prepared_path), read_json(neutral_path)
    if policy["preparation_selection_sha256"] != prepared_hash:
        raise ValueError("priority policy v2 preparation selection binding differs")
    _policy_and_lineage(neutral, preparation, sources=sources, splits=neutral_policy,
        scan_splits=scan_splits, label_policy=label_policy, prepared_root=prepared_root)
    verification = preparation["source_verification"]
    verified = verification.get("archives", [])
    if (verification.get("verified") is not True or len(verified) != 3
            or {row["path"] for row in verified} != set(neutralize.OFFICIAL)):
        raise ValueError("priority preparation official source verification differs")
    for row in verified:
        if (row["bytes"] != neutralize.OFFICIAL[row["path"]][1] or row["md5"] != neutralize.OFFICIAL[row["path"]][2]
                or row["crc_checked"] is not True or row["sha256"] != preparation["input_sha256"]["archive:" + row["path"]]
                or safe_file(data_root, row["path"]).stat().st_size != row["bytes"]):
            raise ValueError("priority preparation raw archive binding differs")
    source_config = read_json(sources)
    snapshot = source_config["metadata_snapshot"]
    if sha256(safe_file(data_root, snapshot["path"])) != snapshot["sha256"]:
        raise ValueError("priority preparation metadata snapshot differs")
    labels = load_label_index(safe_file(data_root, "system_logs_labels.zip"), exhaustive=True)
    _require_labels(labels)
    index, checkpoint_binding = load_member_index(data_root=data_root, prepared_root=prepared_root,
        preparation_checkpoints=preparation_checkpoints, selection=preparation, labels=labels, scan_splits=scan_config)
    if canonical(index) != canonical(neutral["preparation"]["member_index"]) or canonical(checkpoint_binding) != canonical(neutral["preparation"]["checkpoint_binding"]):
        raise ValueError("priority own v2 checkpoint member lineage differs from neutral preparation")
    selected = validate_candidate_ledger(neutral, preparation, index)
    gates, _, errors = _audit_cases(neutral, neutral_root, selected, labels=labels, official_labels=True, precise=True)
    if not gates["artifacts"] or not gates["candidate_closure"] or errors:
        raise ValueError("neutral preparation artifacts or ledger failed verification: " + str(errors[:3]))
    _observation_lineage(neutral, preparation, neutral_root, prepared_root, selected)
    hashes = implementation_hashes()
    inputs = {**neutral["input_sha256"], "splits": config_hashes["splits"],
              "neutral_policy": config_hashes["neutral_policy"], "neutral_selection": neutral_hash}
    windows = {row["case_id"]: row for row in neutral["candidate_ledger"] if row["reason"] in _SELECTED}
    binding = {"protocol": PROTOCOL, "input_sha256": inputs, "code_sha256": hashes,
               "member_index_sha256": digest(index), "window_inventory_sha256": digest(window_inventory(neutral)),
               "source_state": source_state}
    owner_paths = {"data_root": data_root, "prepared_root": prepared_root, "neutral_root": neutral_root,
                   "preparation_checkpoints": preparation_checkpoints, "output_root": output_root}
    cache = PriorityWork(work_root or output_root.with_name(output_root.name + "-priority-work"),
        owner_paths=owner_paths, binding=binding, windows=windows, index=index, labels=labels)
    pool, results = None, {}
    try:
        pending = []
        for key, row in windows.items():
            value = cache.load_case(key)
            if value is None:
                pending.append((key, row))
            else:
                results[key] = value
        _progress(output_root, "reprojecting_raw_windows", cases_completed=len(results), cases_expected=len(windows))
        if workers == 1:
            completed = ((key, scan_window(row, data_root=data_root, index=index, labels=labels)) for key, row in pending)
        else:
            pool = ProcessPoolExecutor(max_workers=workers, initializer=_initialize,
                initargs=(str(safe_file(data_root, "system_logs_labels.zip")), str(data_root), index))
            futures = {pool.submit(_worker_window, row): key for key, row in pending}
            completed = ((futures[future], future.result()) for future in as_completed(futures))
        for key, result in completed:
            cache.save_case(key, result)
            results[key] = result
            _progress(output_root, "reprojecting_raw_windows", cases_completed=len(results), cases_expected=len(windows))
        if (implementation_hashes() != hashes or sha256(prepared_path) != prepared_hash or sha256(neutral_path) != neutral_hash
                or _source_state(data_root) != source_state
                or any(sha256(path) != config_hashes[name] for name, path in config_paths.items())):
            raise ValueError("priority implementation, policy, or preparation changed during rebuild")
        staging = output_root.with_name(output_root.name + ".pending-" + uuid.uuid4().hex)
        _check_output_root(staging, data_root)
        selection = emit_priority_cases(output_root=staging, neutral=neutral, neutral_selection_sha256=neutral_hash,
            results=results, input_hashes=inputs, finalizer_code_sha256=hashes, policy=policy)
        if output_root.exists():
            output_root.rmdir()
        publish_staging(staging, output_root)
    finally:
        if pool is not None:
            pool.shutdown(wait=True, cancel_futures=True)
        cache.close()
    _progress(output_root, "prepared_not_frozen", cases_completed=len(windows), cases_expected=len(windows),
              N_D=selection["N_D"], M_D=selection["M_D"])
    return selection
