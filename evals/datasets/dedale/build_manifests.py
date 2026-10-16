"""Deterministic, host-anchored DEDALE cases; preparation never implies freeze."""
from __future__ import annotations

import argparse
import hashlib
from bisect import bisect_right, insort
from collections import Counter, defaultdict
from datetime import UTC, datetime, timedelta
from pathlib import Path

from .common import canonical, sha256, write_new
from .join_labels import EXHAUSTIVE_HOSTS, LabelIndex
from .parse import DecodedEvent

# The scoring fields and arbitrary raw JSON never enter this projection.
AGENT_FIELDS = frozenset({
    "source", "event_type", "severity", "external_id", "dataset_id", "archive",
    "relative_log_path", "line_number", "host", "timestamp", "observed_at",
    "@timestamp", "original_timestamp", "raw_line_sha256", "event_fingerprint",
    "source_event_id", "process", "parent", "command_line", "user", "username",
    "network", "winlog", "source_ip", "destination_ip", "source_port", "destination_port",
    "message", "original_severity",
    "projection_truncated", "projection_truncated_fields",
})
NESTED_FIELDS = {
    "process": frozenset({"pid", "ppid", "name", "executable", "command_line", "title", "working_directory", "entity_id", "args_count", "args"}),
    "parent": frozenset({"pid", "ppid", "name", "executable", "command_line", "title", "working_directory", "entity_id", "args_count", "args"}),
    "user": frozenset({"id", "name", "domain"}),
    "network": frozenset({"transport", "protocol", "direction", "type", "bytes", "packets", "community_id", "application"}),
    "winlog": frozenset({"event_id", "record_id", "channel", "provider_name", "computer_name", "task", "opcode", "api"}),
}


def project_observations(event: dict) -> dict:
    result = {}
    for key, value in event.items():
        if key not in AGENT_FIELDS:
            continue
        if isinstance(value, dict):
            if key not in NESTED_FIELDS:
                continue
            result[key] = {
                field: item for field, item in value.items()
                if field in NESTED_FIELDS[key] and (
                    isinstance(item, (str, int, float, bool))
                    or (field == "args" and isinstance(item, list) and all(isinstance(part, str) for part in item))
                )
            }
        elif key == "projection_truncated_fields" and isinstance(value, list) and all(isinstance(item, str) for item in value):
            result[key] = list(value)
        elif isinstance(value, (str, int, float, bool)) or value is None:
            result[key] = value
    return result


def utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timestamp must have an explicit timezone")
    return parsed.astimezone(UTC)


def stamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def window_start(value: str) -> str:
    timestamp = utc(value)
    seconds = int(timestamp.timestamp())
    return stamp(datetime.fromtimestamp(seconds - seconds % 1800, UTC))


def validate_splits(config: dict) -> tuple[datetime, datetime, datetime]:
    if config.get("dataset_id") != "dedale-v2.1" or config.get("window_seconds") != 1800:
        raise ValueError("DEDALE uses fixed 1800-second windows")
    if type(config.get("max_records")) is not int or not 1 <= config["max_records"] <= 100:
        raise ValueError("projection must respect the 100-event investigation scope")
    if config.get("seed") != 42 or config.get("benign_per_host_day") != 1:
        raise ValueError("unexpected preregistered sampling policy")
    periods = config["periods"]
    if len(periods) != 2 or [(p["split"], p["purpose"]) for p in periods] != [
        ("development", "benign_calibration"), ("test", "external_test")
    ]:
        raise ValueError("invalid calibration/test purposes")
    first, boundary = utc(periods[0]["start"]), utc(periods[0]["end"])
    last = utc(periods[1]["end"])
    if boundary != utc(periods[1]["start"]) or boundary - first != timedelta(days=14) or last - boundary != timedelta(days=14):
        raise ValueError("calibration and test must be consecutive disjoint 14-day periods")
    if (first, boundary, last) != (utc("2024-12-23T00:00:00Z"), utc("2025-01-06T00:00:00Z"), utc("2025-01-20T00:00:00Z")):
        raise ValueError("time boundaries differ from fixed source documentation")
    return first, boundary, last


def _window_state() -> dict:
    return {"raw_count": 0, "labels": Counter(), "records": [], "kept": set(), "duplicate_retained_rows": 0}


class WindowCollector:
    """Bound memory to 100 projected records per declared host/time window."""
    def __init__(self, *, labels, splits: dict):
        self.labels, self.splits = labels, splits
        self.start, self.boundary, self.end = validate_splits(splits)
        self.windows = {}
        self.stats = Counter()
        self.hosts, self.days, self.original_labels = Counter(), Counter(), Counter()
        self.matched_labels = set()
        self.minimum = self.maximum = None
        self.attack_windows = defaultdict(list)
        self.attack_starts = {}
        self.registered_attack_keys = set()
        self.attack_exclusions = {}
        self.attack_grid_keys = set()
        self._label_clocks = {(entry["source"], entry["host"], entry["timestamp"])
                              for entry in labels.entries.values()}
        positive_times = defaultdict(set)
        for entry in labels.entries.values():
            if entry["label"] == "malicious":
                positive_times[(entry["source"], entry["host"])].add(utc(entry["timestamp"]))
        for (source, host), timestamps in sorted(positive_times.items()):
            previous_end = None
            for start in sorted(timestamps):
                if previous_end is not None and start < previous_end:
                    continue
                end = start + timedelta(seconds=1800)
                previous_end = end
                key = (source, host, stamp(start), "attack")
                self.registered_attack_keys.add(key)
                self.attack_windows[(source, host)].append((start, end, key))
                if start < self.boundary < end or start < self.end < end:
                    self.attack_exclusions[key] = "crosses_test_boundary"
                elif not self.boundary <= start < self.end:
                    self.attack_exclusions[key] = "outside_test_period"
                grid = utc(window_start(stamp(start)))
                while grid < end:
                    self.attack_grid_keys.add((source, host, stamp(grid), "grid"))
                    grid += timedelta(seconds=1800)
            self.attack_starts[(source, host)] = [row[0] for row in self.attack_windows[(source, host)]]

    def add(self, event: dict) -> None:
        source, host, fingerprint = event["source"], event["host"], event["event_fingerprint"]
        label = self.labels.classify(source, fingerprint, host=host)
        observed, keys = self._account(source, host, event["observed_at"], label, fingerprint)
        if not keys:
            return
        safe = project_observations(event)
        order = (observed, event["external_id"])
        for key in keys:
            self._add_to_window(key, event, safe, order, label)

    def _account(self, source, host, timestamp, label, fingerprint=None):
        """Record every validated row once, independently of its projection."""
        self.stats["parsed_rows"] += 1
        observed = utc(timestamp)
        self.minimum = observed if self.minimum is None else min(self.minimum, observed)
        self.maximum = observed if self.maximum is None else max(self.maximum, observed)
        self.hosts[f"{source}:{host}"] += 1
        self.days[observed.date().isoformat()] += 1
        self.original_labels[label] += 1
        if fingerprint is not None and (source, fingerprint) in self.labels.entries:
            self.matched_labels.add((source, fingerprint))
        if not self.start <= observed < self.end:
            self.stats["outside_period_rows"] += 1
            return observed, []
        if observed < self.boundary:
            self.stats["calibration_rows"] += 1
            if label in {"malicious", "malicious-related"}:
                raise ValueError("calibration contains a positive official label")
            return observed, []
        if host not in EXHAUSTIVE_HOSTS.get(source, ()):
            self.stats["excluded_host_rows"] += 1
            return observed, []
        keys = [(source, host, window_start(timestamp), "grid")]
        index = bisect_right(self.attack_starts.get((source, host), ()), observed) - 1
        if index >= 0:
            _, end, key = self.attack_windows[(source, host)][index]
            if observed < end:
                keys.append(key)
        return observed, keys

    def add_decoded(self, decoded: DecodedEvent) -> None:
        """Skip expensive work only after exact negative/retention proofs.

        An identical official source object necessarily retains host and its
        original timestamp. A missing label clock therefore cannot be labeled.
        A retained duplicate necessarily has the same UTC timestamp. Hashes may
        therefore be skipped only when the row is strictly later than the last
        retained timestamp in every matching full window. Equal timestamps and
        out-of-order rows always retain the complete duplicate/ordering check.
        """
        source, host = decoded.source, decoded.host
        verified = (isinstance(self.labels, LabelIndex)
                    and self.labels.official_verified and self.labels.exhaustive)
        fingerprint = None
        if not verified or (source, host, decoded.original_timestamp) in self._label_clocks:
            fingerprint = decoded.fingerprint
            label = self.labels.classify(source, fingerprint, host=host)
        else:
            label = "benign" if host in EXHAUSTIVE_HOSTS.get(source, ()) else "unscorable"
        observed, keys = self._account(source, host, decoded.timestamp, label, fingerprint)
        if not keys:
            return
        if fingerprint is None:
            needed = False
            for key in keys:
                state = self.windows.setdefault(key, _window_state())
                if (len(state["records"]) < self.splits["max_records"]
                        or observed <= state["records"][-1][0][0]):
                    needed = True
                    break
            if not needed:
                for key in keys:
                    state = self.windows[key]
                    state["raw_count"] += 1
                    state["labels"][label] += 1
                return
            fingerprint = decoded.fingerprint
        projected = None

        def projection():
            nonlocal projected
            if projected is None:
                projected = project_observations(decoded.project())
            return projected

        order = (observed, decoded.external_id)
        for key in keys:
            self._add_to_window(key, {"event_fingerprint": fingerprint}, projection, order, label)

    def _add_to_window(self, key, event: dict, safe: dict, order: tuple, label: str) -> None:
        state = self.windows.setdefault(key, _window_state())
        state["raw_count"] += 1
        state["labels"][label] += 1
        fingerprint = event["event_fingerprint"]
        if fingerprint in state["kept"]:
            state["duplicate_retained_rows"] += 1
            existing = next(item for item in state["records"] if item[1]["event_fingerprint"] == fingerprint)
            if order < existing[0]:
                state["records"].remove(existing)
                insort(state["records"], (order, safe() if callable(safe) else safe, label), key=lambda row: row[0])
            return
        if len(state["records"]) >= self.splits["max_records"] and order >= state["records"][-1][0]:
            return
        insort(state["records"], (order, safe() if callable(safe) else safe, label), key=lambda row: row[0])
        state["kept"].add(fingerprint)
        if len(state["records"]) > self.splits["max_records"]:
            removed = state["records"].pop()
            state["kept"].remove(removed[1]["event_fingerprint"])

    def finish(self) -> dict:
        return {"counts": dict(sorted(self.stats.items())), "hosts": dict(sorted(self.hosts.items())),
                "days": dict(sorted(self.days.items())), "original_labels": dict(sorted(self.original_labels.items())),
                "observed_min": stamp(self.minimum) if self.minimum else None,
                "observed_max": stamp(self.maximum) if self.maximum else None,
                "label_fingerprints_expected": len(self.labels.entries),
                "label_fingerprints_matched": len(self.matched_labels),
                "label_fingerprints_unmatched": len(set(self.labels.entries) - self.matched_labels)}


def _rank(key) -> str:
    return hashlib.sha256(canonical([42, *key[:3]]).encode()).hexdigest()


def _gold(event: dict, label: str) -> dict:
    attack = True if label == "malicious" else False if label == "benign" else None
    return {"external_id": event["external_id"], "source_label": label, "is_attack": attack,
            "attack_types": [], "taxonomy_status": "out_of_taxonomy" if attack else "not_applicable" if attack is False else "unscorable",
            "applicability": {"attack_binary": attack is not None, "six_class": False,
                              "techniques": False, "phases": False, "origin": False},
            "provenance": {k: event[k] for k in ("archive", "relative_log_path", "line_number", "raw_line_sha256", "event_fingerprint")}}


def emit_cases(collector: WindowCollector, *, output_root: Path, input_hashes: dict) -> dict:
    output_root = Path(output_root)
    if output_root.exists() and any(output_root.iterdir()):
        raise FileExistsError("output root is not empty; preserve prior build")
    output_root.mkdir(parents=True, exist_ok=True)
    windows = collector.windows
    for key in sorted(collector.registered_attack_keys):
        windows.setdefault(key, _window_state())
    benign_groups = defaultdict(list)
    for key, value in windows.items():
        if key[3] == "grid" and key not in collector.attack_grid_keys and set(value["labels"]) == {"benign"}:
            benign_groups[(key[0], key[1], key[2][:10])].append(key)
    benign_selected = {min(keys, key=_rank) for keys in benign_groups.values()}
    cases, ledger = [], []
    counts = Counter({"attack": 0, "normal": 0, "unscorable": 0})
    for key in sorted(windows):
        source, host, start, kind = key
        value = windows[key]
        projected_labels = Counter(row[2] for row in value["records"])
        is_attack = value["labels"]["malicious"] > 0
        if key in collector.attack_exclusions:
            reason = collector.attack_exclusions[key]
        elif key in collector.attack_grid_keys:
            reason = "overlaps_registered_attack_window"
        elif kind == "attack" and not is_attack:
            reason = "registered_attack_not_observed"
        elif is_attack and not projected_labels["malicious"]:
            reason = "attack_outside_projection"
        elif is_attack:
            reason = "selected_attack"
        elif set(value["labels"]) != {"benign"}:
            reason = "related_or_unknown"
        else:
            reason = "selected_normal" if key in benign_selected else "seeded_benign_not_selected"
        row = {"source": source, "host": host, "time_from": start, "candidate_kind": kind,
               "time_to": stamp(utc(start) + timedelta(seconds=1800)), "reason": reason,
               "raw_window_count": value["raw_count"], "projected_count": len(value["records"]),
               "source_labels": dict(sorted(value["labels"].items())),
               "projected_labels": dict(sorted(projected_labels.items())),
               "duplicate_retained_rows": value["duplicate_retained_rows"]}
        ledger.append(row)
        if reason not in {"selected_attack", "selected_normal"}:
            if reason not in {"seeded_benign_not_selected", "overlaps_registered_attack_window"}:
                counts["unscorable"] += 1
            continue
        case_id = "dedale-" + hashlib.sha256(canonical(key).encode()).hexdigest()[:16]
        dataset = "dedale-v2.1:" + case_id
        root = output_root / "test" / case_id
        observations = [{**record, "dataset_id": dataset} for _, record, _ in value["records"]]
        gold = [_gold(record, label) for _, record, label in value["records"]]
        write_new(root / "agent/events.jsonl", observations, jsonl=True)
        agent = {"schema_version": 1, "case_id": case_id, "dataset_id": dataset, "scenario": "dedale",
                 "split": "test", "title": "Historical event review", "events_file": "events.jsonl",
                 "events_sha256": sha256(root / "agent/events.jsonl"), "event_count": len(observations),
                 "time_from": start, "time_to": row["time_to"], "bounds": "[start,end)",
                 "filters": {"host": host, "dataset_id": dataset}, "limit": 100,
                 "alert": {"title": "Historical event review", "created_at": stamp(utc(start) + timedelta(seconds=900)), "host": host}}
        write_new(root / "agent/manifest.json", agent)
        write_new(root / "scoring/gold.jsonl", gold, jsonl=True)
        write_new(root / "scoring/source-gold.json", {"observed_source_ips": [], "entry_candidates": [],
                  "applicability": {"origin": False}, "reason": "No reviewed source attribution gold"})
        artifacts = {name: sha256(root / name) for name in ["agent/events.jsonl", "agent/manifest.json", "scoring/gold.jsonl", "scoring/source-gold.json"]}
        score = {"schema_version": 1, "case_id": case_id, "dataset_id": dataset, "scenario": "dedale", "split": "test",
                 "campaign_id": "dedale-v2.1-single-campaign", "input_sha256": input_hashes,
                 "counts": {"selected": len(gold), "attack": projected_labels["malicious"], "normal": projected_labels["benign"],
                            "unknown": projected_labels["malicious-related"] + projected_labels["unscorable"]},
                 "window": row, "artifacts": artifacts, "case_is_attack": is_attack,
                 "case_applicability": {"attack_binary": True, "six_class": False, "phases": False, "techniques": False, "origin": False},
                 "stage_review": "pending", "independence": "Correlated windows from a single campaign"}
        write_new(root / "scoring/manifest.json", score)
        case = {"case_id": case_id, "scenario": "dedale", "split": "test", "event_count": len(gold),
                "is_attack": is_attack, "time_from": start, "time_to": row["time_to"], "host": host,
                "campaign_id": "dedale-v2.1-single-campaign", "artifacts": {**artifacts, "scoring/manifest.json": sha256(root / "scoring/manifest.json")},
                "agent_manifest_sha256": artifacts["agent/manifest.json"], "scoring_manifest_sha256": sha256(root / "scoring/manifest.json")}
        cases.append(case)
        counts["attack" if is_attack else "normal"] += 1
        row["case_id"] = case_id
    cases.sort(key=lambda row: row["case_id"])
    selection = {"schema_version": 1, "dataset_id": "dedale-v2.1", "split": "test", "status": "prepared_not_frozen",
                 "N_D": len(cases), "M_D": len(cases), "counts": dict(counts), "cases": cases,
                 "ablation_case_ids": [r["case_id"] for r in cases], "candidate_ledger": ledger,
                 "excluded_host_rows": collector.stats["excluded_host_rows"], "input_sha256": input_hashes,
                 "scan": collector.finish(), "source_label_summary": collector.labels.summary,
                 "official_label_archive_verified": collector.labels.official_verified,
                 "candidate_closure": len(ledger) == len(windows), "stage_coverage": {"reviewed": False, "reason": "Stage gold requires source-based independent review"},
                 "sampling": {"seed": 42, "benign_per_host_day": 1, "rank": "sha256(canonical([42, source, host, UTC half-hour start]))", "max_records": collector.splits["max_records"],
                              "attack_window_rule": "greedy_class1_timestamp_nonoverlapping"}}
    write_new(output_root / "selection.json", selection)
    return selection


def build_from_events(events, *, labels, splits: dict, output_root: Path, input_hashes: dict) -> dict:
    collector = WindowCollector(labels=labels, splits=splits)
    for event in events:
        collector.add(event)
    return emit_cases(collector, output_root=output_root, input_hashes=input_hashes)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("sources", "splits", "label-policy", "data-root", "output-root"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--late-projection", action="store_true",
                        help="Use validated lazy projection; frozen bytes remain identical")
    parser.add_argument("--checkpoint-root", type=Path,
                        help="Reuse complete verified members from this build's JSON checkpoint directory")
    args = parser.parse_args(argv)
    from .scan import prepare_dataset
    result = prepare_dataset(**vars(args))
    print(canonical({"status": result["status"], "N_D": result["N_D"], "M_D": result["M_D"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
