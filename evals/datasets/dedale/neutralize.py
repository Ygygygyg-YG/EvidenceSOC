"""Build neutral cases from an independently verified v2 preparation.

The v2 full-scan ledger is preserved as lineage. Normal controls are selected
again from original, fully exhausted, checksummed members; no synthetic event
timestamp or answer-dependent case identifier is written to the agent view.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
import uuid
from collections import Counter, defaultdict
from concurrent.futures import ProcessPoolExecutor, as_completed
from datetime import timedelta
from pathlib import Path

from .build_manifests import WindowCollector, _gold, project_observations, stamp, utc
from .checkpoint import MAX_CHECKPOINT_BYTES, MemberCheckpoints, _read, code_hashes
from .common import OFFICIAL, canonical, read_json, safe_file, sha256, write_new
from .join_labels import EXHAUSTIVE_HOSTS, LabelIndex, load_label_index
from .parse import (
    ARCHIVE_SOURCES,
    decode_event,
    iter_archive_lines,
    read_archive_manifest,
)
from .scan import (
    _check_output_root,
    _require_labels,
    _validate_policy,
    _validate_scan_splits,
    merge_collector_state,
)

# Malformed external artifacts consistently fail with ValueError.
# ruff: noqa: TRY004

PROTOCOL = "dedale-neutral-v3"
ARTIFACTS = ("agent/events.jsonl", "agent/manifest.json", "scoring/gold.jsonl",
             "scoring/source-gold.json", "scoring/manifest.json")
_FIRST = "2025-01-06T00:00:00Z"
_LAST = "2025-01-20T00:00:00Z"
_CLOCK = re.compile(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(\.\d+)?Z")
_WORKER = None


def digest(value) -> str:
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def instant(value: str) -> tuple[str, str]:
    """Compare normalized UTC timestamps without discarding fractional digits."""
    match = _CLOCK.fullmatch(value) if isinstance(value, str) else None
    if match is None:
        raise ValueError("normalized UTC timestamp required")
    utc(value)  # Validate date/time, independently of lexicographic ordering.
    return match[1], (match[2] or "")[1:].rstrip("0")


def _decoded_instant(value: str) -> tuple[str, str]:
    """decode_event already proved this UTC date and normalized clock valid."""
    return value[:19], value[20:-1].rstrip("0") if value[19:20] == "." else ""


def canonical_clock(value: str) -> str:
    """One representation for either class, with every significant digit kept."""
    whole, fraction = instant(value)
    return whole + ("." + fraction if fraction else "") + "Z"


def shift_seconds(value: str, seconds: int) -> str:
    instant(value)
    whole, fraction = value.removesuffix("Z").split(".", 1) if "." in value else (value[:-1], None)
    result = stamp(utc(whole + "Z") + timedelta(seconds=seconds)).removesuffix("Z")
    return result + ("." + fraction if fraction is not None else "") + "Z"


def neutral_case_id(source: str, host: str, start: str) -> str:
    return "dedale-" + digest([source, host, canonical_clock(start)])[:16]


def candidate_cut(candidate: dict) -> str:
    source, host, base = (candidate[key] for key in ("source", "host", "base_start"))
    offset = int(digest([42, "dedale-normal-control-v3", source, host, base]), 16) % 1_800_000
    return canonical_clock(stamp(utc(base) + timedelta(milliseconds=offset)))


def control_candidates(ledger: list[dict]) -> dict[tuple, list[dict]]:
    groups = defaultdict(list)
    seen = set()
    for row in ledger:
        if (row.get("candidate_kind") != "grid" or set(row.get("source_labels", {})) != {"benign"}
                or row.get("reason") not in {"selected_normal", "seeded_benign_not_selected"}):
            continue
        source, host, base = (row[key] for key in ("source", "host", "time_from"))
        if (source not in EXHAUSTIVE_HOSTS or host not in EXHAUSTIVE_HOSTS[source]
                or not instant(_FIRST) <= instant(base) < instant(_LAST)
                or row["time_to"] != shift_seconds(base, 1800)):
            raise ValueError("invalid preparation control candidate")
        key = source, host, base
        if key in seen:
            raise ValueError("duplicate preparation control candidate")
        seen.add(key)
        candidate = {"source": source, "host": host, "base_start": base,
                     "base_end": row["time_to"], "preparation_grid_raw_count": row["raw_window_count"]}
        groups[(source, host, base[:10])].append(candidate)
    return {key: sorted(rows, key=lambda row: digest([42, row["source"], row["host"], row["base_start"]]))
            for key, rows in sorted(groups.items())}


def start_exclusion(start: str, attack_windows: list[tuple[str, str]]) -> str | None:
    end = shift_seconds(start, 1800)
    if not instant(_FIRST) <= instant(start) < instant(end) <= instant(_LAST):
        return "crosses_test_boundary"
    # An endpoint at the next midnight still belongs to the preceding half-open day.
    day_end = stamp(utc(start[:10] + "T00:00:00Z") + timedelta(days=1))
    if instant(end) > instant(day_end):
        return "crosses_utc_day"
    if any(instant(start) < instant(right) and instant(left) < instant(end)
           for left, right in attack_windows):
        return "overlaps_registered_attack_window"
    return None


def eligible_members(index: list[dict], source: str, host: str, start: str, end: str) -> list[dict]:
    """Use verified scan bounds, conservatively widened for v2 microsecond state."""
    return [row for row in index if row["source"] == source
            and row["hosts"].get(f"{source}:{host}", 0)
            and row["minimum"] is not None
            and utc(row["minimum"]) < utc(end) + timedelta(microseconds=1)
            and utc(row["maximum"]) + timedelta(microseconds=1) >= utc(start)]


def _decoded_pass(data_root: Path, members: list[dict], consume) -> list[dict]:
    proofs = []
    for row in members:
        path = safe_file(data_root, row["archive"])
        count = 0
        # Exhaustion executes both the nested JSONL MD5 check and ZIP CRC check.
        for member, line, raw_line in iter_archive_lines(path, member_names={row["member"]}):
            decoded = decode_event(raw_line, archive=row["archive"], relative_log_path=member, line_number=line)
            consume(decoded)
            count += 1
        if count != row["raw_rows"]:
            raise ValueError("raw member row count differs from verified preparation")
        proofs.append({"archive": row["archive"], "member": row["member"],
                       "jsonl_md5": row["jsonl_md5"], "raw_rows": count,
                       "jsonl_md5_verified": True})
    return proofs


def _window_collector(labels) -> WindowCollector:
    return WindowCollector(labels=labels, splits={"dataset_id": "dedale-v2.1", "window_seconds": 1800,
        "max_records": 100, "seed": 42, "benign_per_host_day": 1,
        "periods": [{"split": "development", "purpose": "benign_calibration", "start": "2024-12-23T00:00:00Z", "end": _FIRST},
                    {"split": "test", "purpose": "external_test", "start": _FIRST, "end": _LAST}]})


def scan_candidate(candidate: dict, *, data_root: Path, index: list[dict], labels,
                   attack_windows: list[tuple[str, str]]) -> dict:
    source, host = candidate["source"], candidate["host"]
    cut, base_end = candidate_cut(candidate), candidate["base_end"]
    start, start_order = None, None
    cut_order, base_end_order = instant(cut), instant(base_end)

    def locate(decoded):
        nonlocal start, start_order
        if decoded.source == source and decoded.host == host:
            observed = _decoded_instant(decoded.timestamp)
            if cut_order <= observed < base_end_order and (start_order is None or observed < start_order):
                start, start_order = decoded.timestamp, observed

    anchor_proofs = _decoded_pass(data_root, eligible_members(index, source, host, cut, base_end), locate)
    result = {**candidate, "candidate_kind": "control", "cut": cut,
              "original_anchor_timestamp": start, "time_from": canonical_clock(start) if start else None,
              "time_to": canonical_clock(shift_seconds(start, 1800)) if start else None,
              "raw_window_count": None, "projected_count": None, "source_labels": None,
              "projected_labels": None, "duplicate_retained_rows": None,
              "passes": {"anchor": anchor_proofs, "window": None}}
    if start is None:
        return {**result, "reason": "no_event_after_cut"}
    exclusion = start_exclusion(start, attack_windows)
    if exclusion:
        return {**result, "reason": exclusion}
    end = result["time_to"]
    end_order = instant(end)
    collector = _window_collector(labels)
    key = source, host, start, "control"
    verified = isinstance(labels, LabelIndex) and labels.official_verified and labels.exhaustive
    label_clocks = {(entry["source"], entry["host"], entry["timestamp"]) for entry in labels.entries.values()}

    def account(decoded):
        if decoded.source != source or decoded.host != host:
            return
        observed = _decoded_instant(decoded.timestamp)
        if not start_order <= observed < end_order:
            return
        fingerprint = None
        if verified and (source, host, decoded.original_timestamp) not in label_clocks:
            label = "benign" if host in EXHAUSTIVE_HOSTS.get(source, ()) else "unscorable"
        else:
            fingerprint = decoded.fingerprint
            label = labels.classify(source, fingerprint, host=host)
        state = collector.windows.get(key)
        if (fingerprint is None and state is not None and len(state["records"]) >= 100
                and observed > state["records"][-1][0][0]):
            state["raw_count"] += 1
            state["labels"][label] += 1
            return
        fingerprint = fingerprint or decoded.fingerprint
        order = observed, decoded.external_id
        collector._add_to_window(key, {"event_fingerprint": fingerprint},
                                 lambda: project_observations(decoded.project()), order, label)

    result["passes"]["window"] = _decoded_pass(data_root, eligible_members(index, source, host, start, end), account)
    state = collector.windows.get(key)
    if state is None or not state["raw_count"]:
        raise ValueError("verified anchor vanished during window reread")
    projected = Counter(row[2] for row in state["records"])
    result.update({"reason": "selected_normal" if set(state["labels"]) == {"benign"} else "window_not_entirely_benign",
                   "raw_window_count": state["raw_count"], "projected_count": len(state["records"]),
                   "source_labels": dict(sorted(state["labels"].items())),
                   "projected_labels": dict(sorted(projected.items())),
                   "duplicate_retained_rows": state["duplicate_retained_rows"]})
    if result["reason"] == "selected_normal":
        result["records"] = state["records"]
    return result


def evaluate_group(candidates: list[dict], *, data_root: Path, index: list[dict], labels,
                   attack_windows: list[tuple[str, str]]) -> list[dict]:
    selected, results = False, []
    for candidate in candidates:
        if selected:
            results.append({**candidate, "candidate_kind": "control", "cut": candidate_cut(candidate),
                            "reason": "not_evaluated_after_first_eligible", "time_from": None, "time_to": None,
                            "original_anchor_timestamp": None,
                            "raw_window_count": None, "projected_count": None, "source_labels": None,
                            "projected_labels": None, "duplicate_retained_rows": None,
                            "passes": {"anchor": None, "window": None}})
            continue
        result = scan_candidate(candidate, data_root=data_root, index=index,
                                labels=labels, attack_windows=attack_windows)
        selected = result["reason"] == "selected_normal"
        results.append(result)
    return results


def _line_json(path: Path) -> list[dict]:
    def unique(pairs):
        value = dict(pairs)
        if len(value) != len(pairs):
            raise ValueError("duplicate JSONL key")
        return value

    values = []
    with path.open("rb") as stream:
        for line in stream:
            if not line.strip() or len(line) > 2 * 1024 * 1024:
                raise ValueError("empty or oversized artifact JSONL row")
            value = json.loads(line.decode("utf-8"), object_pairs_hook=unique)
            if not isinstance(value, dict):
                raise ValueError("artifact JSONL row must be an object")
            canonical(value).encode("utf-8")
            values.append(value)
    return values


def _preparation_cases(prepared_root: Path, selection: dict, labels) -> list[dict]:
    if (selection.get("status") != "prepared_not_frozen" or selection.get("dataset_id") != "dedale-v2.1"
            or selection.get("N_D") != selection.get("M_D") or selection.get("N_D") != len(selection.get("cases", []))
            or selection.get("scan", {}).get("freeze_eligible") is not True
            or selection["scan"].get("full_archive_scan") is not True
            or selection["scan"].get("invalid_rows") != 0
            or selection["scan"].get("label_fingerprints_unmatched") != 0):
        raise ValueError("preparation is incomplete or not source/label eligible")
    attacks, seen = [], set()
    for case in selection["cases"]:
        case_id = case["case_id"]
        if case_id in seen or not re.fullmatch(r"dedale-[0-9a-f]{16}", case_id):
            raise ValueError("invalid or repeated preparation case identity")
        seen.add(case_id)
        root = safe_file(prepared_root, "test/" + case_id)
        if set(case["artifacts"]) != set(ARTIFACTS):
            raise ValueError("preparation case artifact inventory differs")
        for name in ARTIFACTS:
            if sha256(safe_file(root, name)) != case["artifacts"][name]:
                raise ValueError("preparation case artifact hash differs")
        agent, score = (read_json(safe_file(root, name)) for name in ("agent/manifest.json", "scoring/manifest.json"))
        records, gold = (_line_json(safe_file(root, name)) for name in ("agent/events.jsonl", "scoring/gold.jsonl"))
        if (agent["case_id"] != case_id or score["case_id"] != case_id
                or score["input_sha256"] != selection["input_sha256"]
                or case["event_count"] != len(records) or not 1 <= len(records) <= 100
                or len(gold) != len(records) or score["case_is_attack"] is not case["is_attack"]
                or any(score["artifacts"].get(name) != case["artifacts"][name] for name in ARTIFACTS[:-1])):
            raise ValueError("preparation case metadata differs")
        checked = []
        for record, target in zip(records, gold, strict=True):
            label = labels.classify(record["source"], record["event_fingerprint"], host=record["host"])
            if target != _gold(record, label) or project_observations(record) != record:
                raise ValueError("preparation labels or observation projection differ")
            if (not instant(case["time_from"]) <= instant(record["observed_at"]) < instant(case["time_to"])
                    or record["host"] != case["host"] or record["dataset_id"] != agent["dataset_id"]):
                raise ValueError("preparation observation scope differs")
            original = {**record, "dataset_id": "dedale-v2.1"}
            checked.append(((instant(record["observed_at"]), record["external_id"]), original, label))
        if case["is_attack"]:
            window = score["window"]
            if window["reason"] != "selected_attack" or window["candidate_kind"] != "attack":
                raise ValueError("preparation attack window differs")
            attacks.append({"window": {key: value for key, value in window.items() if key != "case_id"},
                            "records": checked})
    return attacks


def load_member_index(*, data_root: Path, prepared_root: Path, preparation_checkpoints: Path,
                      selection: dict, labels, scan_splits: dict) -> tuple[list[dict], dict]:
    member_md5 = {}
    for archive in sorted(ARCHIVE_SOURCES):
        manifest = read_archive_manifest(safe_file(data_root, archive))
        if manifest is None:
            raise ValueError("preparation archive MD5 manifest missing")
        member_md5.update({(archive, member): md5 for member, md5 in manifest["checksums"].items()})
    expected = selection["scan"]["members_expected"]
    if (len(member_md5) != expected or selection["scan"]["members_completed"] != expected
            or len(selection["scan"]["member_summaries"]) != expected):
        raise ValueError("preparation member coverage differs")
    checkpoints = MemberCheckpoints(preparation_checkpoints, data_root=data_root,
        output_root=prepared_root, input_hashes=selection["input_sha256"],
        member_md5=member_md5, labels=labels, splits=scan_splits)
    index, totals, matched = [], Counter(), set()
    window_totals = {}
    attacks = _preparation_cases(prepared_root, selection, labels)
    attack_keys = {(case["window"]["source"], case["window"]["host"], case["window"]["time_from"], "attack") for case in attacks}
    collector = WindowCollector(labels=labels, splits=scan_splits)
    try:
        summaries = {(row["archive"], row["member"]): row for row in selection["scan"]["member_summaries"]}
        if len(summaries) != expected:
            raise ValueError("preparation member summaries repeat identities")
        for (archive, member), md5 in sorted(member_md5.items()):
            state = checkpoints.load((str(safe_file(data_root, archive)), member))
            if state is None or state["stats"]["invalid_rows"]:
                raise ValueError("preparation checkpoints are missing, invalid, or incomplete")
            summary = summaries.get((archive, member))
            actual = {"archive": archive, "member": member, "raw_rows": state["stats"]["raw_rows"],
                      "parsed_rows": state["stats"]["parsed_rows"], "invalid_rows": state["stats"]["invalid_rows"],
                      "jsonl_md5_verified": True}
            if summary != actual:
                raise ValueError("preparation member summary differs from checkpoint")
            totals.update(state["stats"])
            matched.update(state["matched_labels"])
            for key, window in state["windows"].items():
                aggregate = window_totals.setdefault(key, {"raw_count": 0, "labels": Counter()})
                aggregate["raw_count"] += window["raw_count"]
                aggregate["labels"].update(window["labels"])
            merge_collector_state(collector, {**state, "windows": {
                key: window for key, window in state["windows"].items() if key in attack_keys}})
            index.append({**actual, "source": ARCHIVE_SOURCES[archive], "jsonl_md5": md5,
                          "minimum": stamp(state["minimum"]) if state["minimum"] else None,
                          "maximum": stamp(state["maximum"]) if state["maximum"] else None,
                          "hosts": dict(sorted(state["hosts"].items()))})
        if (dict(sorted(totals.items())) != selection["scan"]["counts"]
                or matched != set(labels.entries)):
            raise ValueError("preparation checkpoint totals or label coverage differ")
        for key in collector.registered_attack_keys:
            window_totals.setdefault(key, {"raw_count": 0, "labels": Counter()})
        ledger = {(row["source"], row["host"], row["time_from"], row["candidate_kind"]): row
                  for row in selection["candidate_ledger"]}
        if len(ledger) != len(selection["candidate_ledger"]) or set(ledger) != set(window_totals):
            raise ValueError("preparation candidate ledger does not close over checkpoints")
        for key, value in window_totals.items():
            if (ledger[key]["raw_window_count"] != value["raw_count"]
                    or ledger[key]["source_labels"] != dict(sorted(value["labels"].items()))):
                raise ValueError("preparation candidate raw counts or source labels differ from checkpoints")
        for case in attacks:
            row = case["window"]
            key = row["source"], row["host"], row["time_from"], "attack"
            value = collector.windows.get(key)
            expected_records = [(event, label) for _, event, label in value["records"]] if value else []
            if expected_records != [(event, label) for _, event, label in case["records"]]:
                raise ValueError("preparation attack observations differ from own raw checkpoints")
            if (row["duplicate_retained_rows"] != value["duplicate_retained_rows"]
                    or row["projected_labels"] != dict(sorted(Counter(item[2] for item in value["records"]).items()))
                    or row["projected_count"] != len(value["records"])):
                raise ValueError("preparation attack projection accounting differs from own checkpoints")
        if any(collector.finish()[key] != selection["scan"][key] for key in collector.finish()):
            raise ValueError("preparation full scan summary differs from checkpoints")
        checkpoints.verify_code_unchanged()
        binding = checkpoints.binding
    finally:
        checkpoints.close()
    return index, binding


def implementation_hashes() -> dict[str, str]:
    return {**code_hashes(), "neutralize.py": sha256(Path(__file__))}


def validate_neutral_policy(neutral_policy: dict, scan_config: dict, scan_sha256: str) -> None:
    for key in ("schema_version", "dataset_id", "window_seconds", "max_records", "seed",
                "benign_per_host_day", "periods", "bounds", "timezone", "event_sort",
                "dedup_key", "campaign_id", "recent_months"):
        if canonical(neutral_policy.get(key)) != canonical(scan_config[key]):
            raise ValueError("neutral policy changes fixed investigation scope: " + key)
    if (neutral_policy.get("protocol") != PROTOCOL
            or neutral_policy.get("preparation_splits_sha256") != scan_sha256
            or neutral_policy.get("preparation_code_sha256") != code_hashes()):
        raise ValueError("neutral protocol or preparation implementation binding differs")
    expected = {"after_selected": "not_evaluated_after_first_eligible",
                "anchor_rule": "first actual observation at or after cut and before base_end",
                "candidate_basis": "v2 pure-benign grid rows with reason selected_normal or seeded_benign_not_selected",
                "choose": "first eligible candidate per source/host/UTC day", "group": ["source", "host", "UTC day"],
                "jitter_context": "dedale-normal-control-v3", "jitter_milliseconds_mod": 1800000,
                "rank": "sha256(canonical([42,source,host,base_start]))", "reject_attack_overlap": True,
                "reject_cross_day": True, "require_all_raw_labels": "benign", "width_seconds": 1800}
    if canonical(neutral_policy.get("normal_control")) != canonical(expected):
        raise ValueError("neutral policy normal_control differs from implemented preregistration")
    identity = {"excludes": ["kind", "label", "stage"],
                "formula": "sha256(canonical([source,host,start]))[:16]", "prefix": "dedale-"}
    if canonical(neutral_policy.get("case_identity")) != canonical(identity):
        raise ValueError("neutral policy case_identity differs from implemented rule")
    if neutral_policy.get("attack_rule") != "Reuse own complete-v2 raw-derived registered windows and evidence; no model-dependent changes":
        raise ValueError("neutral policy attack_rule differs from implemented rule")
    if neutral_policy.get("timestamp_representation") != "UTC Z; trim fractional trailing zeros, omit zero fraction; preserve exact instant; raw observation timestamps unchanged":
        raise ValueError("neutral policy timestamp_representation differs from implemented rule")


class ControlWork(MemberCheckpoints):
    """Same-root resumable group results, never a cross-root rebuild shortcut."""

    def __init__(self, root: Path, *, data_root: Path, prepared_root: Path,
                 output_root: Path, preparation_checkpoints: Path,
                 binding: dict, groups: dict):
        self._lease = None
        try:
            self.root = Path(root).absolute()
            for path in [*self.root.parents, self.root]:
                if path.is_symlink() or path.is_junction():
                    raise ValueError("control work root traverses a filesystem link")
            roots = [Path(path).resolve() for path in (data_root, prepared_root, output_root, preparation_checkpoints)]
            if any(self.root.resolve().is_relative_to(path) or path.is_relative_to(self.root.resolve()) for path in roots):
                raise ValueError("control work root overlaps input or output")
            self.root.mkdir(parents=True, exist_ok=True)
            self._acquire()
            self.binding = binding
            self.groups = groups
            owner = {"schema_version": 1, "protocol": PROTOCOL, "binding": binding,
                     "data_root": str(roots[0]), "prepared_root": str(roots[1]),
                     "output_root": str(roots[2]), "preparation_checkpoints": str(roots[3])}
            names = {"owner.json", "owner.json.pending", "active.lock"}
            for key in groups:
                names.update({self._group_name(key), self._group_name(key) + ".pending"})
            if any(path.name not in names or path.is_symlink() or path.is_junction() or not path.is_file()
                   for path in self.root.iterdir()):
                raise ValueError("control work root contains unexpected files")
            owner_path = safe_file(self.root, "owner.json")
            if owner_path.exists():
                if _read(owner_path, 64 * 1024) != owner:
                    raise ValueError("control work owner or implementation binding changed")
            elif any(path.name != "active.lock" for path in self.root.iterdir()):
                raise ValueError("control work owner missing")
            else:
                self._write(owner_path, owner, 64 * 1024)
        except BaseException:
            self.close()
            raise

    @staticmethod
    def _group_name(key):
        return "control-" + digest(list(key)) + ".json"

    def load_group(self, key):
        path = safe_file(self.root, self._group_name(key))
        if not path.exists():
            return None
        envelope = _read(path, MAX_CHECKPOINT_BYTES)
        if not isinstance(envelope, dict) or set(envelope) != {"binding", "group", "results", "payload_sha256"}:
            raise ValueError("invalid control work envelope")
        if (envelope["binding"] != self.binding or envelope["group"] != list(key)
                or envelope["payload_sha256"] != digest({name: value for name, value in envelope.items() if name != "payload_sha256"})):
            raise ValueError("control work payload or binding changed")
        results = envelope["results"]
        if not isinstance(results, list) or len(results) != len(self.groups[key]):
            raise ValueError("control work candidate closure differs")
        selected = False
        for result, candidate in zip(results, self.groups[key], strict=True):
            if not isinstance(result, dict) or any(result.get(name) != value for name, value in candidate.items()):
                raise ValueError("control work candidate identity differs")
            if result.get("cut") != candidate_cut(candidate) or result.get("candidate_kind") != "control":
                raise ValueError("control work candidate cut differs")
            if selected and result.get("reason") != "not_evaluated_after_first_eligible":
                raise ValueError("control work selection order differs")
            if not selected and result.get("reason") == "not_evaluated_after_first_eligible":
                raise ValueError("control work skipped unevaluated candidate")
            if result.get("reason") == "selected_normal":
                selected = True
                records = result.get("records", [])
                if (not 1 <= len(records) <= 100 or result["projected_count"] != len(records)
                        or result["source_labels"] != {"benign": result["raw_window_count"]}
                        or result["projected_labels"] != {"benign": len(records)}):
                    raise ValueError("control work selected counts differ")
                result["records"] = [((tuple(order[0]), order[1]), event, label)
                                     for order, event, label in records]
                for order, event, label in result["records"]:
                    if (label != "benign" or order != (instant(event["observed_at"]), event["external_id"])
                            or project_observations(event) != event or event["source"] != key[0] or event["host"] != key[1]):
                        raise ValueError("control work observation differs")
        return results

    def save_group(self, key, results):
        payload = {"binding": self.binding, "group": list(key), "results": results}
        self._write(safe_file(self.root, self._group_name(key)),
                    {**payload, "payload_sha256": digest(payload)}, MAX_CHECKPOINT_BYTES)
        self.load_group(key)


def _initialize_controls(label_archive, data_root, index, attacks):
    global _WORKER
    labels = load_label_index(Path(label_archive), exhaustive=True)
    _require_labels(labels)
    _WORKER = labels, Path(data_root), index, attacks


def _worker_group(task):
    key, candidates = task
    labels, data_root, index, attacks = _WORKER
    return evaluate_group(candidates, data_root=data_root, index=index, labels=labels,
                          attack_windows=attacks.get(key[:2], []))


def _progress(output_root, stage, **values):
    path = output_root.with_name(output_root.name + "-progress.json")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".pending")
    temporary.write_text(canonical({"schema_version": 1, "protocol": PROTOCOL,
                                   "pid": os.getpid(), "stage": stage, **values}) + "\n", encoding="utf-8")
    temporary.replace(path)


def _emit_case(output_root: Path, *, window: dict, records: list, input_hashes: dict) -> dict:
    source, host, start = (window[key] for key in ("source", "host", "time_from"))
    case_id = neutral_case_id(source, host, start)
    dataset = "dedale-v2.1:" + case_id
    root = output_root / "test" / case_id
    observations = [{**event, "dataset_id": dataset} for _, event, _ in records]
    gold = [_gold(event, label) for _, event, label in records]
    projected = Counter(label for _, _, label in records)
    is_attack = window["candidate_kind"] == "attack"
    write_new(root / "agent/events.jsonl", observations, jsonl=True)
    agent = {"schema_version": 1, "case_id": case_id, "dataset_id": dataset, "scenario": "dedale",
             "split": "test", "title": "Historical event review", "events_file": "events.jsonl",
             "events_sha256": sha256(root / "agent/events.jsonl"), "event_count": len(observations),
             "time_from": start, "time_to": window["time_to"], "bounds": "[start,end)",
             "filters": {"host": host, "dataset_id": dataset}, "limit": 100,
             "alert": {"title": "Historical event review", "created_at": shift_seconds(start, 900), "host": host}}
    write_new(root / "agent/manifest.json", agent)
    write_new(root / "scoring/gold.jsonl", gold, jsonl=True)
    write_new(root / "scoring/source-gold.json", {"observed_source_ips": [], "entry_candidates": [],
              "applicability": {"origin": False}, "reason": "No reviewed source attribution gold"})
    artifacts = {name: sha256(root / name) for name in ARTIFACTS[:-1]}
    score = {"schema_version": 1, "case_id": case_id, "dataset_id": dataset, "scenario": "dedale", "split": "test",
             "campaign_id": "dedale-v2.1-single-campaign", "input_sha256": input_hashes,
             "counts": {"selected": len(gold), "attack": projected["malicious"], "normal": projected["benign"],
                        "unknown": projected["malicious-related"] + projected["unscorable"]},
             "window": window, "artifacts": artifacts, "case_is_attack": is_attack,
             "case_applicability": {"attack_binary": True, "six_class": False, "phases": False, "techniques": False, "origin": False},
             "stage_review": "pending", "independence": "Correlated windows from a single campaign"}
    write_new(root / "scoring/manifest.json", score)
    score_hash = sha256(root / "scoring/manifest.json")
    return {"case_id": case_id, "scenario": "dedale", "split": "test", "event_count": len(gold),
            "is_attack": is_attack, "time_from": start, "time_to": window["time_to"], "host": host,
            "campaign_id": "dedale-v2.1-single-campaign", "artifacts": {**artifacts, "scoring/manifest.json": score_hash},
            "agent_manifest_sha256": artifacts["agent/manifest.json"], "scoring_manifest_sha256": score_hash}


def emit_neutral_cases(*, output_root: Path, preparation: dict, preparation_selection_sha256: str,
                       member_index: list[dict], preparation_binding: dict, attacks: list[dict],
                       controls: list[dict], input_hashes: dict, finalizer_code_sha256: dict) -> dict:
    cases, ledger = [], []
    for candidate in [*({**attack["window"], "records": attack["records"]} for attack in attacks), *controls]:
        row = {key: value for key, value in candidate.items() if key != "records"}
        for key in ("time_from", "time_to"):
            if row.get(key) is not None:
                row[key] = canonical_clock(row[key])
        if row["reason"] in {"selected_attack", "selected_normal"}:
            case = _emit_case(output_root, window=row, records=candidate["records"], input_hashes=input_hashes)
            cases.append(case)
            row["case_id"] = case["case_id"]
        ledger.append(row)
    if len({case["case_id"] for case in cases}) != len(cases):
        raise ValueError("neutral case identity collision")
    cases.sort(key=lambda row: row["case_id"])
    counts = {"attack": sum(case["is_attack"] for case in cases),
              "normal": sum(not case["is_attack"] for case in cases),
              "unscorable": sum(row["reason"] not in {"selected_attack", "selected_normal", "not_evaluated_after_first_eligible"} for row in ledger)}
    selection = {**{key: preparation[key] for key in ("schema_version", "dataset_id", "split", "scan", "source_verification",
                        "source_label_summary", "official_label_archive_verified", "excluded_host_rows")},
                 "protocol": PROTOCOL, "status": "prepared_not_frozen", "N_D": len(cases), "M_D": len(cases),
                 "counts": counts, "cases": cases, "ablation_case_ids": [case["case_id"] for case in cases],
                 "candidate_ledger": ledger, "candidate_closure": True,
                 "preparation_ledger": preparation["candidate_ledger"],
                 "input_sha256": input_hashes,
                 "preparation": {"selection_sha256": preparation_selection_sha256,
                    "input_sha256": preparation["input_sha256"], "checkpoint_binding": preparation_binding,
                    "member_index": member_index, "member_index_sha256": digest(member_index),
                    "scan_protocol": "independent v2 full archive scan, not relabeled as a v3 full scan",
                    "attack_reuse": "This root's independently prepared, artifact-verified attack observations only"},
                 "finalizer_code_sha256": finalizer_code_sha256,
                 "sampling": {"seed": 42, "benign_per_host_day": 1, "max_records": 100,
                    "attack_window_rule": "greedy_class1_timestamp_nonoverlapping",
                    "normal_window_rule": "first real event at or after deterministic millisecond cut; complete raw benign-only window",
                    "normal_rank": "sha256(canonical([42,source,host,base_start]))",
                    "normal_cut": "base_start + int(sha256(canonical([42,'dedale-normal-control-v3',source,host,base_start])),16)%1800000 milliseconds",
                    "case_id": "dedale- + sha256(canonical([source,host,time_from]))[:16]"},
                 "stage_coverage": {"reviewed": False, "reason": "Stage gold requires source-based independent review"}}
    write_new(output_root / "selection.json", selection)
    return selection


def publish_staging(staging: Path, output_root: Path) -> None:
    """Publish atomically, allowing bounded Windows sharing/access retries."""
    staging, output_root = Path(staging).absolute(), Path(output_root).absolute()
    if staging.parent.resolve() != output_root.parent.resolve() or staging == output_root:
        raise ValueError("staging and final output must be distinct siblings")
    for attempt in range(6):
        safe_file(staging.parent, staging.name)
        safe_file(output_root.parent, output_root.name)
        if output_root.exists():
            raise FileExistsError("final output appeared before atomic publication")
        if not staging.is_dir():
            raise FileNotFoundError("complete staging directory is missing")
        try:
            staging.rename(output_root)
            return
        except PermissionError as exc:
            if getattr(exc, "winerror", None) not in {5, 32, 33} or attempt == 5:
                raise
            time.sleep(min(0.1 * 2**attempt, 1.0))


def finalize_dataset(*, sources: Path, scan_splits: Path, splits: Path, label_policy: Path,
                     data_root: Path, prepared_root: Path, preparation_checkpoints: Path,
                     output_root: Path, workers: int = 4, work_root: Path | None = None) -> dict:
    if type(workers) is not int or not 1 <= workers <= 8:
        raise ValueError("control workers must be an integer from 1 to 8")
    data_root, prepared_root, output_root = map(Path, (data_root, prepared_root, output_root))
    _check_output_root(output_root, data_root)
    if (output_root.resolve().is_relative_to(prepared_root.resolve())
            or prepared_root.resolve().is_relative_to(output_root.resolve())):
        raise ValueError("final output root overlaps preparation")
    _progress(output_root, "verifying_preparation")
    scan_config, policy, neutral_policy = map(read_json, (scan_splits, label_policy, splits))
    _validate_scan_splits(scan_config)
    _validate_policy(policy)
    selection_path = safe_file(prepared_root, "selection.json")
    selection_hash = sha256(selection_path)
    preparation = read_json(selection_path)
    old_inputs = preparation["input_sha256"]
    for name, path in (("sources", sources), ("splits", scan_splits), ("label_policy", label_policy)):
        if sha256(path) != old_inputs[name]:
            raise ValueError("preparation input configuration differs: " + name)
    validate_neutral_policy(neutral_policy, scan_config, old_inputs["splits"])
    source_config = read_json(sources)
    verification = preparation.get("source_verification", {})
    verified = verification.get("archives", [])
    if (verification.get("verified") is not True or verification.get("sources_sha256") != old_inputs["sources"]
            or len(verified) != 3 or {row["path"] for row in verified} != set(OFFICIAL)):
        raise ValueError("preparation source verification differs")
    for row in verified:
        if (row["bytes"] != OFFICIAL[row["path"]][1] or row["md5"] != OFFICIAL[row["path"]][2]
                or row["crc_checked"] is not True or row["sha256"] != old_inputs["archive:" + row["path"]]
                or safe_file(data_root, row["path"]).stat().st_size != row["bytes"]):
            raise ValueError("preparation raw archive binding differs")
    snapshot = source_config["metadata_snapshot"]
    if sha256(safe_file(data_root, snapshot["path"])) != snapshot["sha256"]:
        raise ValueError("preparation metadata snapshot differs")
    labels = load_label_index(safe_file(data_root, "system_logs_labels.zip"), exhaustive=True)
    _require_labels(labels)
    attacks = _preparation_cases(prepared_root, preparation, labels)
    index, preparation_binding = load_member_index(data_root=data_root, prepared_root=prepared_root,
        preparation_checkpoints=preparation_checkpoints, selection=preparation, labels=labels, scan_splits=scan_config)
    groups = control_candidates(preparation["candidate_ledger"])
    registered = defaultdict(list)
    for row in preparation["candidate_ledger"]:
        if row["candidate_kind"] == "attack":
            registered[(row["source"], row["host"])].append((row["time_from"], row["time_to"]))
    finalizer_hashes = implementation_hashes()
    input_hashes = {**old_inputs, "splits": sha256(splits), "preparation_splits": old_inputs["splits"],
                    "preparation_selection": selection_hash}
    binding = {"protocol": PROTOCOL, "input_sha256": input_hashes,
               "code_sha256": finalizer_hashes, "member_index_sha256": digest(index)}
    work_root = work_root or output_root.with_name(output_root.name + "-control-work")
    cache = ControlWork(work_root, data_root=data_root, prepared_root=prepared_root,
        output_root=output_root, preparation_checkpoints=preparation_checkpoints,
        binding=binding, groups=groups)
    pool, results = None, {}
    try:
        pending = []
        for key, candidates in groups.items():
            cached = cache.load_group(key)
            if cached is None:
                pending.append((key, candidates))
            else:
                results[key] = cached
        _progress(output_root, "rebuilding_controls", groups_completed=len(results), groups_expected=len(groups))
        if workers == 1:
            completed = ((key, evaluate_group(candidates, data_root=data_root, index=index,
                labels=labels, attack_windows=registered.get(key[:2], []))) for key, candidates in pending)
        else:
            pool = ProcessPoolExecutor(max_workers=workers, initializer=_initialize_controls,
                initargs=(str(safe_file(data_root, "system_logs_labels.zip")), str(data_root), index, dict(registered)))
            # Only host/day groups are submitted, never individual raw rows.
            futures = {pool.submit(_worker_group, (key, candidates)): key for key, candidates in pending}
            completed = ((futures[future], future.result()) for future in as_completed(futures))
        for key, value in completed:
            cache.save_group(key, value)
            results[key] = value
            _progress(output_root, "rebuilding_controls", groups_completed=len(results), groups_expected=len(groups))
        if implementation_hashes() != finalizer_hashes or sha256(selection_path) != selection_hash:
            raise ValueError("finalizer implementation or preparation changed during rebuild")
        for name, path in (("sources", sources), ("splits", splits), ("label_policy", label_policy), ("preparation_splits", scan_splits)):
            if sha256(path) != input_hashes[name]:
                raise ValueError("finalization input changed during rebuild")
        staging = output_root.with_name(output_root.name + ".pending-" + uuid.uuid4().hex)
        _check_output_root(staging, data_root)
        selection = emit_neutral_cases(output_root=staging, preparation=preparation,
            preparation_selection_sha256=selection_hash, member_index=index,
            preparation_binding=preparation_binding, attacks=attacks,
            controls=[row for key in sorted(results) for row in results[key]],
            input_hashes=input_hashes, finalizer_code_sha256=finalizer_hashes)
        if output_root.exists():
            output_root.rmdir()  # Only an empty directory accepted by _check_output_root.
        publish_staging(staging, output_root)
    finally:
        if pool is not None:
            pool.shutdown(wait=True, cancel_futures=True)
        cache.close()
    _progress(output_root, "prepared_not_frozen", groups_completed=len(groups), groups_expected=len(groups),
              N_D=selection["N_D"], M_D=selection["M_D"])
    return selection
