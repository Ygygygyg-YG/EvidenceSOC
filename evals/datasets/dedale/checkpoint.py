"""Bounded JSON checkpoints for completely verified DEDALE log members.

These files detect accidental corruption and stale preparation state. Their
self-hashes are not authenticity signatures: an independent raw-data rebuild
and the existing artifact comparison remain mandatory for acceptance.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import os
import re
from collections import Counter
from datetime import timedelta
from pathlib import Path

from .build_manifests import (
    AGENT_FIELDS,
    NESTED_FIELDS,
    WindowCollector,
    project_observations,
    stamp,
    utc,
    window_start,
)
from .common import canonical, safe_file, sha256
from .join_labels import EXHAUSTIVE_HOSTS
from .parse import ARCHIVE_SOURCES, _utc_timestamp

SCHEMA_VERSION = 1
MAX_CHECKPOINT_BYTES = 64 * 1024 * 1024
MAX_OWNER_BYTES = 16 * 1024
MAX_COUNTER_ENTRIES = 4096
MAX_COUNT = 2**63 - 1
_SHA = re.compile(r"[0-9a-f]{64}")
_MD5 = re.compile(r"[0-9a-f]{32}")
_LABELS = frozenset({"benign", "malicious", "malicious-related", "unscorable"})
_STATS = frozenset({"raw_rows", "parsed_rows", "invalid_rows", "calibration_rows",
                    "outside_period_rows", "excluded_host_rows"})
_STATE_FIELDS = frozenset({"archive", "member", "completed", "jsonl_md5_verified",
                           "windows", "stats", "hosts", "days", "original_labels",
                           "matched_labels", "minimum", "maximum", "invalid_examples"})
_EVENT_REQUIRED = frozenset({"dataset_id", "source", "event_type", "external_id",
                            "archive", "relative_log_path", "line_number", "host",
                            "timestamp", "observed_at", "@timestamp", "original_timestamp",
                            "raw_line_sha256", "event_fingerprint", "source_event_id",
                            "severity", "message"})


def code_hashes() -> dict[str, str]:
    """Include every preparation implementation that can affect member state."""
    directory = Path(__file__).parent
    return {name: sha256(directory / name) for name in (
        "parse.py", "build_manifests.py", "scan.py", "join_labels.py", "common.py",
        "checkpoint.py",
    )}


def _digest(value) -> str:
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def _fail(detail: str):
    raise ValueError("checkpoint " + detail)


def _fields(value, required, detail):
    if not isinstance(value, dict) or set(value) != set(required):
        _fail("invalid " + detail + " fields")


def _count(value) -> int:
    if type(value) is not int or not 0 <= value <= MAX_COUNT:
        _fail("count must be a bounded nonnegative integer")
    return value


def _text(value, *, limit=4096):
    if not isinstance(value, str) or not value or len(value) > limit:
        _fail("invalid bounded string")
    return value


def _hash(value, pattern=_SHA):
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        _fail("invalid digest")
    return value


def _tree(value, depth=0):
    """Constrain parsed JSON before interpreting any checkpoint fields."""
    if depth > 20:
        _fail("JSON nesting exceeds bound")
    if isinstance(value, dict):
        if len(value) > MAX_COUNTER_ENTRIES:
            _fail("JSON object exceeds bound")
        for key, child in value.items():
            _tree(key, depth + 1)
            _tree(child, depth + 1)
    elif isinstance(value, list):
        if len(value) > 100_000:
            _fail("JSON array exceeds bound")
        for child in value:
            _tree(child, depth + 1)
    elif isinstance(value, str):
        if len(value) > 8192:
            _fail("JSON string exceeds bound")
        try:
            value.encode("utf-8")
        except UnicodeError:
            _fail("JSON contains invalid Unicode")
    elif isinstance(value, float):
        if not math.isfinite(value):
            _fail("JSON contains nonfinite number")
    elif value is not None and not isinstance(value, (int, bool)):
        _fail("JSON contains unsupported value")


def _read(path: Path, maximum: int):
    if not path.is_file() or path.stat().st_size > maximum:
        _fail("file missing, irregular, or too large")

    def unique(pairs):
        result = dict(pairs)
        if len(result) != len(pairs):
            _fail("duplicate JSON key")
        return result

    def reject(_value):
        _fail("nonfinite JSON constant")

    try:
        with path.open("rb") as stream:
            payload = stream.read(maximum + 1)
        if len(payload) > maximum:
            _fail("file grew beyond bound")
        value = json.loads(payload.decode("utf-8"), object_pairs_hook=unique,
                           parse_constant=reject)
        _tree(value)
        return value
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("checkpoint cannot be read as strict bounded JSON") from exc


def _counter(value, *, allowed=None) -> Counter:
    if not isinstance(value, dict) or len(value) > MAX_COUNTER_ENTRIES:
        _fail("invalid counter")
    for key, count in value.items():
        _text(key, limit=8192)
        _count(count)
        if allowed is not None and key not in allowed:
            _fail("unexpected counter key")
    return Counter(value)


def _timestamp(value):
    try:
        result = utc(_text(value))
        if stamp(result) != value:
            _fail("timestamp must be canonical UTC")
        return result
    except (ValueError, OverflowError) as exc:
        raise ValueError("checkpoint invalid timestamp") from exc


def _json_state(state) -> dict:
    """Encode explicit tuples/dates/sets; arbitrary Python objects never load."""
    _fields(state, _STATE_FIELDS, "state")
    for window in state["windows"].values():
        if window["kept"] != {row[1]["event_fingerprint"] for row in window["records"]}:
            _fail("in-memory retained fingerprint set differs")
    return {
        **{name: state[name] for name in ("archive", "member", "completed",
                                         "jsonl_md5_verified", "invalid_examples")},
        **{name: dict(sorted(state[name].items()))
           for name in ("stats", "hosts", "days", "original_labels")},
        "minimum": stamp(state["minimum"]) if state["minimum"] is not None else None,
        "maximum": stamp(state["maximum"]) if state["maximum"] is not None else None,
        "matched_labels": [list(key) for key in sorted(state["matched_labels"])],
        "windows": [
            {"key": list(key), "raw_count": window["raw_count"],
             "labels": dict(sorted(window["labels"].items())),
             "duplicate_retained_rows": window["duplicate_retained_rows"],
             "records": [{"order": [stamp(order[0]), order[1]], "event": event,
                          "label": label} for order, event, label in window["records"]]}
            for key, window in sorted(state["windows"].items())
        ],
    }


class MemberCheckpoints:
    """A single build's member cache; no input-verification bypass is exposed."""

    def __init__(self, root: Path, *, data_root: Path, output_root: Path,
                 input_hashes: dict, member_md5: dict, labels, splits: dict):
        self._lease = None
        try:
            self._initialize(root, data_root=data_root, output_root=output_root,
                             input_hashes=input_hashes, member_md5=member_md5,
                             labels=labels, splits=splits)
        except BaseException:
            self.close()
            raise

    def _initialize(self, root: Path, *, data_root: Path, output_root: Path,
                    input_hashes: dict, member_md5: dict, labels, splits: dict):
        self.root = Path(root).absolute()
        for part in [*self.root.parents, self.root]:
            if part.is_symlink() or part.is_junction():
                _fail("root must not traverse filesystem links")
        for other in (Path(data_root).resolve(), Path(output_root).resolve()):
            if self.root.resolve().is_relative_to(other) or other.is_relative_to(self.root.resolve()):
                _fail("root must be separate from raw and output roots")
        self.labels, self.splits = labels, splits
        self.policy = WindowCollector(labels=labels, splits=splits)
        self.member_md5 = member_md5
        self.binding = {"schema_version": SCHEMA_VERSION,
                        "input_sha256": input_hashes, "code_sha256": code_hashes()}
        self.binding_sha256 = _digest(self.binding)
        owner = {"schema_version": SCHEMA_VERSION,
                 "data_root": str(Path(data_root).resolve()),
                 "output_root": str(Path(output_root).resolve()),
                 "binding_sha256": self.binding_sha256}
        expected_names = {"owner.json", "owner.json.pending", "active.lock"}
        for key, md5 in member_md5.items():
            _hash(md5, _MD5)
            expected_names.update({self._name(*key), self._name(*key) + ".pending"})
        if self.root.exists() and not self.root.is_dir():
            _fail("root is not a directory")
        self.root.mkdir(parents=True, exist_ok=True)
        self._acquire()
        for path in self.root.iterdir():
            if path.name not in expected_names or path.is_symlink() or path.is_junction() or not path.is_file():
                _fail("root contains unexpected files or links")
        owner_path = safe_file(self.root, "owner.json")
        if owner_path.exists():
            if canonical(_read(owner_path, MAX_OWNER_BYTES)) != canonical(owner):
                _fail("owner build roots or binding changed")
        elif any(path.name != "active.lock" for path in self.root.iterdir()):
            _fail("owner missing in nonempty root")
        else:
            self._write(owner_path, owner, MAX_OWNER_BYTES)

    def _acquire(self):
        """Keep an OS lease; a crashed process cannot strand a PID lock."""
        lock = safe_file(self.root, "active.lock")
        self._lease = lock.open("a+b")
        if lock.stat().st_size == 0:
            self._lease.write(b"0")
            self._lease.flush()
        self._lease.seek(0)
        try:
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(self._lease.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(self._lease.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise ValueError("checkpoint directory has an active build lock") from exc

    def close(self):
        if self._lease is not None:
            self._lease.close()
            self._lease = None

    @staticmethod
    def _name(archive, member):
        return "member-" + _digest([archive, member]) + ".json"

    @staticmethod
    def _write(path, value, maximum):
        data = (canonical(value) + "\n").encode("utf-8")
        if len(data) > maximum:
            _fail("serialized state exceeds file bound")
        pending = safe_file(path.parent, path.name + ".pending")
        with pending.open("wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        pending.replace(path)

    def _record(self, event, key, archive, member, raw_rows):
        if (not isinstance(event, dict) or not _EVENT_REQUIRED <= set(event)
                or not set(event) <= AGENT_FIELDS or project_observations(event) != event):
            _fail("record projection fields differ")
        source, host, start, _kind = key
        if (event["archive"] != archive or event["relative_log_path"] != member
                or event["source"] != source or event["host"] != host
                or event["dataset_id"] != "dedale-v2.1"):
            _fail("record identity or provenance differs")
        line = _count(event["line_number"])
        if not 1 <= line <= raw_rows:
            _fail("record line outside raw member")
        expected_id = "dedale:" + _digest(["dedale-v2.1", archive, member, line])
        if event["external_id"] != expected_id:
            _fail("record external ID differs from provenance")
        _hash(event["raw_line_sha256"])
        _hash(event["event_fingerprint"])
        try:
            observed = utc(_text(event["observed_at"]))
            if (event["observed_at"] != _utc_timestamp(event["original_timestamp"])
                    or event["timestamp"] != event["observed_at"]
                    or event["@timestamp"] != event["observed_at"]):
                _fail("record timestamps differ")
        except (ValueError, OverflowError) as exc:
            raise ValueError("checkpoint record has invalid timestamp") from exc
        if not utc(start) <= observed < utc(start) + timedelta(seconds=1800):
            _fail("record outside window")
        if not self.policy.boundary <= observed < self.policy.end:
            _fail("record outside test period")
        if event["severity"] not in {"info", "low", "medium", "high", "critical"}:
            _fail("record severity differs")
        _text(event["event_type"], limit=128)
        if event["source_event_id"] is not None:
            _text(event["source_event_id"])
        if not isinstance(event["message"], str) or len(event["message"]) > 8192:
            _fail("record message exceeds bound")
        for name in ("process", "parent", "network", "winlog"):
            if name in event and (not isinstance(event[name], dict) or not event[name]):
                _fail("record nested observation has invalid shape")
        if "user" in event and (not isinstance(event["user"], (str, dict)) or not event["user"]):
            _fail("record user has invalid shape")
        for name in ("command_line", "username", "original_severity"):
            if name in event:
                _text(event[name])
        for name in ("source_ip", "destination_ip"):
            if name in event:
                try:
                    if str(ipaddress.ip_address(_text(event[name]))) != event[name]:
                        _fail("record network address differs")
                except ValueError as exc:
                    raise ValueError("checkpoint invalid record network address") from exc
        for name in ("source_port", "destination_port"):
            if name in event and (type(event[name]) is not int or not 0 <= event[name] <= 65535):
                _fail("record network port differs")
        if "projection_truncated" in event or "projection_truncated_fields" in event:
            fields = event.get("projection_truncated_fields")
            if (event.get("projection_truncated") is not True or not isinstance(fields, list)
                    or not fields or any(not isinstance(item, str) for item in fields)
                    or fields != sorted(set(fields))):
                _fail("record projection truncation metadata differs")
        for name, value in event.items():
            if isinstance(value, str) and name != "message" and len(value) > 4096:
                _fail("record scalar exceeds bound")
            if isinstance(value, dict):
                if name not in NESTED_FIELDS or not set(value) <= NESTED_FIELDS[name]:
                    _fail("record nested fields differ")
                for field, item in value.items():
                    if isinstance(item, str) and len(item) > 4096:
                        _fail("record nested scalar exceeds bound")
                    if isinstance(item, list) and (field != "args" or len(item) > 64
                                                 or any(not isinstance(arg, str) or len(arg) > 1024 for arg in item)):
                        _fail("record arguments exceed bound")
            elif isinstance(value, list):
                if (name != "projection_truncated_fields" or len(value) > 64
                        or any(not isinstance(field, str) or len(field) > 4096 for field in value)):
                    _fail("record list exceeds bound")
        return observed

    def _decode_state(self, value, archive, member):
        _fields(value, _STATE_FIELDS, "state")
        if (value["archive"] != archive or value["member"] != member
                or value["completed"] is not True or value["jsonl_md5_verified"] is not True):
            _fail("incomplete or mismatched member")
        source = ARCHIVE_SOURCES[archive]
        stats = _counter(value["stats"], allowed=_STATS)
        if not {"raw_rows", "parsed_rows", "invalid_rows"} <= set(stats):
            _fail("missing row counters")
        if stats["raw_rows"] != stats["parsed_rows"] + stats["invalid_rows"]:
            _fail("raw/parsed/invalid counts differ")
        hosts, days = _counter(value["hosts"]), _counter(value["days"])
        original_labels = _counter(value["original_labels"], allowed=_LABELS)
        if any(count == 0 for counter in (hosts, days, original_labels) for count in counter.values()):
            _fail("aggregate counter contains unobserved keys")
        if any(sum(counter.values()) != stats["parsed_rows"] for counter in (hosts, days, original_labels)):
            _fail("aggregate row counts differ")
        for host in hosts:
            if not host.startswith(source + ":"):
                _fail("host source differs")
            _text(host[len(source) + 1:])
        for day in days:
            if (len(day) != 10 or _timestamp(day + "T00:00:00Z").date().isoformat() != day):
                _fail("invalid UTC day")
        minimum = _timestamp(value["minimum"]) if value["minimum"] is not None else None
        maximum = _timestamp(value["maximum"]) if value["maximum"] is not None else None
        if stats["parsed_rows"]:
            if minimum is None or maximum is None or minimum > maximum:
                _fail("invalid observed bounds")
            if (minimum.date().isoformat() not in days or maximum.date().isoformat() not in days
                    or any(not minimum.date().isoformat() <= day <= maximum.date().isoformat() for day in days)):
                _fail("UTC days disagree with observed bounds")
        elif minimum is not None or maximum is not None:
            _fail("empty member has observed bounds")
        matched = value["matched_labels"]
        if not isinstance(matched, list) or len(matched) > len(self.labels.entries):
            _fail("invalid matched label set")
        matched_set, matched_counts = set(), Counter()
        for row in matched:
            if not isinstance(row, list) or len(row) != 2 or row[0] != source:
                _fail("invalid matched label identity")
            key = (source, _hash(row[1]))
            if key in matched_set or key not in self.labels.entries:
                _fail("duplicate or unknown matched label")
            entry = self.labels.entries[key]
            timestamp = utc(entry["timestamp"])
            if (minimum is None or not minimum <= timestamp <= maximum
                    or hosts[f"{source}:{entry['host']}"] < 1
                    or days[timestamp.date().isoformat()] < 1):
                _fail("matched label disagrees with raw member bounds")
            matched_set.add(key)
            matched_counts[entry["label"]] += 1
        if any(count > original_labels[label] for label, count in matched_counts.items()):
            _fail("matched labels exceed label row counts")
        eligible = stats["parsed_rows"] - sum(stats[name] for name in (
            "outside_period_rows", "calibration_rows", "excluded_host_rows"))
        if eligible < 0:
            _fail("period/scope counters exceed parsed rows")
        raw_windows = value["windows"]
        maximum_windows = 14 * 48 * len(EXHAUSTIVE_HOSTS[source]) + len(self.policy.registered_attack_keys)
        if not isinstance(raw_windows, list) or len(raw_windows) > maximum_windows:
            _fail("window collection exceeds registered bounds")
        windows, grid_rows, provenance = {}, 0, {}
        for row in raw_windows:
            _fields(row, {"key", "raw_count", "labels", "records", "duplicate_retained_rows"}, "window")
            key = row["key"]
            if (not isinstance(key, list) or len(key) != 4
                    or not all(isinstance(item, str) for item in key)):
                _fail("invalid window key")
            key = tuple(key)
            if key in windows or key[0] != source or key[1] not in EXHAUSTIVE_HOSTS[source]:
                _fail("duplicate or out of scope window")
            start = _timestamp(key[2])
            if key[3] == "grid":
                if key[2] != window_start(key[2]) or not self.policy.boundary <= start < self.policy.end:
                    _fail("grid window outside preregistered policy")
                grid_rows += _count(row["raw_count"])
            elif key[3] != "attack" or key not in self.policy.registered_attack_keys:
                _fail("unregistered attack window")
            raw_count, duplicates = _count(row["raw_count"]), _count(row["duplicate_retained_rows"])
            labels = _counter(row["labels"], allowed=_LABELS - {"unscorable"})
            records = row["records"]
            if (raw_count == 0 or raw_count > hosts[f"{source}:{key[1]}"]
                    or sum(labels.values()) != raw_count or not isinstance(records, list)
                    or not 1 <= len(records) <= min(raw_count, self.splits["max_records"])
                    or duplicates > raw_count - len(records) or any(count == 0 for count in labels.values())):
                _fail("window counts or projection bound differ")
            decoded, kept, retained_labels, previous = [], set(), Counter(), None
            for record in records:
                _fields(record, {"order", "event", "label"}, "retained record")
                event, label, order = record["event"], record["label"], record["order"]
                observed = self._record(event, key, archive, member, stats["raw_rows"])
                identity = event["external_id"]
                representation = canonical([event, label])
                if identity in provenance and provenance[identity] != representation:
                    _fail("record provenance has conflicting projections")
                provenance[identity] = representation
                if observed < minimum or observed > maximum:
                    _fail("retained timestamp outside observed bounds")
                if (not isinstance(order, list) or len(order) != 2
                        or order != [stamp(observed), event["external_id"]]):
                    _fail("record sort key differs")
                native_order = (observed, event["external_id"])
                if previous is not None and native_order <= previous:
                    _fail("records are not strictly ordered")
                previous = native_order
                fingerprint = event["event_fingerprint"]
                if fingerprint in kept or label != self.labels.classify(source, fingerprint, host=key[1]):
                    _fail("record fingerprint or label differs")
                if (source, fingerprint) in self.labels.entries:
                    entry = self.labels.entries[(source, fingerprint)]
                    if ((source, fingerprint) not in matched_set or entry["host"] != key[1]
                            or entry["timestamp"] != event["original_timestamp"]):
                        _fail("retained positive label provenance differs")
                kept.add(fingerprint)
                retained_labels[label] += 1
                decoded.append((native_order, event, label))
            if any(count > labels[label] for label, count in retained_labels.items()):
                _fail("retained label counts exceed raw labels")
            windows[key] = {"raw_count": raw_count, "labels": labels, "records": decoded,
                            "kept": kept, "duplicate_retained_rows": duplicates}
        if grid_rows != eligible:
            _fail("window counts do not cover eligible parsed rows")
        errors = value["invalid_examples"]
        if not isinstance(errors, list) or len(errors) != min(20, stats["invalid_rows"]):
            _fail("invalid example bound differs")
        previous = 0
        for error in errors:
            _fields(error, {"archive", "relative_log_path", "line_number", "error_code"}, "invalid example")
            line = _count(error["line_number"])
            if (error["archive"] != archive or error["relative_log_path"] != member
                    or not previous < line <= stats["raw_rows"]
                    or not isinstance(error["error_code"], str)
                    or re.fullmatch(r"INVALID_[A-Z_]{1,80}", error["error_code"]) is None):
                _fail("invalid example provenance differs")
            previous = line
        return {"archive": archive, "member": member, "completed": True,
                "jsonl_md5_verified": True, "windows": windows, "stats": stats,
                "hosts": hosts, "days": days, "original_labels": original_labels,
                "matched_labels": matched_set, "minimum": minimum, "maximum": maximum,
                "invalid_examples": errors}

    def load(self, task):
        archive, member = Path(task[0]).name, task[1]
        if (archive, member) not in self.member_md5:
            _fail("task is not in the verified member manifest")
        path = safe_file(self.root, self._name(archive, member))
        if not path.exists():
            # A .pending file never proves completion; the member is reread.
            return None
        envelope = _read(path, MAX_CHECKPOINT_BYTES)
        _fields(envelope, {"schema_version", "binding", "archive", "member",
                           "jsonl_md5", "state", "payload_sha256"}, "envelope")
        payload = {key: value for key, value in envelope.items() if key != "payload_sha256"}
        if (type(envelope["schema_version"]) is not int or envelope["schema_version"] != SCHEMA_VERSION
                or canonical(envelope["binding"]) != canonical(self.binding)
                or envelope["archive"] != archive or envelope["member"] != member
                or envelope["jsonl_md5"] != self.member_md5[(archive, member)]
                or _hash(envelope["payload_sha256"]) != _digest(payload)):
            _fail("binding, source member, or payload checksum differs")
        return self._decode_state(envelope["state"], archive, member)

    def save(self, state):
        archive, member = state["archive"], state["member"]
        if (archive, member) not in self.member_md5:
            _fail("result is not in the verified member manifest")
        value = _json_state(state)
        _tree(value)
        self._decode_state(value, archive, member)
        existing = self.load((archive, member))
        if existing is not None:
            if canonical(_json_state(existing)) != canonical(value):
                _fail("completed member state changed")
            return
        payload = {"schema_version": SCHEMA_VERSION, "binding": self.binding,
                   "archive": archive, "member": member,
                   "jsonl_md5": self.member_md5[(archive, member)], "state": value}
        self._write(safe_file(self.root, self._name(archive, member)),
                    {**payload, "payload_sha256": _digest(payload)}, MAX_CHECKPOINT_BYTES)

    def verify_code_unchanged(self):
        if code_hashes() != self.binding["code_sha256"]:
            _fail("preparation code changed during scan")
