"""Scoring-only joins for the four original DEDALE system-label subsets.

No label is inferred from a command, path, message, timestamp, or attack rule.
Class membership is determined from the complete canonical event object.
"""

from __future__ import annotations

import hashlib
import json
import re
import zipfile
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

# Malformed external JSON consistently raises ValueError at this boundary.
# ruff: noqa: TRY004

OFFICIAL_ARCHIVE_SIZE = 2_669_407
OFFICIAL_ARCHIVE_MD5 = "455d0a7042531eff74285006f97822e4"

# This is the documented scope of the supplied system ground truth. Other
# providers and hosts require another policy; absence is not benign evidence.
EXHAUSTIVE_HOSTS = {
    "winlogbeat": frozenset({"CLIENT1.breach.local", "CLIENT2.breach.local"}),
    "auditbeat": frozenset({"internalserver"}),
}
LABEL_MEMBERS = {
    "system_labels/clients_1_and_2/malicious_events_class_1.jsonl": (
        "winlogbeat",
        "class_1",
    ),
    "system_labels/clients_1_and_2/malicious_events_class_1_and_2.jsonl": (
        "winlogbeat",
        "class_1_and_2",
    ),
    "system_labels/internal_server/malicious_events_class_1.jsonl": (
        "auditbeat",
        "class_1",
    ),
    "system_labels/internal_server/malicious_events_class_1_and_2.jsonl": (
        "auditbeat",
        "class_1_and_2",
    ),
}


def canonical_event_fingerprint(event: Mapping[str, Any]) -> str:
    """Hash a raw source object independently of JSON key/whitespace ordering."""
    if not isinstance(event, Mapping):
        raise ValueError("event must be a JSON object")
    try:
        payload = json.dumps(
            dict(event),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, UnicodeError) as exc:
        raise ValueError("event is not canonical JSON") from exc
    return hashlib.sha256(payload).hexdigest()


def _object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _reject_constant(value: str) -> None:
    raise ValueError(f"nonfinite JSON constant: {value}")


def _field(event: Mapping[str, Any], group: str, key: str) -> Any:
    value = event.get(group)
    return value.get(key) if isinstance(value, Mapping) else None


def _identity(event: dict[str, Any], source: str) -> tuple[Any, ...]:
    """Use native record identity to detect contradictory copies of an event.

    Timestamp and agent identity distinguish event-log resets or audit-sequence
    reuse across sessions. A source-object fingerprint remains the join key.
    """
    if _field(event, "agent", "type") != source:
        raise ValueError("label source does not match its archive member")
    host = _field(event, "host", "name")
    if not isinstance(host, str) or host not in EXHAUSTIVE_HOSTS[source]:
        raise ValueError("label host is outside the verified source/host scope")
    agent_id = _field(event, "agent", "id")
    timestamp = event.get("@timestamp")
    if not isinstance(agent_id, str) or not agent_id:
        raise ValueError("label event is missing agent.id")
    if not isinstance(timestamp, str):
        raise ValueError("label event is missing @timestamp")
    try:
        parsed = datetime.fromisoformat(timestamp)
    except ValueError as exc:
        raise ValueError("label @timestamp is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("label @timestamp must have an explicit timezone")
    if source == "winlogbeat":
        sequence = _field(event, "winlog", "record_id")
        channel = _field(event, "winlog", "channel")
        if not isinstance(channel, str) or not channel:
            raise ValueError("label event is missing winlog.channel")
    else:
        sequence = _field(event, "auditd", "sequence")
        channel = None
    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 0:
        raise ValueError("label event is missing a valid native record identity")
    return source, host, agent_id, timestamp, channel, sequence


@dataclass(frozen=True)
class LabelIndex:
    """A complete in-memory index, retained only on the scoring side."""

    class_1: dict[str, frozenset[str]]
    class_1_and_2: dict[str, frozenset[str]]
    fingerprint_hosts: dict[str, dict[str, str]]
    entries: dict[tuple[str, str], dict[str, Any]]
    official_verified: bool
    exhaustive: bool
    summary: dict[str, Any]

    def classify(
        self, source: str, fingerprint: str, *, host: str | None = None
    ) -> str:
        """Retain unknowns unless integrity, provider, host and policy agree."""
        if (
            not isinstance(source, str)
            or source not in EXHAUSTIVE_HOSTS
            or not isinstance(fingerprint, str)
            or (host is not None and not isinstance(host, str))
        ):
            return "unscorable"
        if re.fullmatch(r"[0-9a-f]{64}", fingerprint) is None:
            return "unscorable"
        known_host = self.fingerprint_hosts[source].get(fingerprint)
        if known_host is not None:
            if host is not None and host != known_host:
                return "unscorable"
            if fingerprint in self.class_1[source]:
                return "malicious"
            return "malicious-related"
        if any(fingerprint in values for values in self.class_1_and_2.values()):
            return "unscorable"
        if (
            self.official_verified
            and self.exhaustive
            and host in EXHAUSTIVE_HOSTS[source]
        ):
            return "benign"
        return "unscorable"

    def iter_labeled_events(self) -> Iterator[dict[str, Any]]:
        """Yield minimal unique entries for the builder's coverage ledger."""
        for key in sorted(self.entries):
            entry = self.entries[key]
            yield {**entry, "locations": list(entry["locations"])}


def load_label_index(archive_path: Path, *, exhaustive: bool = False) -> LabelIndex:
    """Read every label member and CRC before permitting any negative label.

    A structurally valid local fixture can be read without official integrity,
    but ``official_verified`` remains false and unmatched events are unscorable.
    Production dataset freezes must reject such an index.
    """
    if not isinstance(exhaustive, bool):
        raise ValueError("exhaustive must be an explicit boolean policy")
    archive_path = Path(archive_path)
    with archive_path.open("rb") as handle:
        actual_md5 = hashlib.file_digest(handle, "md5").hexdigest()
    actual_size = archive_path.stat().st_size
    official_verified = (
        actual_size == OFFICIAL_ARCHIVE_SIZE and actual_md5 == OFFICIAL_ARCHIVE_MD5
    )
    groups = {
        source: {"class_1": set(), "class_1_and_2": set()}
        for source in EXHAUSTIVE_HOSTS
    }
    hosts: dict[str, dict[str, str]] = {source: {} for source in EXHAUSTIVE_HOSTS}
    identities: dict[tuple[Any, ...], str] = {}
    member_counts: dict[str, Any] = {}
    entries: dict[tuple[str, str], dict[str, Any]] = {}
    duplicate_rows = 0
    try:
        with zipfile.ZipFile(archive_path) as archive:
            members = [info.filename for info in archive.infolist()]
            if len(members) != len(set(members)):
                raise ValueError("duplicate ZIP member names")
            if set(LABEL_MEMBERS) - set(members):
                raise ValueError("missing required label archive member")
            if {name for name in members if name.endswith(".jsonl")} != set(
                LABEL_MEMBERS
            ):
                raise ValueError("unexpected label JSONL archive member")
            bad_member = archive.testzip()
            if bad_member is not None:
                raise ValueError(f"CRC integrity failure: {bad_member}")
            for member, (source, group) in LABEL_MEMBERS.items():
                seen: set[str] = set()
                rows = 0
                with archive.open(member) as handle:
                    for line_number, raw in enumerate(handle, 1):
                        try:
                            event = json.loads(
                                raw.decode("utf-8"),
                                object_pairs_hook=_object_pairs,
                                parse_constant=_reject_constant,
                            )
                        except (UnicodeError, ValueError) as exc:
                            raise ValueError(
                                f"invalid label JSON in {member}:{line_number}"
                            ) from exc
                        if not isinstance(event, dict):
                            raise ValueError("label event must be a JSON object")
                        identity = _identity(event, source)
                        fingerprint = canonical_event_fingerprint(event)
                        previous = identities.setdefault(identity, fingerprint)
                        if previous != fingerprint:
                            raise ValueError(
                                "conflicting content for the same label event identity"
                            )
                        if fingerprint in seen:
                            duplicate_rows += 1
                        seen.add(fingerprint)
                        groups[source][group].add(fingerprint)
                        hosts[source][fingerprint] = event["host"]["name"]
                        entry = entries.setdefault(
                            (source, fingerprint),
                            {
                                "source": source,
                                "fingerprint": fingerprint,
                                "host": event["host"]["name"],
                                "timestamp": event["@timestamp"],
                                "label": None,
                                "locations": [],
                            },
                        )
                        entry["locations"].append(f"{member}:{line_number}")
                        rows += 1
                member_counts[member] = {
                    "rows": rows,
                    "unique_events": len(seen),
                    "duplicate_rows": rows - len(seen),
                }
    except (zipfile.BadZipFile, EOFError, RuntimeError) as exc:
        raise ValueError("label archive integrity/CRC validation failed") from exc
    for source, values in groups.items():
        if not values["class_1"] <= values["class_1_and_2"]:
            raise ValueError(f"{source} class_1 is not a subset of class_1_and_2")
    for (source, fingerprint), entry in entries.items():
        entry["label"] = (
            "malicious"
            if fingerprint in groups[source]["class_1"]
            else "malicious-related"
        )
    summary = {
        "archive_md5": actual_md5,
        "archive_size": actual_size,
        "official_verified": official_verified,
        "crc_complete": True,
        "labels_complete_read": True,
        "exhaustive_policy_requested": exhaustive,
        "negative_policy": "official-complete-known-source-host"
        if exhaustive and official_verified
        else "unknown",
        "duplicate_rows": duplicate_rows,
        "members": member_counts,
        "sources": {
            source: {
                "malicious": len(values["class_1"]),
                "malicious-related": len(values["class_1_and_2"] - values["class_1"]),
                "union": len(values["class_1_and_2"]),
            }
            for source, values in groups.items()
        },
    }
    return LabelIndex(
        class_1={
            source: frozenset(values["class_1"]) for source, values in groups.items()
        },
        class_1_and_2={
            source: frozenset(values["class_1_and_2"])
            for source, values in groups.items()
        },
        fingerprint_hosts=hosts,
        entries=entries,
        official_verified=official_verified,
        exhaustive=exhaustive,
        summary=summary,
    )


def join_event(
    event: Mapping[str, Any],
    index: LabelIndex,
    *,
    source_file: str | None = None,
    line_number: int | None = None,
) -> dict[str, Any]:
    """Return isolated scoring metadata without copying observable payloads."""
    if line_number is not None and (
        isinstance(line_number, bool)
        or not isinstance(line_number, int)
        or line_number < 1
    ):
        raise ValueError("line_number must be a positive integer")
    source_event = event.get("_source", event)
    if not isinstance(source_event, Mapping):
        raise ValueError("event must contain a JSON source object")
    fingerprint = canonical_event_fingerprint(source_event)
    source = _field(source_event, "agent", "type")
    host = _field(source_event, "host", "name")
    return {
        "label": index.classify(source, fingerprint, host=host),
        "source": source,
        "host": host,
        "timestamp": source_event.get("@timestamp"),
        "fingerprint": fingerprint,
        "source_file": source_file,
        "line_number": line_number,
    }
