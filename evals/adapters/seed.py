"""Trusted raw-log projection. No scoring material or case title is read."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

from evidencesoc.ingestion.jsonl import ParsedLogRecord
from evidencesoc.ingestion.normalize import normalize_record

from evals.contracts import WorkerRunSpec, canonical_hash

FORBIDDEN = {
    "gold",
    "ground_truth",
    "is_attack",
    "case_is_attack",
    "attack_types",
    "dataset_labels",
    "labels",
    "label",
    "scoring",
    "expected_answer",
    "mapping_evidence",
    "taxonomy_version",
    "unmapped_labels",
    "normal_basis",
}
OBSERVABLE = {
    "source_ip",
    "destination_ip",
    "host",
    "service",
    "user",
    "username",
    "account",
    "http",
    "event_type",
    "observed_at",
    "source",
    "message",
}
ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def reject_answers(value):
    if isinstance(value, dict):
        if FORBIDDEN.intersection(value):
            raise ValueError("answer-bearing raw input is forbidden")
        for child in value.values():
            reject_answers(child)
    elif isinstance(value, list):
        for child in value:
            reject_answers(child)


def evidence_id(case_id: str, event_id: str) -> str:
    number = int.from_bytes(
        hashlib.sha256(f"{case_id}:{event_id}".encode()).digest()[:16], "big"
    )
    chars = []
    for _ in range(26):
        chars.append(ALPHABET[number & 31])
        number >>= 5
    return "EV-" + "".join(reversed(chars))


def _trim(value: str, limit: int) -> str:
    return value.encode()[:limit].decode("utf-8", errors="ignore")


def load_seed(spec: WorkerRunSpec, agent_dir: Path) -> dict:
    root = Path(agent_dir).resolve(strict=True)
    path = root / "events.jsonl"
    if path.is_symlink() or path.resolve(strict=True).parent != root:
        raise ValueError("agent input escapes case directory")
    events = []
    with path.open(encoding="utf-8") as stream:
        for line_no, line in enumerate(stream, 1):
            raw = json.loads(line)
            reject_answers(raw)
            when = datetime.fromisoformat(raw["observed_at"])
            if when.tzinfo is None:
                raise ValueError("source event timestamp needs timezone")
            event = normalize_record(
                ParsedLogRecord(raw, "agent/events.jsonl", line_no),
                event_id="SE-" + canonical_hash(raw)[:32],
                ingested_at=when.astimezone(UTC),
            )
            events.append(event.model_dump(mode="json"))
    if not events:
        raise ValueError("empty raw case")
    events.sort(key=lambda x: (x["observed_at"], x["event_id"]))
    if len({x["event_id"] for x in events}) != len(events):
        raise ValueError("duplicate event identity in raw case")
    evidence = []
    registry = {}
    used = 0
    for event in events[: spec.seed.max_events]:
        raw = event["raw"]
        summary = _trim(
            str(raw.get("message", event["event_type"])), spec.seed.max_event_bytes
        )
        observations = {key: raw[key] for key in OBSERVABLE if key in raw}
        if "message" in observations:
            observations["message"] = summary
        item = {
            "evidence_id": evidence_id(spec.case_id, event["event_id"]),
            "event_id": event["event_id"],
            "source": event["source"],
            "observed_at": event["observed_at"],
            "query": {
                "seed_rule": spec.seed.version,
                "matched_event_id": event["event_id"],
            },
            "summary": summary or "Observed event",
            "content_sha256": event["content_sha256"],
            "raw": observations,
        }
        length = len(json.dumps(item, ensure_ascii=False).encode())
        if used + length > spec.seed.max_total_bytes:
            break
        used += length
        evidence.append(item)
        registry[item["evidence_id"]] = {
            **item,
            "case_id": spec.case_id,
            "provenance": "raw_seed_v1",
        }
    if not evidence:
        raise ValueError("seed byte budget cannot fit first event")
    first = datetime.fromisoformat(events[0]["observed_at"])
    last = datetime.fromisoformat(events[-1]["observed_at"])
    center = first + (last - first) / 2
    alerts = [
        {
            "alert_id": "AL-" + canonical_hash([spec.run_id, spec.case_id])[:26],
            "title": "Observed security events",
            "severity": "info",
            "created_at": center.isoformat(),
            "event_ids": [x["event_id"] for x in evidence],
        }
    ]
    return {
        "events": events,
        "evidence": evidence,
        "registry": registry,
        "alerts": alerts,
        "seed_bytes": used,
        "input_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }
