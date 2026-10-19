"""Scoring-side preregistered sampling and validated human review imports."""

from __future__ import annotations

import json
import random
from datetime import datetime
from pathlib import Path

from evals.contracts import GROUPS, canonical_hash
from evals.metrics.evidence import ordered_citations


def _report(row):
    """Retain the sealed graph report, including its original reconstruction."""
    return (
        (row.get("result") or {}).get("diagnostic_snapshot")
        or row.get("diagnosis")
        or {}
    )


def _diagnosis(row):
    value = _report(row)
    return value.get("diagnosis", value) or {}


def report_claims(report: dict) -> list[dict]:
    """Enumerate actual native prose and typed assertions without judging them."""
    diagnosis = report.get("diagnosis", report) or {}
    claims = [dict(item) for item in diagnosis.get("claims", [])]
    used = {item["claim_id"] for item in claims}

    def identity_for(identity):
        while identity in used:
            identity = "@" + identity
        used.add(identity)
        return identity

    def add(name, value, references):
        claims.append({
            "claim_id": identity_for("typed:" + name),
            "text": name + " = " + json.dumps(value, ensure_ascii=False, sort_keys=True),
            "evidence_ids": list(references),
        })

    def add_fields(path, value):
        for key, item in value.items():
            if key not in {"evidence_ids", "knowledge_chunk_ids"} and item is not None:
                add(path + "." + key, item, value.get("evidence_ids", []))

    references = diagnosis.get("evidence_ids", [])
    if diagnosis.get("verdict") in {"attack", "benign"}:
        add("verdict", diagnosis["verdict"], references)
    if diagnosis.get("attack_types"):
        add("attack_types", diagnosis["attack_types"], references)
    if diagnosis.get("technique_ids"):
        add("technique_ids", diagnosis["technique_ids"], references)
    add_fields("origin", diagnosis.get("origin") or {})
    for index, stage in enumerate(diagnosis.get("stage_instances", [])):
        add("stage." + str(index), {key: value for key, value in stage.items() if key != "evidence_ids"}, stage.get("evidence_ids", []))
    if "diagnosis" in report:
        for section in ("origin", "classification"):
            add_fields("snapshot." + section, report.get(section) or {})
        for index, step in enumerate(report.get("attack_steps") or []):
            add_fields("snapshot.attack_steps." + str(index), step)
        for native in report.get("claims") or []:
            claims.append({**native, "claim_id": identity_for("snapshot:" + native["claim_id"])})
    return claims


def report_citations(report: dict) -> list[str]:
    """Canonical diagnosis order, then original graph report assertion order."""
    return ordered_citations(report)


def build_review_plan(rows: list[dict]) -> dict:
    cases = {}
    for row in rows:
        identity = (row["dataset"], row["case_id"])
        truth = row["gold"]["is_attack"]
        if type(truth) is not bool:
            raise ValueError(
                "review sampling needs controller-side known package truth"
            )
        if identity in cases and cases[identity] != truth:
            raise ValueError("inconsistent case truth across groups")
        cases[identity] = truth
    selected = []
    generator = random.Random(42)
    for dataset in ("ait", "dedale"):
        for truth in (True, False):
            population = sorted(
                case_id
                for (kind, case_id), value in cases.items()
                if kind == dataset and value == truth
            )
            if len(population) < 2:
                raise ValueError("need two attacks and two normal cases per dataset")
            selected.extend(
                (dataset, case_id) for case_id in generator.sample(population, 2)
            )
    slots = []
    for dataset, case_id in selected:
        found = [
            row
            for row in rows
            if row["dataset"] == dataset and row["case_id"] == case_id
        ]
        if sorted(row["group_id"] for row in found) != sorted(GROUPS):
            raise ValueError("all eight groups required in review sampling frame")
        for row in sorted(found, key=lambda x: GROUPS.index(x["group_id"])):
            slots.append(
                {
                    "slot_id": "review-"
                    + canonical_hash([42, dataset, case_id, row["group_id"]])[:24],
                    "row_id": row["row_id"],
                    "dataset": dataset,
                    "case_id": case_id,
                }
            )
    presentation_order = [slot["slot_id"] for slot in slots]
    random.Random(42).shuffle(presentation_order)
    return {
        "schema_version": "task13-review-v1",
        "seed": 42,
        "underlying_cases": 8,
        "planned_slots": 64,
        "reviewer": "user",
        "review_window": "19:00-00:00 Asia/Shanghai",
        "slots": slots,
        "presentation_order": presentation_order,
    }


def _presentation_order(plan):
    order = plan.get("presentation_order")
    registered = [slot["slot_id"] for slot in plan["slots"]]
    if (
        not isinstance(order, list)
        or len(order) != 64
        or len(set(order)) != 64
        or set(order) != set(registered)
    ):
        raise ValueError("presentation order must retain each of the 64 registered slots exactly once")
    return order


def blinded_bundle(plan: dict, rows: list[dict]) -> dict:
    lookup = {row["row_id"]: row for row in rows}
    slots = {slot["slot_id"]: slot for slot in plan["slots"]}
    records = []
    for slot_id in _presentation_order(plan):
        slot = slots[slot_id]
        row = lookup[slot["row_id"]]
        report = _report(row)
        records.append(
            {
                "slot_id": slot["slot_id"],
                "claims": report_claims(report),
                "report_sha256": canonical_hash(report),
                "evidence_ids": list(dict.fromkeys(report_citations(report))),
                "evidence_registry": row.get(
                    "evidence_registry",
                    (row.get("result") or {}).get("evidence_registry", {}),
                ),
                "reviewed_at": None,
                "relevance": {},
                "review_status": "pending",
                "unavailable_reason": "no_report" if not report else None,
            }
        )
    return {
        "schema_version": "task13-blinded-review-v1",
        "review_plan_sha256": canonical_hash(plan),
        "reviewer": plan["reviewer"],
        "records": records,
    }


def validated_reviews(path: Path, rows: list[dict]) -> dict[str, dict]:
    envelope = json.loads(Path(path).read_text(encoding="utf-8"))
    plan = json.loads(Path(envelope["review_plan"]).read_text(encoding="utf-8"))
    if envelope.get("review_plan_sha256") != canonical_hash(plan):
        raise ValueError("review plan hash differs from preregistration")
    if (
        plan.get("schema_version") != "task13-review-v1"
        or plan.get("planned_slots") != 64
        or len(plan.get("slots", [])) != 64
    ):
        raise ValueError("review plan must retain all64 preregistered slots")
    if envelope.get("reviewer") != "user" or plan.get("reviewer") != "user":
        raise ValueError("only the registered human reviewer may provide judgments")
    slots = {item["slot_id"]: item for item in plan["slots"]}
    if len(slots) != 64:
        raise ValueError("duplicate review slots")
    _presentation_order(plan)
    lookup = {row["row_id"]: row for row in rows}
    datasets = {row.get("dataset") for row in rows if row.get("dataset")}
    if not datasets:
        datasets = {
            slot["dataset"] for slot in slots.values() if slot["row_id"] in lookup
        }
    results = {}
    seen = set()
    for record in envelope.get("records", []):
        slot_id = record["slot_id"]
        if slot_id not in slots or slot_id in seen:
            raise ValueError("unregistered or duplicate review slot")
        seen.add(slot_id)
        row_id = slots[slot_id]["row_id"]
        if row_id not in lookup and slots[slot_id]["dataset"] not in datasets:
            continue  # other dataset is independently validated in its scoring process
        if row_id not in lookup:
            raise ValueError("review row is not part of this scoring plan")
        row = lookup[row_id]
        if row.get("case_id") != slots[slot_id]["case_id"]:
            raise ValueError("review case binding differs")
        report = _report(row)
        claims = report_claims(report)
        expected = {claim["claim_id"] for claim in claims}
        judgments = record.get("claims", [])
        actual = [item["claim_id"] for item in judgments]
        if set(actual) != expected or len(actual) != len(expected):
            raise ValueError("all actual claims must be reviewed exactly once")
        if record.get("report_sha256") != canonical_hash(report):
            raise ValueError("human review report hash does not match sealed report")
        timestamp = datetime.fromisoformat(record["reviewed_at"])
        if timestamp.tzinfo is None:
            raise ValueError("human review requires an aware timestamp")
        for judgment in judgments:
            if (
                judgment.get("judgment")
                not in {"supported", "unsupported", "uncertain", "undetermined"}
                or not judgment.get("basis", "").strip()
            ):
                raise ValueError(
                    "human claim judgment requires status and source basis"
                )
        references = list(dict.fromkeys(report_citations(report)))[:5]
        relevance = record.get("relevance", {})
        if set(relevance) != set(references) or any(
            value
            not in {
                "supported",
                "relevant",
                "uncertain",
                "undetermined",
                "irrelevant",
                "unsupported",
            }
            for value in relevance.values()
        ):
            raise ValueError("all actual top5 citations need human relevance judgments")
        if not report or not claims:
            if record.get("unavailable_reason") not in {
                "no_report",
                "no_factual_claims",
                "diagnostic_failure",
            }:
                raise ValueError("empty report/claims needs objective retained reason")
            results[row_id] = {
                "reviewed": False,
                "reason": record["unavailable_reason"],
                "slot_id": slot_id,
            }
        else:
            results[row_id] = {
                "reviewed": True,
                "reviewer": "user",
                "reviewed_at": record["reviewed_at"],
                "claims": judgments,
                "relevance": relevance,
                "slot_id": slot_id,
                "underlying_case": slots[slot_id]["case_id"],
            }
    return results
