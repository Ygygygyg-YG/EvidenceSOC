"""Separate scoring-side reads over sealed attempts and frozen applicable gold."""

from __future__ import annotations

from datetime import datetime
from math import isfinite
from pathlib import Path

from evals.contracts import GROUPS, canonical_hash
from evals.datasets.dedale.common import read_json, safe_file
from evals.metrics import score_rows
from evals.metrics.classification import SIX_CLASSES
from evals.runners.execute import collect_rows
from evals.runners.manifest import file_hash, validate_plan, write_immutable_json


def load_gold(case_dir: Path, dataset: str) -> tuple[dict, dict, dict]:
    root = safe_file(Path(case_dir), "scoring")
    manifest = read_json(safe_file(root, "manifest.json"))
    gold_path = safe_file(root, "gold.jsonl")
    import json

    events = [
        json.loads(line)
        for line in gold_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    for relative, digest in manifest.get("artifacts", {}).items():
        if file_hash(safe_file(Path(case_dir), relative)) != digest:
            raise ValueError("frozen scoring artifact hash mismatch")
    if dataset == "dedale":
        truth = manifest.get("case_is_attack")
        mask = manifest.get("case_applicability", {})
        if (
            type(truth) is not bool
            or mask.get("attack_binary") is not True
            or any(
                mask.get(key) is not False
                for key in ["six_class", "techniques", "phases", "origin"]
            )
        ):
            raise ValueError(
                "DEDALE requires explicit package truth and frozen fine-label masks"
            )
        gold = {
            "is_attack": truth,
            "attack_types": [],
            "technique_ids": [],
            "stage_instances": [],
            "precedes": [],
        }
    else:
        labels = [row.get("is_attack") for row in events]
        truth = (
            True
            if any(value is True for value in labels)
            else False
            if labels and all(value is False for value in labels)
            else None
        )
        types = sorted(
            {
                label
                for row in events
                for label in row.get("attack_types", [])
                if label in SIX_CLASSES
            }
        )
        gold = {
            "is_attack": truth,
            "attack_types": types,
            "technique_ids": [],
            "stage_instances": [],
            "precedes": [],
        }
        # Fine labels are only the mapped frozen six classes. No ATT&CK/stage
        # truth is manufactured from attack type names or temporal log order.
        mask = {
            "attack_binary": type(truth) is bool,
            "six_class": truth is False or bool(types),
            "techniques": False,
            "phases": False,
            "origin": False,
        }
    return (
        gold,
        mask,
        {
            "scoring_manifest": file_hash(root / "manifest.json"),
            "gold": file_hash(gold_path),
        },
    )


def _known_sum(values, *, tokens=False):
    values = list(values)
    if not values or any(
        not isinstance(value, int if tokens else (int, float))
        or isinstance(value, bool)
        or value < 0
        or (isinstance(value, float) and not isfinite(value))
        for value in values
    ):
        return None
    total = sum(values)
    return total if isinstance(total, int) or isfinite(total) else None


def _usage_value(call, key):
    usage = call.get("usage")
    return usage.get(key) if isinstance(usage, dict) else None


def _resources(attempts):
    results = [attempt["result"] for attempt in attempts if attempt["result"]]
    calls = [call for result in results for call in result.get("model_ledger", [])]
    tools = [call for result in results for call in result.get("tool_ledger", [])]
    per_attempt = []
    for attempt in attempts:
        result = attempt["result"] or {}
        ledger = result.get("model_ledger", [])
        if ledger:
            per_attempt.append(
                {
                    "input_tokens": _known_sum(
                        (_usage_value(call, "prompt_tokens") for call in ledger),
                        tokens=True,
                    ),
                    "output_tokens": _known_sum(
                        (_usage_value(call, "completion_tokens") for call in ledger),
                        tokens=True,
                    ),
                    "cost": _known_sum(call.get("cost_cny") for call in ledger),
                }
            )
        else:
            per_attempt.append(result.get("resources", {}))
    if results:
        usage = {
            key: _known_sum((item.get(key) for item in per_attempt), tokens=key != "cost")
            for key in ["input_tokens", "output_tokens", "cost"]
        }
    else:
        usage = None
    grouped = {}
    for index, call in enumerate(calls):
        identity = call.get("logical_call_id", f"unbound-physical-{index}")
        grouped.setdefault(
            identity, {"logical_call_id": identity, "physical_attempts": 0}
        )["physical_attempts"] += 1
    latencies = []
    for attempt in attempts:
        record = attempt["record"]
        if record.get("started_at") and record.get("finished_at"):
            latencies.append(
                (
                    datetime.fromisoformat(record["finished_at"])
                    - datetime.fromisoformat(record["started_at"])
                ).total_seconds()
                * 1000
            )
    latency = sum(latencies) if latencies and len(latencies) == len(attempts) else None
    return usage, list(grouped.values()), tools, latency


def _resource_coverage(attempts):
    """Keep observed physical usage even when the complete row total is unknown.

    Legacy attempt summaries are counted separately from physical requests. An
    interrupted attempt has unknown usage, never an invented zero-cost request.
    """
    keys = ("input_tokens", "output_tokens", "cost")
    values = {key: [] for key in keys}
    missing = dict.fromkeys(keys, 0)
    physical_n = legacy_n = missing_attempts = 0
    for attempt in attempts:
        result = attempt.get("result") or {}
        ledger = result.get("model_ledger")
        if ledger:
            physical_n += len(ledger)
            for call in ledger:
                observed = {
                    "input_tokens": _usage_value(call, "prompt_tokens"),
                    "output_tokens": _usage_value(call, "completion_tokens"),
                    "cost": call.get("cost_cny"),
                }
                for key, value in observed.items():
                    if _known_sum([value], tokens=key != "cost") is None:
                        missing[key] += 1
                    else:
                        values[key].append(value)
        elif result.get("resources"):
            legacy_n += 1
            for key in keys:
                value = result["resources"].get(key)
                if _known_sum([value], tokens=key != "cost") is not None:
                    values[key].append(value)
        else:
            missing_attempts += 1
    return {
        "known_subtotals": {
            key: _known_sum(items, tokens=key != "cost")
            for key, items in values.items()
        },
        "physical_requests_n": physical_n,
        "physical_missing_counts": missing,
        "legacy_summaries_n": legacy_n,
        "missing_attempts_n": missing_attempts,
    }


def _tool_ledger_complete(attempts) -> bool:
    if not attempts:
        return False
    for attempt in attempts:
        result = attempt["result"]
        if result is None:
            return False
        resources = result.get("resources", {})
        if "tool_ledger_complete" in resources:
            if resources["tool_ledger_complete"] is not True:
                return False
        elif not isinstance(result.get("tool_ledger"), list):
            return False
    return True


def score_plan(
    plan: dict,
    output_root: Path,
    *,
    reviews: dict | None = None,
    verification: dict | None = None,
) -> dict:
    validate_plan(plan)
    controller = plan["controller"]
    dataset = controller["dataset"]
    rows = collect_rows(plan, output_root)
    groups = {group: [] for group in GROUPS}
    source_hashes = {
        "plan": plan["plan_sha256"],
        "configuration": plan["config_sha256"],
        "selection": controller["selection_sha256"],
    }
    for row in rows:
        case_dir = safe_file(Path(controller["case_root"]), row["case_id"])
        for name, digest in row.get("scoring_hashes", {}).items():
            if file_hash(safe_file(case_dir, f"scoring/{name}")) != digest:
                raise ValueError("scoring input hash changed after planning")
        gold, mask, gold_hashes = load_gold(case_dir, dataset)
        result = row["result"] or {}
        usage, model_calls, tool_calls, latency = _resources(row["attempts"])
        agent_manifest = read_json(safe_file(case_dir, "agent/manifest.json"))
        groups[row["group"]].append(
            {
                "case_id": row["case_id"],
                "row_id": row["row_id"],
                "group_id": row["group"],
                "dataset": dataset,
                "scenario": agent_manifest.get("scenario", "unspecified"),
                "applicability": mask,
                "gold": gold,
                "diagnosis": result.get("diagnostic_snapshot"),
                "diagnosis_status": row["diagnosis_status"],
                "execution_status": row["execution_status"],
                "evidence_registry": result.get("evidence_registry", {}),
                "usage": usage,
                "resource_coverage": _resource_coverage(row["attempts"]),
                "model_calls": model_calls,
                "tool_calls": tool_calls,
                "tool_ledger_complete": _tool_ledger_complete(row["attempts"]),
                "latency_ms": latency,
                "human_review": (reviews or {}).get(row["row_id"]),
                "reserved_tool_slots": row["worker_spec"]["capabilities"][
                    "total_reserved_calls"
                ],
            }
        )
        source_hashes["gold:" + row["case_id"]] = canonical_hash(gold_hashes)
        for attempt in row["attempts"]:
            source_hashes[f"attempt:{row['row_id']}:{attempt['record']['attempt']}"] = (
                attempt["record"]["record_sha256"]
            )
    result = {
        "schema_version": 1,
        "run_id": controller["run_id"],
        "metadata": {
            "dataset": dataset,
            "split": controller["split"],
            "source_commit": controller["source_commit"],
            "requested_model": controller["model"]["requested_model"],
            "published_version": controller["model"]["published_version"],
            "protocol_sha256": None,
            "formal_complete": False,
            "score_status": "automatic_intermediate",
            "planned_n": len(rows),
            "human_metrics_scope": "Only imported, completed human review; otherwise null",
        },
        "groups": {
            dataset: {group: score_rows(values) for group, values in groups.items()}
        },
        "verification": verification or {},
        "source_hashes": source_hashes,
    }
    if (
        controller.get("freeze_manifest")
        and Path(controller["freeze_manifest"]).is_file()
    ):
        result["metadata"]["protocol_sha256"] = (
            read_json(Path(controller["freeze_manifest"]))
            .get("bindings", {})
            .get("protocol")
        )
    return result


def write_scores(plan: dict, output_root: Path, destination: Path, **kwargs) -> dict:
    result = score_plan(plan, output_root, **kwargs)
    write_immutable_json(destination, result)
    return result
