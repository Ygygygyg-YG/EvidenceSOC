"""Immutable controller plans and fail-closed formal admission checks."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from evals.contracts import GROUPS, ControllerRunSpec, WorkerRunSpec, canonical_hash
from evals.datasets.dedale.common import read_json, safe_file
from evals.freeze import (
    accepted_isolation_receipt,
    validate_committed_sources,
    validate_freeze_file_coverage,
)

ROOT = Path(__file__).resolve().parents[2]
NEUTRAL_CASE = re.compile(r"(?:ait-[0-9a-f]{24}|dedale-[0-9a-f]{16})\Z")


def file_hash(path: Path) -> str:
    with Path(path).open("rb") as stream:
        import hashlib

        return hashlib.file_digest(stream, "sha256").hexdigest()


def write_immutable_json(path: Path, value: Any) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = (
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    )
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(payload)
        stream.flush()
        import os

        os.fsync(stream.fileno())


def agent_input(case_root: Path, case_id: str) -> tuple[Path, dict[str, str]]:
    if not NEUTRAL_CASE.fullmatch(case_id):
        raise ValueError("case identity must be neutral and path independent")
    agent = safe_file(Path(case_root), f"{case_id}/agent")
    if {path.name for path in agent.iterdir()} != {"manifest.json", "events.jsonl"}:
        raise ValueError("agent mount has unexpected files outside the exact allowlist")
    manifest_path = safe_file(agent, "manifest.json")
    manifest = read_json(manifest_path)
    if (
        manifest.get("case_id") != case_id
        or manifest.get("events_file") != "events.jsonl"
    ):
        raise ValueError("agent manifest identity or events reference differs")
    events = safe_file(agent, "events.jsonl")
    digest = file_hash(events)
    if digest != manifest.get("events_sha256"):
        raise ValueError("agent events hash differs from trusted manifest")
    files = {"manifest.json": file_hash(manifest_path), "events.jsonl": digest}
    return agent, files


def build_plan(config: dict[str, Any] | ControllerRunSpec) -> dict[str, Any]:
    controller = (
        config
        if isinstance(config, ControllerRunSpec)
        else ControllerRunSpec.model_validate(config)
    )
    value = controller.model_dump(mode="json")
    if controller.rows:
        raise ValueError("controller rows must be generated from the frozen selection")
    selection_path = Path(controller.selection_path)
    if file_hash(selection_path) != controller.selection_sha256:
        raise ValueError("selection hash mismatch")
    selection = read_json(selection_path)
    if selection.get("split") != controller.split:
        raise ValueError("selection split differs from requested split")
    cases = selection.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError("selection requires cases")
    identities = [row.get("case_id") for row in cases]
    if any(
        not isinstance(identity, str) or not NEUTRAL_CASE.fullmatch(identity)
        for identity in identities
    ):
        raise ValueError("case identity must be neutral")
    if any(
        not identity.startswith(controller.dataset + "-") for identity in identities
    ):
        raise ValueError("case identity belongs to another dataset")
    if len(set(identities)) != len(identities):
        raise ValueError("duplicate case identity")
    if set(selection.get("ablation_case_ids", identities)) != set(identities):
        raise ValueError("baseline and ablation case sets differ")
    configuration_hash = canonical_hash(value)
    rows = []
    for selected in cases:
        case_id = selected["case_id"]
        _, hashes = agent_input(Path(controller.case_root), case_id)
        expected = selected.get("agent_manifest_sha256")
        if expected and hashes["manifest.json"] != expected:
            raise ValueError("selection agent manifest hash mismatch")
        scoring_root = safe_file(Path(controller.case_root), f"{case_id}/scoring")
        scoring_hashes = {
            name: file_hash(safe_file(scoring_root, name))
            for name in ["manifest.json", "gold.jsonl", "source-gold.json"]
            if safe_file(scoring_root, name).is_file()
        }
        if (
            selected.get("scoring_manifest_sha256")
            and scoring_hashes.get("manifest.json")
            != selected["scoring_manifest_sha256"]
        ):
            raise ValueError("selection scoring manifest hash mismatch")
        for group in GROUPS:
            spec = WorkerRunSpec(
                run_id=controller.run_id,
                case_id=case_id,
                group=group,
                config_sha256=configuration_hash,
                model=controller.model,
                seed=controller.seed,
                budget=controller.call_budget,
            )
            rows.append(
                {
                    "row_id": "row-"
                    + canonical_hash([controller.run_id, case_id, group, 1])[:24],
                    "case_id": case_id,
                    "group": group,
                    "replicate": 1,
                    "worker_spec": spec.model_dump(mode="json"),
                    "input_hashes": hashes,
                    "scoring_hashes": scoring_hashes,
                }
            )
    admissions = {
        str(Path(path).resolve()): file_hash(Path(path))
        for path in controller.admission_paths
    }
    payload = {
        "schema_version": "task13-plan-v1",
        "controller": value,
        "config_sha256": configuration_hash,
        "admission_hashes": admissions,
        "rows": rows,
    }
    return {**payload, "plan_sha256": canonical_hash(payload)}


def validate_plan(plan: dict[str, Any]) -> dict[str, Any]:
    payload = {key: value for key, value in plan.items() if key != "plan_sha256"}
    if canonical_hash(payload) != plan.get("plan_sha256"):
        raise ValueError("plan hash mismatch")
    controller = ControllerRunSpec.model_validate(plan["controller"])
    if canonical_hash(controller) != plan["config_sha256"]:
        raise ValueError("controller configuration hash mismatch")
    rows = plan["rows"]
    keys = {(row["case_id"], row["group"], row["replicate"]) for row in rows}
    cases = {row["case_id"] for row in rows}
    if (
        len(keys) != len(rows)
        or len(rows) != len(cases) * len(GROUPS)
        or {row["group"] for row in rows} != set(GROUPS)
    ):
        raise ValueError("plan matrix is incomplete or duplicated")
    for row in rows:
        spec = WorkerRunSpec.model_validate(row["worker_spec"])
        if (
            not NEUTRAL_CASE.fullmatch(row["case_id"])
            or spec.case_id != row["case_id"]
            or spec.group != row["group"]
            or spec.config_sha256 != plan["config_sha256"]
            or spec.run_id != controller.run_id
        ):
            raise ValueError("worker specification binding differs")
        if (
            row["row_id"]
            != "row-"
            + canonical_hash([controller.run_id, row["case_id"], row["group"], 1])[:24]
        ):
            raise ValueError("row identity differs from plan")
    return plan


def validate_execution_gates(
    plan: dict[str, Any], *, allow_final_test: bool = False
) -> None:
    validate_plan(plan)
    config = plan["controller"]
    if file_hash(Path(config["selection_path"])) != config["selection_sha256"]:
        raise ValueError("selection hash changed after planning")
    for path, digest in plan["admission_hashes"].items():
        if file_hash(Path(path)) != digest:
            raise ValueError("admission evidence hash changed")
    if config["split"] != "test":
        return
    if not allow_final_test:
        raise ValueError("formal execution requires --allow-final-test")
    expected = 22 if config["dataset"] == "ait" else 66
    if len(plan["rows"]) != expected * 8:
        raise ValueError(f"formal {config['dataset']} requires {expected} cases")
    if (
        not config["freeze_manifest"]
        or not config["freeze_sha256"]
        or not config["admission_paths"]
    ):
        raise ValueError("formal freeze and admission evidence are required")
    freeze_path = Path(config["freeze_manifest"])
    if file_hash(freeze_path) != config["freeze_sha256"]:
        raise ValueError("freeze hash mismatch")
    freeze = read_json(freeze_path)
    required_bindings = {
        "protocol",
        "dependencies",
        "knowledge",
        "model",
        "prompts",
        "tools",
        "scoring",
        "review",
        "plots",
        "dataset_admission",
    }
    if (
        freeze.get("status") != "frozen"
        or freeze.get("source_commit") != config["source_commit"]
        or not required_bindings.issubset(freeze.get("bindings", {}))
        or any(
            not re.fullmatch(r"[0-9a-f]{64}", freeze["bindings"][key])
            for key in required_bindings
        )
    ):
        raise ValueError("formal freeze bindings are incomplete")
    if any(
        freeze.get("gates", {}).get(gate) != "passed"
        for gate in ["G1", "G2", "G3", "G4", "G5"]
    ):
        raise ValueError("formal freeze gates are incomplete")
    files = freeze.get("files", {})
    if (
        not files
        or "services/backend/uv.lock" not in files
        or "docs/evaluations/protocol.md" not in files
    ):
        raise ValueError("freeze must bind implementation, protocol and lock files")
    validate_freeze_file_coverage(freeze, repository=ROOT)
    isolation = freeze.get("isolation", {})
    receipt_path = Path(isolation.get("receipt_path", ""))
    if not receipt_path.is_file() or file_hash(receipt_path) != isolation.get(
        "receipt_sha256"
    ):
        raise ValueError("real worker isolation receipt is absent")
    receipt = read_json(receipt_path)
    if not accepted_isolation_receipt(receipt, config["source_commit"]):
        raise ValueError("real model worker isolation is not accepted")
    admissions = [read_json(Path(path)) for path in config["admission_paths"]]
    if config["dataset"] == "dedale":
        valid = any(
            value.get("dataset_frozen") is True
            and value.get("task12_accepted") is True
            and value.get("selection", {}).get("sha256") == config["selection_sha256"]
            for value in admissions
        )
    else:
        valid = any(
            value.get("active_test_folders_exactly_22_neutral") is True
            and value.get("selection_sha256") == config["selection_sha256"]
            for value in admissions
        )
    if not valid:
        raise ValueError("Task12 dataset admission is not bound to this selection")
    validate_committed_sources(ROOT, config["source_commit"])
