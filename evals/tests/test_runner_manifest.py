"""The controller plan retains every row and freezes answer-free worker inputs."""

from __future__ import annotations

import importlib
import importlib.util
import json
from hashlib import sha256
from pathlib import Path

import pytest


def runner():
    assert importlib.util.find_spec("evals.runners.manifest") is not None
    return importlib.import_module("evals.runners.manifest")


def fixture_config(tmp_path, split="validation"):
    cases = []
    case_root = tmp_path / "cases"
    for number in range(2):
        case_id = "ait-" + f"{number:024x}"
        agent = case_root / case_id / "agent"
        agent.mkdir(parents=True)
        events = b'{"external_id":"e1","message":"raw observation"}\n'
        (agent / "events.jsonl").write_bytes(events)
        manifest = {
            "case_id": case_id,
            "events_file": "events.jsonl",
            "events_sha256": sha256(events).hexdigest(),
            "split": split,
        }
        (agent / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        cases.append(
            {
                "case_id": case_id,
                "agent_manifest_sha256": sha256(
                    (agent / "manifest.json").read_bytes()
                ).hexdigest(),
            }
        )
    selection = tmp_path / "selection.json"
    selection.write_text(
        json.dumps(
            {
                "split": split,
                "cases": cases,
                "ablation_case_ids": [row["case_id"] for row in cases],
            }
        ),
        encoding="utf-8",
    )
    return {
        "run_id": "run-001",
        "dataset": "ait",
        "split": split,
        "case_root": str(case_root),
        "selection_path": str(selection),
        "selection_sha256": sha256(selection.read_bytes()).hexdigest(),
        "source_commit": "1" * 40,
        "budget_cny": 100,
        "dev_budget_cny": 15,
        "reviewer": "user",
        "review_window": "19:00-00:00 Asia/Shanghai",
        "rows": [],
        "admission_paths": [],
        "freeze_manifest": None,
    }


def test_plan_expands_exact_matrix_with_neutral_worker_projection(tmp_path):
    module = runner()
    plan = module.build_plan(fixture_config(tmp_path))
    assert len(plan["rows"]) == 16
    assert len({row["row_id"] for row in plan["rows"]}) == 16
    assert {row["group"] for row in plan["rows"]} == set(module.GROUPS)
    assert all(
        "agent_dir" not in row["worker_spec"] and "dataset" not in row["worker_spec"]
        for row in plan["rows"]
    )
    assert module.validate_plan(plan) == plan


def test_plan_rejects_tamper_and_duplicate_case(tmp_path):
    module = runner()
    config = fixture_config(tmp_path)
    plan = module.build_plan(config)
    plan["rows"].pop()
    with pytest.raises(ValueError, match="hash|matrix"):
        module.validate_plan(plan)
    selection = Path(config["selection_path"])
    value = json.loads(selection.read_text())
    value["cases"].append(value["cases"][0])
    selection.write_text(json.dumps(value), encoding="utf-8")
    config["selection_sha256"] = sha256(selection.read_bytes()).hexdigest()
    with pytest.raises(ValueError, match="duplicate"):
        module.build_plan(config)


@pytest.mark.parametrize(
    "case_id",
    ["../other", "shaw-test-attack-webshell", "/absolute", "ait-" + "0" * 24 + "/../x"],
)
def test_answer_bearing_or_escaping_identity_rejected(tmp_path, case_id):
    module = runner()
    config = fixture_config(tmp_path)
    selection = Path(config["selection_path"])
    value = json.loads(selection.read_text())
    value["cases"][0]["case_id"] = case_id
    selection.write_text(json.dumps(value), encoding="utf-8")
    config["selection_sha256"] = sha256(selection.read_bytes()).hexdigest()
    with pytest.raises(ValueError, match="neutral|identity"):
        module.build_plan(config)


def test_existing_immutable_file_cannot_be_replaced(tmp_path):
    module = runner()
    path = tmp_path / "immutable.json"
    module.write_immutable_json(path, {"answer": 1})
    with pytest.raises(FileExistsError):
        module.write_immutable_json(path, {"answer": 2})
    assert json.loads(path.read_text())["answer"] == 1


def test_final_run_needs_explicit_flag_and_full_gates(tmp_path):
    module = runner()
    config = fixture_config(tmp_path, split="test")
    plan = module.build_plan(config)
    with pytest.raises(ValueError, match="allow-final-test"):
        module.validate_execution_gates(plan, allow_final_test=False)
    with pytest.raises(ValueError, match="freeze|admission|22"):
        module.validate_execution_gates(plan, allow_final_test=True)


def test_agent_mount_rejects_unregistered_extra_files(tmp_path):
    module = runner()
    config = fixture_config(tmp_path)
    first = next(Path(config["case_root"]).iterdir())
    (first / "agent/answers.json").write_text("{}")
    with pytest.raises(ValueError, match="allowlist|unexpected|extra"):
        module.build_plan(config)


def test_dataset_cannot_relabel_other_dataset_case_identity(tmp_path):
    module = runner()
    config = fixture_config(tmp_path)
    config["dataset"] = "dedale"
    with pytest.raises(ValueError, match="dataset"):
        module.build_plan(config)
