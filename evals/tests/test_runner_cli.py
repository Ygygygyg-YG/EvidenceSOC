"""Public entry points provide explicit, safely separated controller phases."""

from __future__ import annotations

import importlib
import importlib.util
import json
from pathlib import Path

from test_runner_manifest import fixture_config


def test_cli_fixture_plan_execute_score_is_explicit_and_preserves_missing(
    tmp_path, capsys
):
    assert importlib.util.find_spec("evals.runners.cli") is not None
    cli = importlib.import_module("evals.runners.cli")
    settings = fixture_config(tmp_path)
    for case in Path(settings["case_root"]).iterdir():
        scoring = case / "scoring"
        scoring.mkdir()
        (scoring / "manifest.json").write_text(json.dumps({"case_id": case.name}))
        (scoring / "gold.jsonl").write_text(
            json.dumps({"is_attack": False, "attack_types": []}) + "\n"
        )
    config = tmp_path / "config.json"
    config.write_text(json.dumps(settings), encoding="utf-8")
    plan = tmp_path / "plan.json"
    assert cli.main(["plan", "--config", str(config), "--output", str(plan)]) == 0
    outputs = tmp_path / "outputs"
    assert (
        cli.main(
            [
                "execute",
                "--plan",
                str(plan),
                "--output-root",
                str(outputs),
                "--fixture",
                "--row-limit",
                "1",
            ]
        )
        == 0
    )
    response = json.loads(capsys.readouterr().out.splitlines()[-1])
    assert response["completed"] == 1 and response["missing"] == 15
    manifest = json.loads(plan.read_text(encoding="utf-8"))
    result = json.loads(
        (
            outputs / manifest["rows"][0]["row_id"] / "attempt-001/result.json"
        ).read_text(encoding="utf-8")
    )
    assert result["diagnostic_snapshot"]["taxonomy_status"] == "unknown"
    assert result["model_ledger"] == []
    score = tmp_path / "score.json"
    assert (
        cli.main(
            [
                "score",
                "--plan",
                str(plan),
                "--output-root",
                str(outputs),
                "--output",
                str(score),
            ]
        )
        == 0
    )
    scored = json.loads(score.read_text(encoding="utf-8"))
    assert scored["metadata"]["formal_complete"] is False
    assert all(
        group["coverage"]["planned_n"] == 2
        for group in scored["groups"]["ait"].values()
    )


def test_cli_no_worker_fallback_when_runtime_is_absent(tmp_path):
    assert importlib.util.find_spec("evals.runners.cli") is not None
    cli = importlib.import_module("evals.runners.cli")
    config = tmp_path / "config.json"
    config.write_text(json.dumps(fixture_config(tmp_path)), encoding="utf-8")
    plan = tmp_path / "plan.json"
    cli.main(["plan", "--config", str(config), "--output", str(plan)])
    assert (
        cli.main(
            ["execute", "--plan", str(plan), "--output-root", str(tmp_path / "outputs")]
        )
        == 1
    )
