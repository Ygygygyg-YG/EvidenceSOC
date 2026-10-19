"""Formal wrapper records each invocation and stops before an unfrozen run."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from test_runner_manifest import fixture_config


def test_formal_resume_records_each_exact_invocation_and_stops_at_gates(tmp_path):
    shell = shutil.which("pwsh") or shutil.which("powershell")
    if shell is None:
        pytest.skip("PowerShell is unavailable on this host")
    repository = Path(__file__).resolve().parents[2]
    config = fixture_config(tmp_path, split="test")
    config_path = tmp_path / "controller.json"
    config_path.write_text(json.dumps(config), encoding="utf-8")
    runtime_path = tmp_path / "runtime.json"
    runtime_path.write_text("{}", encoding="utf-8")
    outputs = tmp_path / "runs"
    arguments = [
        shell,
        "-NoProfile",
        "-File",
        str(repository / "evals/run_formal.ps1"),
        "-Dataset",
        "ait",
        "-Config",
        str(config_path),
        "-RuntimeConfig",
        str(runtime_path),
        "-OutputRoot",
        str(outputs),
        "-Python",
        sys.executable,
        "-AllowFinalTest",
    ]
    for _ in range(2):
        completed = subprocess.run(
            arguments, cwd=repository, capture_output=True, timeout=60, check=False
        )
        assert completed.returncode != 0
    root = outputs / config["run_id"]
    assert (root / "plan.json").is_file()
    assert not (root / "attempts").exists()
    assert list(root.glob("scores-*.json")) == []
    receipts = sorted(root.glob("commands-*.json"))
    assert len(receipts) == 2
    values = [json.loads(path.read_text(encoding="utf-8")) for path in receipts]
    assert {value["plan_reused"] for value in values} == {False, True}
    assert len({value["commands"][-1][-1] for value in values}) == 2
    assert all(value["runtime_sha256"] and value["config_sha256"] for value in values)
