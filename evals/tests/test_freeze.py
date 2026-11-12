"""Freeze scaffolding stays unfrozen and cannot omit evaluated implementation."""

from __future__ import annotations

import importlib
import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest


def freezer():
    assert importlib.util.find_spec("evals.freeze") is not None
    return importlib.import_module("evals.freeze")


def test_freeze_requires_backend_tests_and_all_task13_source_and_configs(tmp_path):
    module = freezer()
    representatives = [
        "services/backend/src/evidencesoc/agents/graph.py",
        "services/backend/tests/agents/test_graph.py",
        "evals/adapters/evidencesoc.py",
        "evals/runners/execute.py",
        "evals/metrics/classification.py",
        "evals/plots/generate.py",
        "evals/tests/test_contracts.py",
        "evals/configs/ait.json",
        "evals/configs/dedale.json",
    ]
    for name in representatives + ["evals/configs/freeze_manifest.json"]:
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{}", encoding="utf-8")
    required = module.required_freeze_files(tmp_path)
    assert set(representatives) <= set(required)
    assert "evals/configs/freeze_manifest.json" not in required
    minimal = {
        "files": {
            "docs/evaluations/protocol.md": "a" * 64,
            "services/backend/uv.lock": "b" * 64,
        }
    }
    with pytest.raises(ValueError, match="coverage|evaluated"):
        module.validate_freeze_file_coverage(minimal, repository=tmp_path)


def test_formal_source_gate_rejects_untracked_affected_source(tmp_path, monkeypatch):
    module = freezer()
    commands = []
    source = tmp_path / "evals/adapters/untracked.py"
    source.parent.mkdir(parents=True)
    source.write_text("# evaluated source", encoding="utf-8")

    def git(command, **kwargs):
        commands.append(command)
        if command[1] == "rev-parse":
            return SimpleNamespace(returncode=0, stdout="a" * 40 + "\n")
        if command[1] == "diff":
            return SimpleNamespace(returncode=0, stdout="")
        if command[1] == "ls-files":
            return SimpleNamespace(returncode=0, stdout="evals/adapters/untracked.py\0")
        raise AssertionError("unexpected Git operation")

    monkeypatch.setattr(module.subprocess, "run", git)
    with pytest.raises(ValueError, match="untracked|committed"):
        module.validate_committed_sources(tmp_path, "a" * 40)
    assert any(command[1:3] == ["ls-files", "--others"] for command in commands)
    assert all("--exclude-standard" not in command for command in commands)


@pytest.mark.parametrize(
    "invocations,cross_case,critical", [(0, True, 0), (1, False, 0), (1, True, 1)]
)
def test_g4_never_accepts_fixture_or_skipped_or_cross_case_unsafe_receipts(
    invocations, cross_case, critical
):
    module = freezer()
    receipt = {
        "status": "passed",
        "source_commit": "a" * 40,
        "real_model_invocations": invocations,
        "cross_case_denied": cross_case,
        "critical_skips": critical,
    }
    assert module.accepted_isolation_receipt(receipt, "a" * 40) is False


def test_unfrozen_controls_are_deterministic_and_use_actual_accepted_inputs():
    module = freezer()
    repository = Path(__file__).resolve().parents[2]
    first = module.build_unfrozen_artifacts(repository, "a" * 40, "task13-campaign")
    assert first == module.build_unfrozen_artifacts(
        repository, "a" * 40, "task13-campaign"
    )
    freeze, controllers = first
    assert freeze["status"] == "prepared_not_frozen"
    assert all(status == "pending" for status in freeze["gates"].values())
    assert freeze["isolation"] is None
    manifest = importlib.import_module("evals.runners.manifest")
    for dataset, count in [("ait", 22), ("dedale", 66)]:
        config = controllers[dataset]
        assert config["run_id"] == "task13-campaign"
        assert config["freeze_manifest"] is None and config["freeze_sha256"] is None
        assert config["budget_cny"] == 100 and config["dev_budget_cny"] == 15
        plan = manifest.build_plan(config)
        assert len(plan["rows"]) == count * 8
        with pytest.raises(ValueError, match="freeze"):
            manifest.validate_execution_gates(plan, allow_final_test=True)


def test_unfrozen_controls_bind_relocated_protocol_and_admissions(tmp_path):
    module = freezer()
    protocol = "evals/protocol.md"
    admissions = {
        "ait": "evals/configs/admission/task12-ait-hashes.json",
        "dedale": "evals/configs/admission/task12-dedale-freeze-2026-10-17.json",
    }
    for name in [
        protocol,
        *admissions.values(),
        ".backups/task12-readiness/data/manifests/ait-task11-test-selection.json",
        "data/dedale/priority-cases-v4/selection.json",
    ]:
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"{}")

    freeze, controllers = module.build_unfrozen_artifacts(
        tmp_path, "a" * 40, "task13-campaign"
    )

    assert freeze["bindings"]["protocol"] == freeze["files"][protocol]
    for dataset, admission in admissions.items():
        assert controllers[dataset]["admission_paths"] == [str(tmp_path / admission)]
    module.validate_freeze_file_coverage(freeze, repository=tmp_path)


def test_generated_control_artifacts_cannot_enter_the_source_freeze(tmp_path):
    module = freezer()
    for name in [
        "evals/configs/ait.json",
        "evals/configs/freeze_manifest.json",
        "data/task13/control/campaign/ait.json",
        "evals/__pycache__/test.pyc",
        "evals/.task13_test_tmp/figures/untracked.png",
    ]:
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{}", encoding="utf-8")
    assert module.required_freeze_files(tmp_path) == ["evals/configs/ait.json"]


def test_freeze_coverage_rejects_stale_or_forged_hashes(tmp_path):
    module = freezer()
    path = tmp_path / "evals/runners/execute.py"
    path.parent.mkdir(parents=True)
    path.write_text("before", encoding="utf-8")
    with pytest.raises(ValueError, match="hash"):
        module.validate_freeze_file_coverage(
            {"files": {"evals/runners/execute.py": "a" * 64}}, repository=tmp_path
        )
