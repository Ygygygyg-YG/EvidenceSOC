"""Immutable attempts must never silently turn failed or missing rows into wins."""

from __future__ import annotations

import importlib
import importlib.util
import json
from pathlib import Path

import pytest
from test_runner_manifest import fixture_config


def runner():
    assert importlib.util.find_spec("evals.runners.execute") is not None
    return importlib.import_module("evals.runners.execute")


def make_plan(tmp_path):
    return importlib.import_module("evals.runners.manifest").build_plan(
        fixture_config(tmp_path)
    )


def test_resume_keeps_immutable_success_and_missing_rows(tmp_path):
    module = runner()
    plan = make_plan(tmp_path)
    calls = []

    async def worker(spec, agent_dir):
        calls.append(spec["group"])
        return {
            "execution_status": "completed",
            "diagnosis_status": "succeeded",
            "diagnostic_snapshot": {"verdict": "unknown"},
        }

    output = tmp_path / "outputs"
    first = module.execute_plan(plan, output, worker=worker, row_limit=1)
    assert first["completed"] == 1 and first["missing"] == 15
    original = (
        output / plan["rows"][0]["row_id"] / "attempt-001" / "attempt.json"
    ).read_bytes()
    second = module.execute_plan(plan, output, worker=worker, row_limit=1)
    assert second["completed"] == 2 and len(calls) == 2
    assert (
        output / plan["rows"][0]["row_id"] / "attempt-001" / "attempt.json"
    ).read_bytes() == original
    assert len(module.collect_rows(plan, output)) == 16


def test_failed_schema_and_unknown_are_not_rerun(tmp_path):
    module = runner()
    plan = make_plan(tmp_path)

    async def worker(spec, agent_dir):
        return {
            "execution_status": "failed",
            "diagnosis_status": "failed",
            "errors": [{"category": "schema"}],
        }

    output = tmp_path / "outputs"
    module.execute_plan(plan, output, worker=worker, row_limit=1)
    first = module.collect_rows(plan, output)[0]
    with pytest.raises(ValueError, match="infra|transport|eligible"):
        module.create_rerun_permit(
            plan,
            first,
            approved_by="user",
            reason="schema",
            output=tmp_path / "permit.json",
        )


def test_rerun_permit_is_bound_to_previous_attempt_and_plan(tmp_path):
    module = runner()
    plan = make_plan(tmp_path)

    async def worker(spec, agent_dir):
        raise ConnectionError("do not log sensitive endpoint")

    output = tmp_path / "outputs"
    module.execute_plan(plan, output, worker=worker, row_limit=1)
    row = module.collect_rows(plan, output)[0]
    permit = module.create_rerun_permit(
        plan,
        row,
        approved_by="user",
        reason="transport",
        output=tmp_path / "permit.json",
    )
    assert permit["previous_attempt_sha256"]
    permit["plan_sha256"] = "f" * 64
    with pytest.raises(ValueError, match="permit|hash"):
        module.execute_plan(
            plan, output, worker=worker, row_limit=1, rerun_permits=[permit]
        )


def test_result_tamper_is_rejected_before_resume_or_score(tmp_path):
    module = runner()
    plan = make_plan(tmp_path)

    async def worker(spec, agent_dir):
        return {
            "execution_status": "completed",
            "diagnosis_status": "succeeded",
            "diagnostic_snapshot": {"verdict": "benign"},
        }

    output = tmp_path / "outputs"
    module.execute_plan(plan, output, worker=worker, row_limit=1)
    result = output / plan["rows"][0]["row_id"] / "attempt-001" / "result.json"
    result.write_text(
        json.dumps(
            {
                "execution_status": "completed",
                "diagnostic_snapshot": {"verdict": "attack"},
            }
        )
    )
    with pytest.raises(ValueError, match="hash|artifact"):
        module.collect_rows(plan, output)


def test_authorized_transport_rerun_keeps_both_attempts_and_costs(tmp_path):
    module = runner()
    plan = make_plan(tmp_path)
    output = tmp_path / "outputs"

    async def failed(spec, agent_dir):
        return {
            "execution_status": "failed",
            "diagnosis_status": "failed",
            "errors": [{"category": "transport"}],
            "resources": {"input_tokens": 7, "output_tokens": 0, "cost": 0.01},
        }

    async def succeeded(spec, agent_dir):
        return {
            "execution_status": "completed",
            "diagnosis_status": "succeeded",
            "diagnostic_snapshot": {"verdict": "unknown"},
            "resources": {"input_tokens": 8, "output_tokens": 1, "cost": 0.02},
        }

    module.execute_plan(plan, output, worker=failed, row_limit=1)
    row = module.collect_rows(plan, output)[0]
    permit = module.create_rerun_permit(
        plan,
        row,
        approved_by="user",
        reason="transport",
        output=tmp_path / "permit.json",
    )
    module.execute_plan(
        plan, output, worker=succeeded, row_limit=1, rerun_permits=[permit]
    )
    row = module.collect_rows(plan, output)[0]
    assert len(row["attempts"]) == 2 and row["execution_status"] == "completed"
    assert row["attempts"][0]["record"]["execution_status"] == "failed"
    scorer = importlib.import_module("evals.runners.score")
    usage, *_ = scorer._resources(row["attempts"])
    assert usage["input_tokens"] == 15 and usage["cost"] == pytest.approx(0.03)


def test_budget_halt_preserves_current_failure_and_stops_later_dispatch(tmp_path):
    module = runner()
    plan = make_plan(tmp_path)
    output = tmp_path / "outputs"
    calls = []

    async def worker(spec, agent_dir):
        calls.append(spec)
        return {
            "execution_status": "failed",
            "diagnosis_status": "failed",
            "errors": [{"category": "budget", "error_type": "BudgetLimit"}],
        }

    with pytest.raises(RuntimeError, match="halt"):
        module.execute_plan(plan, output, worker=worker)
    rows = module.collect_rows(plan, output)
    assert len(calls) == 1 and rows[0]["execution_status"] == "failed"
    assert sum(row["execution_status"] == "missing" for row in rows) == 15


def test_runtime_phase_cannot_bypass_development_budget(tmp_path):
    module = runner()
    plan = make_plan(tmp_path)
    with pytest.raises(ValueError, match="phase"):
        module.execute_plan(
            plan,
            tmp_path / "output",
            runtime_options={
                "phase": "formal",
                "source_commit": plan["controller"]["source_commit"],
            },
        )


def test_interrupted_attempt_is_retained_and_never_automatically_replayed(tmp_path):
    module = runner()
    plan = make_plan(tmp_path)
    output = tmp_path / "outputs"

    class WorkerStopped(BaseException):
        pass

    async def interrupted(spec, agent_dir):
        raise WorkerStopped()

    with pytest.raises(WorkerStopped):
        module.execute_plan(plan, output, worker=interrupted, row_limit=1)
    rows = module.collect_rows(plan, output)
    assert rows[0]["execution_status"] == "interrupted"
    original = rows[0]["attempt_record"]["record_sha256"]

    async def completed(spec, agent_dir):
        return {
            "execution_status": "completed",
            "diagnosis_status": "succeeded",
            "diagnostic_snapshot": {"verdict": "unknown"},
        }

    summary = module.execute_plan(plan, output, worker=completed, row_limit=1)
    rows = module.collect_rows(plan, output)
    assert summary["interrupted"] == 1 and summary["completed"] == 1
    assert rows[0]["attempt_record"]["record_sha256"] == original
    permit = module.create_rerun_permit(
        plan,
        rows[0],
        approved_by="user",
        reason="infrastructure",
        output=tmp_path / "permit.json",
    )
    module.execute_plan(
        plan, output, worker=completed, row_limit=1, rerun_permits=[permit]
    )
    row = module.collect_rows(plan, output)[0]
    assert [item["record"]["execution_status"] for item in row["attempts"]] == [
        "interrupted",
        "completed",
    ]


def test_changed_input_is_rejected_before_creating_an_attempt_directory(tmp_path):
    module = runner()
    plan = make_plan(tmp_path)
    output = tmp_path / "outputs"
    agent = Path(plan["controller"]["case_root"]) / plan["rows"][0]["case_id"] / "agent"
    (agent / "events.jsonl").write_bytes(b"changed input")

    async def worker(spec, agent_dir):
        raise AssertionError("changed input must never be dispatched")

    with pytest.raises(ValueError, match="hash"):
        module.execute_plan(plan, output, worker=worker, row_limit=1)
    assert not (output / plan["rows"][0]["row_id"]).exists()
    assert all(
        row["execution_status"] == "missing"
        for row in module.collect_rows(plan, output)
    )


@pytest.mark.parametrize("exhausted", ["total", "development"])
def test_budget_exhaustion_stops_next_worker_before_creating_start(
    tmp_path, monkeypatch, exhausted
):
    module = runner()
    runtime = importlib.import_module("scripts.task13_worker_runtime")
    model_client = importlib.import_module("evals.adapters.model_client")
    config = fixture_config(tmp_path)
    config["budget_cny"] = 30
    plan = importlib.import_module("evals.runners.manifest").build_plan(config)
    options = {
        "phase": "development",
        "source_commit": plan["controller"]["source_commit"],
        "budget_dir": str(tmp_path / "budget"),
    }
    account = model_client.BudgetAccount(
        Path(options["budget_dir"]) / "campaign.sqlite", total_cny=30, dev_cny=15
    )
    monkeypatch.setattr(runtime, "preflight_runtime", lambda options, controller: None)
    calls = []

    async def worker(spec, agent_dir, runtime_options):
        calls.append(spec)
        phase = "formal" if exhausted == "total" else "development"
        amount = 30 if exhausted == "total" else 15
        reservation = account.reserve("exhaust", amount, phase)
        account.settle(reservation, amount)
        return {
            "execution_status": "completed",
            "diagnosis_status": "succeeded",
            "diagnostic_snapshot": {"verdict": "unknown"},
        }

    monkeypatch.setattr(runtime, "run_container", worker)
    with pytest.raises(RuntimeError, match="budget.*exhausted|exhausted.*budget"):
        module.execute_plan(plan, tmp_path / "outputs", runtime_options=options)
    rows = module.collect_rows(plan, tmp_path / "outputs")
    assert len(calls) == 1 and rows[0]["execution_status"] == "completed"
    assert sum(row["execution_status"] == "missing" for row in rows) == 15


def test_halted_budget_stops_initial_dispatch(tmp_path, monkeypatch):
    module = runner()
    runtime = importlib.import_module("scripts.task13_worker_runtime")
    model_client = importlib.import_module("evals.adapters.model_client")
    plan = make_plan(tmp_path)
    options = {
        "phase": "development",
        "source_commit": plan["controller"]["source_commit"],
        "budget_dir": str(tmp_path / "budget"),
    }
    account = model_client.BudgetAccount(
        Path(options["budget_dir"]) / "campaign.sqlite"
    )
    account.bind_model("model-a", "fingerprint-a")
    with pytest.raises(RuntimeError, match="version"):
        account.bind_model("model-b", "fingerprint-b")
    monkeypatch.setattr(runtime, "preflight_runtime", lambda options, controller: None)

    async def worker(*args):
        raise AssertionError("a halted campaign must never dispatch")

    monkeypatch.setattr(runtime, "run_container", worker)
    with pytest.raises(RuntimeError, match="halted"):
        module.execute_plan(plan, tmp_path / "outputs", runtime_options=options)
    assert not (tmp_path / "outputs").exists()


def test_unregistered_third_attempt_cannot_be_silently_omitted(tmp_path):
    module = runner()
    plan = make_plan(tmp_path)
    output = tmp_path / "outputs"
    (output / plan["rows"][0]["row_id"] / "attempt-003").mkdir(parents=True)
    with pytest.raises(ValueError, match="attempt"):
        module.collect_rows(plan, output)


@pytest.mark.parametrize("category", ["infrastructure", "transport"])
def test_typed_worker_failures_retain_rerun_category_and_hide_details(
    tmp_path, category
):
    module = runner()
    errors = importlib.import_module("evals.adapters.worker_errors")
    failure = (
        errors.WorkerInfrastructureError
        if category == "infrastructure"
        else errors.WorkerTransportError
    )
    plan = make_plan(tmp_path)

    async def worker(spec, agent):
        raise failure("secret-url-and-credential")

    output = tmp_path / "outputs"
    module.execute_plan(plan, output, worker=worker, row_limit=1)
    row = module.collect_rows(plan, output)[0]
    assert row["attempt_record"]["error_category"] == category
    permit = module.create_rerun_permit(
        plan, row, approved_by="user", reason=category, output=tmp_path / "permit.json"
    )
    assert permit["reason"] == category
    assert "secret-url-and-credential" not in json.dumps(row)


@pytest.mark.parametrize(
    "category,status",
    [
        ("schema", "failed"),
        ("refusal", "failed"),
        ("application", "failed"),
        (None, "completed"),
    ],
)
def test_schema_refusal_application_and_completed_unknown_never_allow_reruns(
    tmp_path, category, status
):
    module = runner()
    plan = make_plan(tmp_path)

    async def worker(spec, agent):
        return {
            "execution_status": status,
            "diagnosis_status": "failed" if category else "succeeded",
            "diagnostic_snapshot": {"verdict": "unknown"},
            "errors": [{"category": category}] if category else [],
        }

    output = tmp_path / "outputs"
    module.execute_plan(plan, output, worker=worker, row_limit=1)
    row = module.collect_rows(plan, output)[0]
    with pytest.raises(ValueError, match="eligible|infrastructure|transport"):
        module.create_rerun_permit(
            plan,
            row,
            approved_by="user",
            reason="infrastructure",
            output=tmp_path / "permit.json",
        )


@pytest.mark.parametrize(
    "categories",
    [["schema", "transport"], ["transport", "schema"], ["refusal", "infrastructure"]],
)
def test_mixed_nonrerunnable_errors_cannot_be_hidden_by_final_transport(
    tmp_path, categories
):
    module = runner()
    plan = make_plan(tmp_path)

    async def worker(spec, agent):
        return {
            "execution_status": "failed",
            "diagnosis_status": "failed",
            "errors": [{"category": category} for category in categories],
        }

    output = tmp_path / "outputs"
    module.execute_plan(plan, output, worker=worker, row_limit=1)
    row = module.collect_rows(plan, output)[0]
    assert row["attempt_record"]["error_category"] not in module.RERUN_CATEGORIES
    with pytest.raises(ValueError, match="eligible|infrastructure|transport"):
        module.create_rerun_permit(
            plan,
            row,
            approved_by="user",
            reason=categories[-1],
            output=tmp_path / "permit.json",
        )
