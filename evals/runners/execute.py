"""Sequential dispatch, immutable attempt chains and explicit rerun permits."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from evals.adapters.worker_errors import WorkerInfrastructureError, WorkerTransportError
from evals.contracts import AdapterResult, AttemptRecord, canonical_hash
from evals.datasets.dedale.common import read_json, safe_file
from evals.runners.manifest import (
    agent_input,
    file_hash,
    validate_execution_gates,
    validate_plan,
    write_immutable_json,
)

Worker = Callable[[dict[str, Any], Path], Awaitable[dict[str, Any] | AdapterResult]]
RERUN_CATEGORIES = {"infrastructure", "transport"}


def now() -> str:
    return datetime.now(UTC).isoformat()


def _attempts(plan, row, output_root):
    row_dir = safe_file(Path(output_root), row["row_id"])
    if row_dir.exists() and any(
        path.name.startswith("attempt-")
        and path.name not in {"attempt-001", "attempt-002"}
        for path in row_dir.iterdir()
    ):
        raise ValueError("unregistered attempt exceeds the frozen two-attempt policy")
    attempts = []
    for number in [1, 2]:
        directory = row_dir / f"attempt-{number:03d}"
        if not directory.exists():
            continue
        start_path = directory / "started.json"
        if not start_path.is_file():
            raise ValueError("attempt directory has no immutable start record")
        start = read_json(start_path)
        if (
            start.get("plan_sha256") != plan["plan_sha256"]
            or start.get("row_id") != row["row_id"]
            or start.get("attempt") != number
        ):
            raise ValueError("attempt start is bound to a different plan")
        final = directory / "attempt.json"
        if final.exists():
            record = AttemptRecord.model_validate(read_json(final)).model_dump(
                mode="json"
            )
            if (
                record["config_sha256"] != plan["config_sha256"]
                or record["input_sha256"] != canonical_hash(row["input_hashes"])
                or record["row_id"] != row["row_id"]
                or record["attempt"] != number
            ):
                raise ValueError("attempt configuration/input binding mismatch")
            for name, digest in record["artifact_hashes"].items():
                if file_hash(safe_file(directory, name)) != digest:
                    raise ValueError("attempt artifact hash mismatch")
            result_path = directory / "result.json"
            result = read_json(result_path) if result_path.exists() else None
            if (
                result_path.exists()
                and file_hash(result_path) != record["output_sha256"]
            ):
                raise ValueError("attempt output hash mismatch")
            record["record_sha256"] = file_hash(final)
        else:
            record = {
                **start,
                "execution_status": "interrupted",
                "diagnosis_status": "missing",
                "error_category": "infrastructure",
                "finished_at": None,
                "record_sha256": file_hash(start_path),
            }
            result = None
        attempts.append({"record": record, "result": result})
    if [a["record"]["attempt"] for a in attempts] != list(range(1, len(attempts) + 1)):
        raise ValueError("attempt sequence has a gap")
    if len(attempts) == 2:
        permit_path = row_dir / "attempt-002" / "permit.json"
        if not permit_path.exists():
            raise ValueError("second attempt lacks immutable rerun authorization")
        _validate_permit(read_json(permit_path), plan, row, attempts[0]["record"])
    return attempts


def collect_rows(plan: dict, output_root: Path) -> list[dict]:
    validate_plan(plan)
    collected = []
    for row in plan["rows"]:
        attempts = _attempts(plan, row, output_root)
        latest = attempts[-1] if attempts else None
        collected.append(
            {
                **row,
                "attempts": attempts,
                "result": latest["result"] if latest else None,
                "attempt_record": latest["record"] if latest else None,
                "execution_status": latest["record"]["execution_status"]
                if latest
                else "missing",
                "diagnosis_status": latest["record"].get("diagnosis_status", "missing")
                if latest
                else "missing",
            }
        )
    return collected


def _validate_permit(permit, plan, row, previous):
    payload = {key: value for key, value in permit.items() if key != "permit_sha256"}
    if (
        canonical_hash(payload) != permit.get("permit_sha256")
        or permit.get("plan_sha256") != plan["plan_sha256"]
        or permit.get("row_id") != row["row_id"]
        or permit.get("previous_attempt_sha256") != previous["record_sha256"]
        or permit.get("attempt") != 2
        or not permit.get("approved_by")
        or not permit.get("approved_at")
    ):
        raise ValueError("rerun permit hash or binding differs")
    if (
        previous["attempt"] != 1
        or previous.get("execution_status") not in {"failed", "interrupted"}
        or previous.get("error_category") not in RERUN_CATEGORIES
        or permit.get("reason") != previous.get("error_category")
    ):
        raise ValueError(
            "rerun is only eligible for infrastructure or transport failures"
        )


def create_rerun_permit(
    plan: dict, row: dict, *, approved_by: str, reason: str, output: Path
) -> dict:
    previous = row.get("attempt_record")
    if (
        not previous
        or previous.get("attempt") != 1
        or previous.get("execution_status") not in {"failed", "interrupted"}
        or reason not in RERUN_CATEGORIES
        or previous.get("error_category") != reason
        or not approved_by.strip()
    ):
        raise ValueError(
            "rerun is only eligible for infrastructure or transport failure"
        )
    payload = {
        "schema_version": "task13-rerun-v1",
        "plan_sha256": plan["plan_sha256"],
        "row_id": row["row_id"],
        "previous_attempt_sha256": previous["record_sha256"],
        "attempt": 2,
        "reason": reason,
        "approved_by": approved_by,
        "approved_at": now(),
    }
    permit = {**payload, "permit_sha256": canonical_hash(payload)}
    write_immutable_json(output, permit)
    return permit


async def _execute(plan, output_root, worker, row_limit, permits, readiness=None):
    dispatched = 0
    for row in collect_rows(plan, output_root):
        if row_limit is not None and dispatched >= row_limit:
            break
        previous = row["attempt_record"]
        permit = permits.get(row["row_id"])
        if previous:
            if not permit:
                continue
            _validate_permit(permit, plan, row, previous)
        elif permit:
            raise ValueError("rerun permit cannot authorize an initial attempt")
        if readiness:
            readiness()
        number = 2 if previous else 1
        directory = safe_file(
            Path(output_root), f"{row['row_id']}/attempt-{number:03d}"
        )
        agent, hashes = agent_input(
            Path(plan["controller"]["case_root"]), row["case_id"]
        )
        if hashes != row["input_hashes"]:
            raise ValueError("case input hash changed after planning")
        directory.mkdir(parents=True, exist_ok=False)
        start = {
            "plan_sha256": plan["plan_sha256"],
            "row_id": row["row_id"],
            "attempt": number,
            "started_at": now(),
            "config_sha256": plan["config_sha256"],
            "input_sha256": canonical_hash(hashes),
            "approved_rerun": number == 2,
        }
        write_immutable_json(directory / "started.json", start)
        if permit:
            write_immutable_json(directory / "permit.json", permit)
        try:
            value = await worker(row["worker_spec"], agent)
            result = (
                value
                if isinstance(value, AdapterResult)
                else AdapterResult.model_validate(value)
            )
            result_value = result.model_dump(mode="json")
            categories = [error.get("category") for error in result.errors]
            error_category = next(
                (
                    category
                    for category in categories
                    if category not in RERUN_CATEGORIES
                ),
                "infrastructure"
                if "infrastructure" in categories
                else "transport"
                if categories
                else None,
            )
            status, diagnostic = result.execution_status, result.diagnosis_status
        except Exception as error:  # noqa: BLE001 - preserve every failed attempt without leaking secrets.
            error_category = (
                "transport"
                if isinstance(
                    error, (WorkerTransportError, ConnectionError, TimeoutError)
                )
                else "infrastructure"
                if isinstance(error, (WorkerInfrastructureError, OSError))
                else "application"
            )
            result_value = AdapterResult(
                execution_status="failed",
                diagnosis_status="failed",
                errors=[
                    {"category": error_category, "error_type": type(error).__name__}
                ],
            ).model_dump(mode="json")
            status, diagnostic = "failed", "failed"
        write_immutable_json(directory / "result.json", result_value)
        artifacts = {
            "started.json": file_hash(directory / "started.json"),
            "result.json": file_hash(directory / "result.json"),
        }
        if permit:
            artifacts["permit.json"] = file_hash(directory / "permit.json")
        record = AttemptRecord(
            attempt=number,
            row_id=row["row_id"],
            started_at=start["started_at"],
            finished_at=now(),
            execution_status=status,
            diagnosis_status=diagnostic,
            error_category=error_category,
            approved_rerun=number == 2,
            config_sha256=plan["config_sha256"],
            input_sha256=canonical_hash(hashes),
            output_sha256=artifacts["result.json"],
            artifact_hashes=artifacts,
        )
        write_immutable_json(directory / "attempt.json", record.model_dump(mode="json"))
        dispatched += 1
        if any(
            error.get("error_type") == "BudgetLimit"
            for error in result_value.get("errors", [])
        ):
            raise RuntimeError(
                "campaign halted by request budget; later rows remain missing"
            )
    rows = collect_rows(plan, output_root)
    counts = {
        key: sum(row["execution_status"] == key for row in rows)
        for key in ["completed", "failed", "interrupted", "missing"]
    }
    return {
        "run_id": plan["controller"]["run_id"],
        "plan_sha256": plan["plan_sha256"],
        "planned": len(rows),
        "dispatched_now": dispatched,
        **counts,
    }


def execute_plan(
    plan: dict,
    output_root: Path,
    *,
    worker: Worker | None = None,
    runtime_options: dict | None = None,
    row_limit: int | None = None,
    rerun_permits: list[dict] | None = None,
    allow_final_test: bool = False,
) -> dict:
    validate_execution_gates(plan, allow_final_test=allow_final_test)
    if row_limit is not None and row_limit < 1:
        raise ValueError("row limit must be positive")
    if worker is not None and plan["controller"]["split"] == "test":
        raise ValueError("injected or fixture workers cannot execute formal tests")
    readiness = None
    if worker is None:
        from scripts.task13_worker_runtime import preflight_runtime, run_container

        if not runtime_options:
            raise ValueError("real execution requires explicit Docker runtime options")
        expected_phase = (
            "formal" if plan["controller"]["split"] == "test" else "development"
        )
        if runtime_options.get("phase") != expected_phase:
            raise ValueError(
                "runtime phase differs from the planned development/formal budget"
            )
        if runtime_options.get("source_commit") != plan["controller"]["source_commit"]:
            raise ValueError("runtime source differs from the planned implementation")
        preflight_runtime(runtime_options, plan["controller"])

        def ready():
            from evals.adapters.model_client import BudgetAccount

            account = BudgetAccount(
                Path(runtime_options["budget_dir"]) / "campaign.sqlite",
                total_cny=plan["controller"]["budget_cny"],
                dev_cny=plan["controller"]["dev_budget_cny"],
            )
            summary = account.summary()
            if summary.get("halted"):
                raise RuntimeError(
                    "campaign halted by observable model version or accounting failure"
                )
            if summary["remaining_total_cny"] <= 1e-12 or (
                expected_phase == "development"
                and summary["remaining_development_cny"] <= 1e-12
            ):
                raise RuntimeError(
                    "campaign budget exhausted; later rows remain missing"
                )

        readiness = ready

        async def docker_worker(spec, agent):
            return await run_container(spec, agent, runtime_options)

        worker = docker_worker
    permits = {}
    for permit in rerun_permits or []:
        if permit["row_id"] in permits:
            raise ValueError("duplicate rerun authorization")
        permits[permit["row_id"]] = permit
    current = {row["row_id"]: row for row in collect_rows(plan, output_root)}
    for identity, permit in permits.items():
        if identity not in current or not current[identity]["attempt_record"]:
            raise ValueError("rerun permit references missing row or attempt")
        _validate_permit(
            permit, plan, current[identity], current[identity]["attempt_record"]
        )
    return asyncio.run(
        _execute(plan, Path(output_root), worker, row_limit, permits, readiness)
    )
