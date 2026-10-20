"""Controller-only F8 plans, human review packets and immutable paired execution.

Condition names and expected truth stay in this module and its saved plan. Workers
receive only one approved state, measured control values and an enable flag.
"""

from __future__ import annotations

import inspect
import re
import uuid
from collections import Counter
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path

from evidencesoc.agents.models import SimulatedAction
from evidencesoc.config import Settings
from evidencesoc.domain.models import ResponsePlan
from evidencesoc.persistence.database import (
    create_database_engine,
    create_session_factory,
)
from sqlalchemy.engine import make_url

from evals.adapters.artifacts import write_immutable_json

# Keep the established controller review API while workers import its safe owner.
from evals.adapters.retained_workflow import (
    _matching_workflow_state,  # noqa: F401
    _require_inspected_renewal_model,  # noqa: F401
    _require_renewal_workflow,  # noqa: F401
    _snapshot_valid,
    apply_human_decision,  # noqa: F401
    build_approval_packet,  # noqa: F401
    open_retained_workflow,  # noqa: F401
    renew_expired_plan,  # noqa: F401
    resource_fields,
)
from evals.adapters.verification_observations import clone_approved_state
from evals.adapters.verification_worker import (
    SourceResources,
    VerificationWorkerRequest,
    read_persisted_approval,
)
from evals.contracts import canonical_hash

CONDITIONS = ("success", "failure", "no_change")
BRANCHES = ("enabled", "disabled")


def validate_verification_plan(plan):
    slots = plan.get("slots", [])
    if (
        plan.get("schema_version") != "task13-verification-plan-v1"
        or len(slots) != 264
        or plan.get("planned_pairs") != 264
        or plan.get("planned_branches") != 528
        or plan.get("planned_cases") != 88
    ):
        raise ValueError("the complete 264-pair/528-branch plan is required")
    groups = {}
    identifiers = {
        name: set() for name in ("pair_id", "condition_id", "namespace", "request_id")
    }
    for slot in slots:
        identity = (slot["dataset"], slot["case_id"])
        groups.setdefault(identity, []).append(slot["condition"])
        branches = slot.get("branches", [])
        if [item.get("branch") for item in branches] != list(BRANCHES):
            raise ValueError("all 528 enabled/disabled branches must remain in order")
        for item, names in (
            (slot, ("pair_id", "condition_id")),
            *((item, ("namespace", "request_id")) for item in branches),
        ):
            for name in names:
                value = item.get(name)
                if (
                    not isinstance(value, str)
                    or re.fullmatch(r"[0-9a-f]{32}", value) is None
                    or value in identifiers[name]
                ):
                    raise ValueError("duplicate or nonopaque verification identifiers")
                identifiers[name].add(value)
    if Counter(dataset for dataset, _ in groups) != {"ait": 22, "dedale": 66} or any(
        sorted(conditions) != sorted(CONDITIONS) for conditions in groups.values()
    ):
        raise ValueError("all 88 cases and all three conditions must remain complete")


def build_verification_plan(
    cases: list[dict], *, source_commit: str | None = None
) -> dict:
    if Counter(row.get("dataset") for row in cases) != {"ait": 22, "dedale": 66}:
        raise ValueError("F8 requires exactly 22 AIT + 66 DEDALE = 88 cases")
    identities = [row["case_id"] for row in cases]
    if len(set(identities)) != 88 or any(
        re.fullmatch(r"(?:ait|dedale)-[0-9a-f]{16,24}", value) is None
        for value in identities
    ):
        raise ValueError("F8 requires 88 distinct neutral case identities")
    slots = []
    for row in cases:
        for condition in CONDITIONS:
            slots.append(
                {
                    "pair_id": uuid.uuid4().hex,
                    "condition_id": uuid.uuid4().hex,
                    "condition": condition,
                    "dataset": row["dataset"],
                    "case_id": row["case_id"],
                    "agent_sha256": row["agent_sha256"],
                    "branches": [
                        {
                            "branch": branch,
                            "namespace": uuid.uuid4().hex,
                            "request_id": uuid.uuid4().hex,
                        }
                        for branch in BRANCHES
                    ],
                }
            )
    return {
        "schema_version": "task13-verification-plan-v1",
        "planned_cases": 88,
        "planned_pairs": 264,
        "planned_branches": 528,
        "source_commit": source_commit,
        "reviewer": "user",
        "review_window": "19:00-00:00 Asia/Shanghai",
        "slots": slots,
    }


def verify_source_approval(source: dict) -> dict:
    """Concrete read-only verifier for the retained original PostgreSQL case DB."""
    resources = SourceResources.model_validate(resource_fields(source["resources"]))
    base = Settings(_env_file=None)
    url = make_url(base.database_url)
    if url.get_backend_name() != "postgresql":
        raise ValueError("original persisted approval store must be PostgreSQL")
    engine = create_database_engine(
        url.set(database=resources.database_name).render_as_string(hide_password=False)
    )
    try:
        return read_persisted_approval(source["state"], create_session_factory(engine))
    finally:
        engine.dispose()


def _eligibility(source, now):
    if not isinstance(source, dict) or not isinstance(source.get("state"), dict):
        return "missing", "missing_b3_state"
    state = source["state"]
    if state.get("diagnosis_execution_status") != "completed":
        return "failed", "diagnostic_failure"
    verdict = (
        (state.get("diagnostic_snapshot") or {}).get("diagnosis", {}).get("verdict")
    )
    if verdict == "benign":
        return "not_applicable", "not_applicable"
    if verdict != "attack":
        return "not_executable", "unknown_diagnosis"
    if not _snapshot_valid(state):
        return "failed", "invalid_diagnostic_snapshot"
    if not state.get("response_plan"):
        return "not_executable", "no_response_plan"
    try:
        plan = ResponsePlan.model_validate(state["response_plan"])
    except ValueError:
        return "failed", "invalid_response_plan"
    if plan.expires_at is None or plan.expires_at <= now:
        return "not_executable", "plan_expired"
    approval = state.get("approval")
    if not approval:
        return "not_executable", "approval_pending"
    if approval.get("decision") != "approved":
        return "rejected", "approval_rejected"
    try:
        clone_approved_state(state, uuid.uuid4().hex)
        SourceResources.model_validate(resource_fields(source.get("resources") or {}))
    except (ValueError, PermissionError):
        return "failed", "invalid_approved_state"
    if (state.get("simulation_execution") or {}).get("status") != "completed":
        return "not_executable", "simulation_incomplete"
    return None, None


def _measurements(state, condition, now):
    fields = {
        "block_ip_simulated": ("network_blocked", False, True),
        "isolate_host_simulated": ("host_isolated", False, True),
        "disable_account_simulated": ("account_enabled", True, False),
    }
    observations = {}
    for raw in state["response_plan"]["actions"]:
        action = SimulatedAction.model_validate(raw)
        field, before, after = fields[action.action]
        observations[action.action_id] = {
            "before": {"observed_at": now.isoformat(), field: before},
            "after": {
                "observed_at": (now + timedelta(microseconds=1)).isoformat(),
                field: after if condition == "success" else before,
                "error_code": "SIMULATED_CONTROL_REJECTED"
                if condition == "failure"
                else None,
            },
        }
    return observations


def _validated_worker_result(value, request, plan, used_resources):
    isolation = value.get("isolation_evidence") or {}
    probe, container = isolation.get("probe", {}), isolation.get("container", {})
    resource = value.get("resource_receipt") or {}
    boundaries = probe.get("boundaries", {})
    if (
        value.get("status") != "completed"
        or isolation.get("status") != "passed"
        or value.get("input_sha256") != canonical_hash(request)
        or value.get("source_state_sha256") != request.source_state_sha256
        or value.get("approved_plan_sha256") != request.approved_plan_sha256
        or value.get("approval_receipt_sha256") != request.approval_receipt_sha256
        or value.get("diagnostic_snapshot_sha256")
        != request.approved_state["diagnostic_snapshot_sha256"]
        or probe.get("pid") != 1
        or not probe.get("nonce")
        or probe.get("nonce") != resource.get("worker_nonce")
        or probe.get("hostname") != container.get("hostname")
        or probe.get("agent_sha256") != request.agent_sha256
        or set(boundaries) != {"scoring", "git", "other_case"}
        or any(
            not rows or any(row.get("readable") is not False for row in rows)
            for rows in boundaries.values()
        )
        or not container.get("container_id")
        or container.get("private_pid_namespace") is not True
        or container.get("root_read_only") is not True
        or not re.fullmatch(r"[0-9a-f]{40}", isolation.get("source_commit", ""))
        or (
            plan.get("source_commit")
            and isolation["source_commit"] != plan["source_commit"]
        )
        or resource.get("evidence_namespace") != request.namespace
        or resource.get("trace_id") != "TRACE-" + request.namespace
        or value.get("model_ledger") != []
    ):
        raise ValueError("worker receipt does not prove this isolated execution")
    copied = SourceResources.model_validate(
        {key: resource.get(key) for key in ("database_name", "index_name")}
    )
    if (
        copied.database_name == request.source_resources.database_name
        or copied.index_name == request.source_resources.index_name
    ):
        raise ValueError("verification did not copy the original resources")
    identities = {
        "database": copied.database_name,
        "index": copied.index_name,
        "checkpoint": resource.get("checkpoint_id"),
        "trace": resource.get("trace_id"),
        "worker": resource.get("worker_nonce"),
        "container": container["container_id"],
    }
    if any(
        not value or (key, value) in used_resources for key, value in identities.items()
    ):
        raise ValueError("verification branches reused a worker or state resource")
    outcome = value.get("outcome")
    if request.verification_enabled:
        if (
            outcome not in {"success", "failure", "insufficient_evidence"}
            or (value.get("validation_result") or {}).get("outcome") != outcome
        ):
            raise ValueError("enabled branch has no deterministic validation result")
    elif (
        outcome != "unverified"
        or value.get("validation_result") is not None
        or value.get("verification_call_count", 0) != 0
        or value.get("verification_attempts", 0) != 0
    ):
        raise ValueError("disabled branch must not perform verification")
    used_resources.update(identities.items())
    return outcome


async def run_verification_plan(
    plan, sources, *, worker, output_dir, approval_verifier=None, now=None
):
    """Persist every planned branch, including missing, ineligible and rejected work."""
    validate_verification_plan(plan)
    output_dir = Path(output_dir)
    write_immutable_json(output_dir / "plan.json", plan)
    records, used_resources = [], set()
    for slot in plan["slots"]:
        current = now or datetime.now(UTC)
        source = sources.get(slot["case_id"])
        status, reason = _eligibility(source, current)
        receipt = None
        if status is None:
            if approval_verifier is None:
                status, reason = "not_executable", "persisted_approval_unavailable"
            else:
                try:
                    receipt = approval_verifier(deepcopy(source))
                    if inspect.isawaitable(receipt):
                        receipt = await receipt
                except Exception:  # noqa: BLE001 -- retain a sanitized unexecuted slot.
                    status, reason = "not_executable", "persisted_approval_unavailable"
        observations = (
            _measurements(source["state"], slot["condition"], current)
            if status is None
            else None
        )
        for branch in slot["branches"]:
            record = {
                "pair_id": slot["pair_id"],
                "case_id": slot["case_id"],
                "dataset": slot["dataset"],
                "branch": branch["branch"],
                "namespace": branch["namespace"],
                "condition_id": slot["condition_id"],
                "status": status,
                "reason": reason,
                "outcome": None,
                "cost": None,
                "approval_status": "approved" if receipt else "unavailable",
            }
            if status is None:
                try:
                    state = deepcopy(source["state"])
                    request = VerificationWorkerRequest(
                        request_id=branch["request_id"],
                        namespace=branch["namespace"],
                        case_id=slot["case_id"],
                        agent_sha256=slot["agent_sha256"],
                        source_state_sha256=canonical_hash(state),
                        approved_plan_sha256=state["approved_plan_sha256"],
                        approval_receipt=receipt,
                        approval_receipt_sha256=canonical_hash(receipt),
                        approved_state=state,
                        source_resources=resource_fields(source["resources"]),
                        verification_enabled=branch["branch"] == "enabled",
                        observations=observations,
                    )
                    write_immutable_json(
                        output_dir / "inputs" / (request.request_id + ".json"),
                        request.model_dump(mode="json"),
                    )
                    value = await worker(request)
                    write_immutable_json(
                        output_dir / "raw" / (request.request_id + ".json"), value
                    )
                    outcome = _validated_worker_result(
                        value, request, plan, used_resources
                    )
                    record.update(
                        status="completed",
                        reason=None,
                        outcome=outcome,
                        cost=value.get("cost"),
                        input_sha256=canonical_hash(request),
                        output_sha256=canonical_hash(value),
                        resource_receipt=value["resource_receipt"],
                        isolation_evidence=value["isolation_evidence"],
                        source_state_sha256=request.source_state_sha256,
                        approved_plan_sha256=request.approved_plan_sha256,
                        diagnostic_snapshot_sha256=state["diagnostic_snapshot_sha256"],
                        verification_call_count=value.get("verification_call_count"),
                        verification_attempts=value.get("verification_attempts"),
                    )
                except Exception as error:  # noqa: BLE001 -- no result can be promoted without its receipt.
                    record.update(
                        status="failed",
                        reason="worker_receipt_invalid",
                        error_type=type(error).__name__,
                    )
            write_immutable_json(
                output_dir / "branches" / (branch["namespace"] + ".json"), record
            )
            records.append(record)
    result = {
        "schema_version": "task13-verification-results-v1",
        "plan_sha256": canonical_hash(plan),
        "planned_pairs": 264,
        "planned_branches": 528,
        "records": records,
        "planned_slots": [
            {
                key: slot[key]
                for key in (
                    "pair_id",
                    "case_id",
                    "dataset",
                    "condition",
                    "condition_id",
                )
            }
            for slot in plan["slots"]
        ],
    }
    write_immutable_json(output_dir / "results.json", result)
    return result
