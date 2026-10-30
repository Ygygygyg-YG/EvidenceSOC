"""Fresh SELECT-only review of owned product state; no worker or decision API."""

from __future__ import annotations

import asyncio
import os
from contextlib import nullcontext
from datetime import UTC, datetime
from pathlib import Path
from time import monotonic

from evidencesoc.domain.models import ApprovalRecord, ResponsePlan
from evidencesoc.persistence.tables import (
    ApprovalTable,
    IncidentTable,
    ResponsePlanTable,
)
from sqlalchemy import select, text

from evals.adapters.e_planning_journal import EPlanningDispatchJournal
from evals.adapters.e_planning_review import (
    EPlanningReviewRequest,
    require_review_window,
    validate_review_state,
)
from evals.adapters.e_planning_worker import _claim_binding
from evals.adapters.planning_analysis import verify_planning_analysis
from evals.adapters.retained_workflow import (
    build_approval_packet,
    open_retained_workflow,
)
from evals.adapters.verification_worker import read_persisted_approval
from evals.contracts import canonical_hash


def _aware(value):
    return (
        value.replace(tzinfo=UTC)
        if isinstance(value, datetime) and value.tzinfo is None
        else value
    )


def validate_product_rows(request, state, incident, row, approvals):
    """Join the exact checkpoint incident, plan and decision to actual product rows."""
    plan = ResponsePlan.model_validate(state.get("response_plan"))
    if (
        state.get("incident_id") != request.incident_id
        or plan.incident_id != request.incident_id
        or incident is None
        or incident.incident_id != request.incident_id
        or incident.status != state.get("status")
        or row is None
        or ResponsePlan.model_validate(
            {key: _aware(getattr(row, key)) for key in ResponsePlan.model_fields}
        )
        != plan
    ):
        raise PermissionError("actual incident or plan rows differ from checkpoint")
    approval = state.get("approval")
    if approval is None:
        if approvals:
            raise PermissionError("checkpoint omits an actual product decision")
    elif len(approvals) != 1 or ApprovalRecord.model_validate(
        {key: _aware(getattr(approvals[0], key)) for key in ApprovalRecord.model_fields}
    ) != ApprovalRecord.model_validate(approval):
        raise PermissionError("actual product decision differs from checkpoint")


def _checkpoint_readonly(workflow, database):
    with (
        workflow.checkpointer.conn.connection() as connection,
        connection.cursor() as cursor,
    ):
        cursor.execute(
            "SELECT current_database() AS database_name, "
            "current_setting('transaction_read_only') AS read_only"
        )
        value = cursor.fetchone()
    if value["database_name"] != database or value["read_only"] != "on":
        raise PermissionError(
            "checkpoint connection is not the owned read-only database"
        )
    return dict(value)


def _product_snapshot(workflow, request, state):
    with workflow.services._sessions() as session:
        database, readonly = session.execute(
            text("SELECT current_database(), current_setting('transaction_read_only')")
        ).one()
        if database != request.source_resources.database_name or readonly != "on":
            raise PermissionError(
                "product connection is not the owned read-only database"
            )
        incident = session.get(IncidentTable, request.incident_id)
        plan = state.get("response_plan") or {}
        row = session.get(ResponsePlanTable, plan.get("response_plan_id"))
        approvals = session.scalars(
            select(ApprovalTable).where(
                ApprovalTable.response_plan_id == plan.get("response_plan_id")
            )
        ).all()
        validate_product_rows(request, state, incident, row, approvals)
        receipt = None
        if (state.get("approval") or {}).get("decision") == "approved":
            receipt = read_persisted_approval(state, lambda: nullcontext(session))
        return {
            "database_name": database,
            "read_only": readonly,
            "approval_receipt": receipt,
        }


async def read_retained_review_state(request):
    """Low-level diagnostic read, conveying no source/dispatch authorization."""
    request = EPlanningReviewRequest.model_validate(request.model_dump(mode="json"))
    if request.operation != "read_packet":
        raise PermissionError("host reader supports read_packet only")
    start = datetime.now(UTC)
    tick = monotonic()
    reference = {
        **request.source_resources.model_dump(mode="json"),
        "incident_id": request.incident_id,
        "source_commit": request.source_commit,
    }
    async with open_retained_workflow(
        reference, model=None, verification_enabled=False, readonly=True
    ) as workflow:
        checkpoint = await asyncio.to_thread(
            _checkpoint_readonly, workflow, request.source_resources.database_name
        )
        config = workflow._config(request.incident_id)
        first = await workflow.graph.aget_state(config)
        state = dict(first.values)
        if not state:
            raise PermissionError("owned checkpoint is missing")
        product = await asyncio.to_thread(_product_snapshot, workflow, request, state)
        second = await workflow.graph.aget_state(config)
        if first.config != second.config or canonical_hash(state) != canonical_hash(
            dict(second.values)
        ):
            raise PermissionError("actual checkpoint changed during read-only review")
    packet = build_approval_packet(
        {"case_id": request.case_id, "dataset": request.dataset},
        state,
        participation_policy=request.planning_request.participation_policy,
    )
    return {
        "state": state,
        "approval_packet": packet,
        "approval_receipt": product["approval_receipt"],
        "host_read_receipt": {
            "schema_version": "task13-e-host-review-read-v1",
            "origin": "host_original_postgresql_read",
            "request_sha256": canonical_hash(request),
            "resources_sha256": canonical_hash(request.case_resource),
            "state_sha256": canonical_hash(state),
            "database_name": reference["database_name"],
            "checkpoint_transaction_read_only": checkpoint["read_only"],
            "business_transaction_read_only": product["read_only"],
            "started_at": start.isoformat(),
            "finished_at": datetime.now(UTC).isoformat(),
            "elapsed_seconds": monotonic() - tick,
            "provider_calls": 0,
            "model_calls": 0,
            "mcp_calls": 0,
            "decisions_written": 0,
            "dispatch_authority": False,
        },
    }


def _host_context(request, agent_dir, options):
    import json

    from scripts.task13_worker_runtime import validate_e_planning_host

    planning = request.planning_request
    dependencies = json.loads(
        (Path(options["dependencies_dir"]) / "task13_dependencies.json").read_bytes()
    )
    validate_e_planning_host(planning, agent_dir, options, dependencies, review=True)
    journal = EPlanningDispatchJournal.open_existing(
        Path(options["import_dispatch_path"]),
        expected_registration_sha256=planning.registration_sha256,
        expected_authority_sha256=options["planning_authority_sha256"],
    )

    def claim():
        return _claim_binding(planning, journal.validate_request(planning))

    binding = claim()
    if binding["status"] != "started":
        raise PermissionError(
            "host review requires its original started planning claim"
        )
    imported = verify_planning_analysis(
        planning,
        Path(options["import_source_dir"]),
        Path(options["budget_dir"]) / "campaign.sqlite",
    )
    return imported, binding, claim


async def read_e_planning_host_review(request, agent_dir, options):
    """Host read adapter with fresh full source, claim, product and seal checks."""
    request = EPlanningReviewRequest.model_validate(request.model_dump(mode="json"))
    if (
        request.operation != "read_packet"
        or os.getpid() == 1
        or os.environ.get("TASK13_WORKER_NONCE")
    ):
        raise PermissionError("read_packet host admission required")
    policy = request.planning_request.participation_policy
    require_review_window(participation_policy=policy)
    imported, binding, claim = _host_context(request, agent_dir, options)
    if claim() != binding:
        raise PermissionError("host planning claim changed before fresh product read")
    result = await read_retained_review_state(request)
    state = result["state"]
    validate_review_state(request, state, imported, binding)
    if claim() != binding:
        raise PermissionError("host planning claim changed after fresh product read")
    approval = state.get("approval")
    if approval is not None:
        require_review_window(
            datetime.fromisoformat(approval["decided_at"].replace("Z", "+00:00")),
            policy,
        )
    require_review_window(participation_policy=policy)
    return {
        "status": "completed",
        "operation": "read_packet",
        "request_id": request.request_id,
        "input_sha256": canonical_hash(request),
        "source_state_sha256": canonical_hash(state),
        "planning_slot_id": request.planning_request.planning_slot_id,
        "registration_sha256": request.planning_request.registration_sha256,
        "selected_source_lineage_sha256": request.planning_request.selected_source_lineage_sha256,
        "source": {
            "state": state,
            "resources": {
                **request.source_resources.model_dump(mode="json"),
                "incident_id": request.incident_id,
                "source_commit": request.source_commit,
            },
        },
        "approval_packet": result["approval_packet"],
        "approval_receipt": result["approval_receipt"],
        "host_read_receipt": result["host_read_receipt"],
        "model_ledger": [],
        "tool_ledger": [],
    }
