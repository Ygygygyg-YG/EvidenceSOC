"""Answer-free access to retained product workflows and human review operations.

Only product state and resource references cross this boundary. Experiment
conditions, expected truth, scoring and controller orchestration stay outside.
"""

from __future__ import annotations

import os
import re
from contextlib import asynccontextmanager
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path

from evidencesoc.agents.capabilities import InvestigationCapabilities
from evidencesoc.agents.checkpoint import open_checkpointer
from evidencesoc.agents.graph import InvestigationWorkflow, _plan_hash
from evidencesoc.agents.nodes import NodeHandlers
from evidencesoc.agents.services import PostgresWorkflowServices
from evidencesoc.config import Settings
from evidencesoc.domain.models import ResponsePlan
from evidencesoc.persistence.database import (
    create_database_engine,
    create_session_factory,
)
from sqlalchemy.engine import make_url

from evals.adapters.model_client import BudgetAccount, TrackedModel
from evals.contracts import canonical_hash


def resource_fields(reference):
    """Keep retained-reference metadata outside the worker resource schema."""
    return {
        key: reference[key]
        for key in ("database_name", "index_name")
        if key in reference
    }


def _require_inspected_renewal_model(model, reference):
    from evals.adapters.budget_v2 import PURPOSE_PHASES, SupplementBudgetAccount
    from evals.adapters.remediation_contracts import CAMPAIGN
    from evals.adapters.remediation_worker import StableCallModel

    budget = os.environ.get("TASK13_BUDGET_DB")
    commit = os.environ.get("TASK13_SOURCE_COMMIT", "")
    valid_model = (
        isinstance(model, TrackedModel)
        and isinstance(model.account, BudgetAccount)
        and not isinstance(model.account, SupplementBudgetAccount)
        and model.phase == "verification"
    )
    if type(model) is StableCallModel and type(model.model) is TrackedModel:
        binding = (
            model.account.request_binding()
            if type(model.account) is SupplementBudgetAccount
            else {}
        )
        purpose = binding.get("purpose")
        valid_model = (
            type(model.model) is TrackedModel
            and type(model.account) is SupplementBudgetAccount
            and binding.get("campaign_id") == CAMPAIGN
            and binding.get("group") == "B3"
            and purpose in {"f8", "development"}
            and model.phase == PURPOSE_PHASES[purpose]
            and model.slot_id.startswith(purpose + "-review-")
            and model.run_id
            == CAMPAIGN
            + "-"
            + canonical_hash([model.slot_id, binding.get("attempt")])[:16]
        )
    if (
        not valid_model
        or not budget
        or not Path(budget).is_file()
        or model.account.path.resolve() != Path(budget).resolve()
        or os.environ.get("TASK13_PHASE") != "verification"
        or os.getpid() != 1
        or not os.environ.get("TASK13_WORKER_NONCE")
        or re.fullmatch(r"[0-9a-f]{40}", commit) is None
        or reference.get("source_commit") != commit
    ):
        raise PermissionError(
            "renewal requires the inspected tracked model and shared budget account"
        )
    # Loading an existing account verifies its persisted limits and never resets it.
    BudgetAccount(Path(budget), total_cny=100, dev_cny=15)


def _require_renewal_workflow(workflow):
    model = getattr(workflow, "_task13_renewal_model", None)
    nodes = getattr(workflow, "_task13_review_nodes", None)
    if (
        nodes is None
        or nodes.model is not model
        or workflow.services.planner_model is not model
        or workflow.settings.llm_mode != "deepseek"
    ):
        raise PermissionError("renewal requires the bound tracked workflow factory")
    _require_inspected_renewal_model(model, workflow._task13_source_reference)


@asynccontextmanager
async def open_retained_workflow(reference, *, model=None):
    """Open the original retained checkpoint; only a tracked worker may renew it."""
    # Import locally: the worker contract also imports these workflow helpers.
    from evals.adapters.verification_worker import SourceResources

    resources = SourceResources.model_validate(resource_fields(reference))
    if model is not None:
        _require_inspected_renewal_model(model, reference)
    base = Settings(_env_file=None)
    url = make_url(base.database_url)
    if url.get_backend_name() != "postgresql":
        raise ValueError("retained approval workflow requires PostgreSQL")
    database_url = url.set(database=resources.database_name).render_as_string(
        hide_password=False
    )
    settings = Settings(
        _env_file=None,
        database_url=database_url,
        opensearch_url=base.opensearch_url,
        opensearch_index=resources.index_name,
        rag_data_directory=base.rag_data_directory,
        llm_mode="deepseek" if model is not None else "fixture",
    )
    engine = create_database_engine(database_url)
    policy = InvestigationCapabilities()
    services = PostgresWorkflowServices(
        settings,
        session_factory=create_session_factory(engine),
        capabilities=policy,
        model_timeout=model.config.timeout_seconds if model else 120,
    )
    services.planner_model = model
    nodes = NodeHandlers(
        services,
        settings,
        model,
        capabilities=policy,
        model_timeout=model.config.timeout_seconds if model else 120,
    )
    previous = {
        key: os.environ.get(key) for key in ("DATABASE_URL", "OPENSEARCH_INDEX")
    }
    try:
        os.environ["DATABASE_URL"] = database_url
        os.environ["OPENSEARCH_INDEX"] = resources.index_name
        async with open_checkpointer(database_url) as saver:
            workflow = InvestigationWorkflow(
                services=services,
                settings=settings,
                checkpointer=saver,
                model=model,
                nodes=nodes,
                capabilities=policy,
                database_url=database_url,
            )
            workflow._task13_renewal_model = model
            workflow._task13_review_nodes = nodes
            workflow._task13_source_reference = deepcopy(reference)
            yield workflow
    finally:
        try:
            await services.aclose()
        finally:
            engine.dispose()
            for key, value in previous.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value


def _snapshot_valid(state):
    snapshot = state.get("diagnostic_snapshot")
    return isinstance(snapshot, dict) and state.get(
        "diagnostic_snapshot_sha256"
    ) == _plan_hash(snapshot)


def build_approval_packet(
    case: dict, state: dict, *, now: datetime | None = None
) -> dict:
    """Materialize review details from an actual saved B3 state, without a decision."""
    if not _snapshot_valid(state):
        raise ValueError("a valid sealed B3 snapshot is required for review")
    plan = ResponsePlan.model_validate(state.get("response_plan"))
    current = now or datetime.now(UTC)
    return {
        "schema_version": "task13-response-review-v1",
        "case_id": case["case_id"],
        "dataset": case["dataset"],
        "incident_id": state["incident_id"],
        "reviewer": "user",
        "review_window": "19:00-00:00 Asia/Shanghai",
        "state_sha256": canonical_hash(state),
        "diagnostic_snapshot_sha256": state["diagnostic_snapshot_sha256"],
        "plan_sha256": _plan_hash(state["response_plan"]),
        "response_plan": deepcopy(state["response_plan"]),
        "decision": None,
        "status": "renewal_required"
        if plan.expires_at is None or plan.expires_at <= current
        else "pending",
        "renewal_method": "original InvestigationWorkflow.renew_plan",
    }


async def _matching_workflow_state(workflow, packet):
    state = await workflow.get_state(packet["incident_id"])
    if (
        canonical_hash(state) != packet.get("state_sha256")
        or not _snapshot_valid(state)
        or state.get("diagnostic_snapshot_sha256")
        != packet["diagnostic_snapshot_sha256"]
        or _plan_hash(state.get("response_plan")) != packet["plan_sha256"]
    ):
        raise PermissionError(
            "saved workflow differs from the reviewed B3 state or plan"
        )
    return state


async def apply_human_decision(workflow, packet, *, decision, reason, decided_by):
    """Call the original persistent approval path only for an explicit human input."""
    if (
        decided_by != "user"
        or decision not in {"approved", "rejected"}
        or not reason.strip()
    ):
        raise PermissionError(
            "only the registered human may record an approval decision"
        )
    state = await _matching_workflow_state(workflow, packet)
    plan = ResponsePlan.model_validate(state["response_plan"])
    if state.get("status") != "awaiting_approval":
        raise PermissionError("the original workflow is not awaiting this approval")
    if plan.expires_at is None or plan.expires_at <= datetime.now(UTC):
        raise PermissionError("expired plan requires original product renewal")
    return await workflow.approve(
        state["incident_id"],
        response_plan_id=plan.response_plan_id,
        decision=decision,
        reason=reason,
        decided_by=decided_by,
    )


async def renew_expired_plan(workflow, packet, *, requested_by):
    if requested_by != "user":
        raise PermissionError("only the registered human may request renewal")
    state = await _matching_workflow_state(workflow, packet)
    plan = ResponsePlan.model_validate(state["response_plan"])
    _require_renewal_workflow(workflow)
    # Regeneration, hydration and any model call remain in the original workflow;
    # the caller must provide its inspected worker and frozen paid-call account.
    return await workflow.renew_plan(
        state["incident_id"],
        response_plan_id=plan.response_plan_id,
        requested_by=requested_by,
    )
