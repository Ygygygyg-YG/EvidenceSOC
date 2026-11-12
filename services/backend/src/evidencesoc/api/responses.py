from typing import Annotated, Literal

from fastapi import APIRouter, Header, Query, Request, Response

from evidencesoc.agents.demo_sqli import DemoRegistrationError
from evidencesoc.api.demo_session import require_demo_reviewer
from evidencesoc.api.dependencies import get_runner
from evidencesoc.api.errors import ApiError
from evidencesoc.api.models import (
    ERROR_RESPONSES,
    DecisionAccepted,
    DecisionRequest,
    PlanRenewalAccepted,
    PlanRenewalRequest,
    ResponsePlanDetail,
    ResponsePlanPage,
)

router = APIRouter(prefix="/api/v1/response-plans", responses=ERROR_RESPONSES)


@router.get("", response_model=ResponsePlanPage)
async def list_response_plans(
    request: Request,
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=200)] = 20,
    decision_state: Literal["pending", "approved", "rejected"] | None = None,
):
    return await get_runner(request).call(
        "list_response_plans", page, page_size, decision_state
    )


@router.get("/{plan_id}", response_model=ResponsePlanDetail)
async def get_response_plan(plan_id: str, request: Request):
    return await get_runner(request).call("get_response_plan_detail", plan_id)


async def decide(
    plan_id: str,
    body: DecisionRequest,
    request: Request,
    decision: str,
    idempotency_key: str,
):
    if not idempotency_key.strip():
        raise ApiError(422, "INVALID_REQUEST", "Idempotency key must not be blank.")
    actor_id = require_demo_reviewer(request)
    runner = get_runner(request)
    demo = getattr(
        getattr(runner.workflow, "services", None), "demo_registration", None
    )
    if demo is not None and decision == "approved":
        plan = await runner.call("get_response_plan_detail", plan_id)
        if plan["decision_state"] == "pending":
            try:
                registered = await demo.authorize_start(None, plan["incident_id"])
            except DemoRegistrationError as error:
                raise ApiError(409, "DEMO_REGISTRATION_INVALID", str(error)) from None
            if registered and not await runner.workflow.matches_pending_plan_version(
                plan["incident_id"], plan_id, body.plan_version
            ):
                raise ApiError(409, "CONFLICT", "Response plan version is stale.")
    result = await runner.call(
        "record_decision_idempotent",
        plan_id,
        {
            **body.model_dump(),
            "decided_by": actor_id,
            "decision": decision,
            "response_plan_id": plan_id,
        },
        idempotency_key,
    )
    accepted = result["response"]
    request.state.trace_id = accepted["trace_id"]
    if not result["replayed"]:
        metadata = result["metadata"]
        await runner.record_decision(metadata)
        runner.schedule(metadata)
    return accepted


@router.post("/{plan_id}/approve", status_code=202, response_model=DecisionAccepted)
async def approve(
    plan_id: str,
    body: DecisionRequest,
    request: Request,
    idempotency_key: Annotated[str, Header(min_length=1, max_length=255)],
):
    return await decide(plan_id, body, request, "approved", idempotency_key)


@router.post("/{plan_id}/reject", status_code=202, response_model=DecisionAccepted)
async def reject(
    plan_id: str,
    body: DecisionRequest,
    request: Request,
    idempotency_key: Annotated[str, Header(min_length=1, max_length=255)],
):
    return await decide(plan_id, body, request, "rejected", idempotency_key)


@router.post("/{plan_id}/renew", status_code=202, response_model=PlanRenewalAccepted)
async def renew_expired_plan(
    plan_id: str,
    body: PlanRenewalRequest,
    request: Request,
    response: Response,
    idempotency_key: Annotated[str, Header(min_length=1, max_length=255)],
):
    if not idempotency_key.strip():
        raise ApiError(422, "INVALID_REQUEST", "Idempotency key must not be blank.")
    actor_id = require_demo_reviewer(request)
    runner = get_runner(request)
    metadata, created = await runner.call(
        "prepare_plan_renewal", plan_id, body.plan_version, actor_id, idempotency_key
    )
    request.state.trace_id = metadata["trace_id"]
    if created:
        await runner.publish(
            metadata,
            "plan.renewal_requested",
            {
                "response_plan_id": plan_id,
                "plan_version": body.plan_version,
                "requested_by": actor_id,
                "status": "reconstructing",
            },
            "plan-renewal:" + plan_id,
        )
    if metadata["state"].get("pending_renewal"):
        runner.schedule(metadata)
    response.status_code = 202 if created else 200
    return {
        "response_plan_id": plan_id,
        "investigation_id": metadata["investigation_id"],
        "incident_id": metadata["incident_id"],
        "trace_id": metadata["trace_id"],
        "status": "accepted",
        "stream_url": f"/api/v1/investigations/{metadata['investigation_id']}/stream",
    }
