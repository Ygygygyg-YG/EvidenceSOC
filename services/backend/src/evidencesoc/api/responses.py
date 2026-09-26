from fastapi import APIRouter, Request

from evidencesoc.api.dependencies import get_runner
from evidencesoc.api.models import ERROR_RESPONSES, DecisionAccepted, DecisionRequest

router = APIRouter(prefix="/api/v1/response-plans", responses=ERROR_RESPONSES)


async def decide(plan_id: str, body: DecisionRequest, request: Request, decision: str):
    runner = get_runner(request)
    metadata = await runner.call(
        "record_decision",
        plan_id,
        {**body.model_dump(), "decision": decision, "response_plan_id": plan_id},
    )
    request.state.trace_id = metadata["trace_id"]
    await runner.record_decision(metadata)
    runner.schedule(metadata)
    return {
        "response_plan_id": plan_id,
        "investigation_id": metadata["investigation_id"],
        "incident_id": metadata["incident_id"],
        "trace_id": metadata["trace_id"],
        "decision": decision,
        "status": "accepted",
    }


@router.post("/{plan_id}/approve", status_code=202, response_model=DecisionAccepted)
async def approve(plan_id: str, body: DecisionRequest, request: Request):
    return await decide(plan_id, body, request, "approved")


@router.post("/{plan_id}/reject", status_code=202, response_model=DecisionAccepted)
async def reject(plan_id: str, body: DecisionRequest, request: Request):
    return await decide(plan_id, body, request, "rejected")
