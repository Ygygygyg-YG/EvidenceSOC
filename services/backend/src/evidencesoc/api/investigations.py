from fastapi import APIRouter, Request, Response

from evidencesoc.api.dependencies import get_runner
from evidencesoc.api.models import (
    ERROR_RESPONSES,
    EvaluationDetail,
    IncidentDetail,
    InvestigationAccepted,
    InvestigationRequest,
)

router = APIRouter(prefix="/api/v1", responses=ERROR_RESPONSES)


@router.post("/investigations", response_model=InvestigationAccepted, status_code=202)
async def create_investigation(
    body: InvestigationRequest, request: Request, response: Response
):
    runner = get_runner(request)
    metadata, created = await runner.call("create_investigation", **body.model_dump())
    request.state.trace_id = metadata["trace_id"]
    await runner.start(metadata)
    response.status_code = 202 if created else 200
    return {
        **metadata,
        "stream_url": f"/api/v1/investigations/{metadata['investigation_id']}/stream",
    }


@router.get("/incidents/{incident_id}", response_model=IncidentDetail)
async def get_incident(incident_id: str, request: Request):
    data = await get_runner(request).call("get_incident", incident_id)
    if data.get("trace_id"):
        request.state.trace_id = data["trace_id"]
    return data


@router.get("/evaluations/{evaluation_id}", response_model=EvaluationDetail)
async def get_evaluation(evaluation_id: str, request: Request):
    return await get_runner(request).call("evaluation", evaluation_id)
