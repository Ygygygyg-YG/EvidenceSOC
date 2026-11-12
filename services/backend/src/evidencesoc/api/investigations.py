from typing import Annotated, Literal

from fastapi import APIRouter, Header, Query, Request, Response

from evidencesoc.agents.demo_sqli import DemoRegistrationError, is_demo_alert
from evidencesoc.api.alerts import _time_bound
from evidencesoc.api.demo_session import require_demo_session
from evidencesoc.api.dependencies import get_runner
from evidencesoc.api.errors import ApiError
from evidencesoc.api.models import (
    ERROR_RESPONSES,
    EvaluationDetail,
    EvidenceDetail,
    EvidencePage,
    IncidentDetail,
    IncidentPage,
    InvestigationAccepted,
    InvestigationRequest,
    InvestigationSnapshot,
)
from evidencesoc.domain.models import IncidentStatus

router = APIRouter(prefix="/api/v1", responses=ERROR_RESPONSES)


@router.post("/investigations", response_model=InvestigationAccepted, status_code=202)
async def create_investigation(
    body: InvestigationRequest,
    request: Request,
    response: Response,
    idempotency_key: Annotated[str, Header(min_length=1, max_length=128)],
):
    require_demo_session(request, check_origin=True)
    if not idempotency_key.strip():
        raise ApiError(422, "INVALID_REQUEST", "Idempotency key must not be blank.")
    if body.mode != request.app.state.execution_mode:
        raise ApiError(
            409,
            "EXECUTION_MODE_MISMATCH",
            "Requested investigation mode does not match the configured backend mode.",
        )
    runner = get_runner(request)
    demo = getattr(getattr(runner.workflow, "services", None), "demo_registration", None)
    if demo is not None:
        try:
            await demo.authorize_start(body.alert_id, body.incident_id)
        except DemoRegistrationError as error:
            raise ApiError(409, "DEMO_REGISTRATION_INVALID", str(error)) from None
    elif body.alert_id is not None and is_demo_alert(body.alert_id):
        raise ApiError(409, "DEMO_REGISTRATION_INVALID", "请启用 SQL 注入演示配置。")
    metadata, created = await runner.call(
        "create_investigation", **body.model_dump(), idempotency_key=idempotency_key
    )
    request.state.trace_id = metadata["trace_id"]
    await runner.start(metadata)
    response.status_code = 202 if created else 200
    return {
        **metadata,
        "stream_url": f"/api/v1/investigations/{metadata['investigation_id']}/stream",
    }


@router.get("/investigations/{investigation_id}", response_model=InvestigationSnapshot)
async def get_investigation_snapshot(investigation_id: str, request: Request):
    snapshot = await get_runner(request).call(
        "get_investigation_snapshot", investigation_id
    )
    request.state.trace_id = snapshot["trace_id"]
    return {**snapshot, "mode": request.app.state.execution_mode}


@router.get("/incidents", response_model=IncidentPage)
async def list_incidents(
    request: Request,
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=200)] = 20,
    status: IncidentStatus | None = None,
    risk: Literal["high"] | None = None,
    time_from: str | None = None,
    time_to: str | None = None,
):
    if (time_from is None) != (time_to is None):
        raise ApiError(422, "INVALID_REQUEST", "Both time bounds are required.")
    start = _time_bound(time_from) if time_from is not None else None
    end = _time_bound(time_to) if time_to is not None else None
    if start is not None and end is not None and start >= end:
        raise ApiError(422, "INVALID_REQUEST", "Time bounds must be increasing.")
    return await get_runner(request).call(
        "list_incidents", page, page_size, status, start, end, risk
    )


@router.get("/incidents/{incident_id}", response_model=IncidentDetail)
async def get_incident(incident_id: str, request: Request):
    data = await get_runner(request).call("get_incident", incident_id)
    if data.get("trace_id"):
        request.state.trace_id = data["trace_id"]
    return data


@router.get(
    "/incidents/{incident_id}/evidence",
    response_model=EvidencePage,
)
async def list_incident_evidence(
    incident_id: str,
    request: Request,
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=200)] = 20,
):
    return await get_runner(request).call(
        "list_incident_evidence", incident_id, page, page_size
    )


@router.get(
    "/incidents/{incident_id}/evidence/{evidence_id}",
    response_model=EvidenceDetail,
)
async def get_evidence_detail(incident_id: str, evidence_id: str, request: Request):
    require_demo_session(request)
    return await get_runner(request).call(
        "get_evidence_detail", incident_id, evidence_id
    )


@router.get("/evaluations/{evaluation_id}", response_model=EvaluationDetail)
async def get_evaluation(evaluation_id: str, request: Request):
    return await get_runner(request).call("evaluation", evaluation_id)
