from typing import Annotated

from fastapi import APIRouter, Header, Query, Request, Response

from evidencesoc.api.dependencies import get_runner
from evidencesoc.api.models import ERROR_RESPONSES, AlertPage, AlertRequest
from evidencesoc.domain.models import Alert, IncidentStatus, Severity

router = APIRouter(prefix="/api/v1", responses=ERROR_RESPONSES)


@router.post("/alerts", response_model=Alert, status_code=201)
async def ingest_alert(
    body: AlertRequest,
    request: Request,
    response: Response,
    idempotency_key: Annotated[str | None, Header(min_length=1, max_length=255)] = None,
):
    runner = get_runner(request)
    if idempotency_key is not None and not idempotency_key.strip():
        from evidencesoc.api.errors import ApiError

        raise ApiError(422, "INVALID_REQUEST", "Idempotency key must not be blank.")
    payload = body.model_dump(mode="json", exclude_none=True)
    alert, created = await runner.call("ingest_alert", payload, idempotency_key)
    response.status_code = 201 if created else 200
    return alert


@router.get("/alerts", response_model=AlertPage)
async def list_alerts(
    request: Request,
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=200)] = 50,
    severity: Severity | None = None,
    status: IncidentStatus | None = None,
):
    return await get_runner(request).call(
        "list_alerts", page, page_size, severity, status
    )
