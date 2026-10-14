import re
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Header, Query, Request, Response

from evidencesoc.api.dependencies import get_runner
from evidencesoc.api.errors import ApiError
from evidencesoc.api.models import ERROR_RESPONSES, AlertDetail, AlertPage, AlertRequest
from evidencesoc.domain.models import Alert, IncidentStatus, Severity

router = APIRouter(prefix="/api/v1", responses=ERROR_RESPONSES)
ISO_AWARE_TIME = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})\Z"
)


def _time_bound(value: str) -> datetime:
    if not ISO_AWARE_TIME.fullmatch(value):
        raise ApiError(
            422, "INVALID_REQUEST", "Time bounds must be ISO-8601 with a timezone."
        )
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ApiError(
            422, "INVALID_REQUEST", "Time bounds must be valid timestamps."
        ) from exc
    if parsed.tzinfo is None:
        raise ApiError(422, "INVALID_REQUEST", "Time bounds must include a timezone.")
    return parsed.astimezone(UTC)


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
    time_from: str | None = None,
    time_to: str | None = None,
    query: str | None = None,
):
    if (time_from is None) != (time_to is None):
        raise ApiError(422, "INVALID_REQUEST", "Both time bounds are required.")
    start = _time_bound(time_from) if time_from is not None else None
    end = _time_bound(time_to) if time_to is not None else None
    if start is not None and end is not None and start >= end:
        raise ApiError(422, "INVALID_REQUEST", "Time bounds must be increasing.")
    if query is not None:
        query = query.strip()
        if not 1 <= len(query) <= 200 or any(ord(char) < 32 for char in query):
            raise ApiError(
                422, "INVALID_REQUEST", "Query must contain 1 to 200 text characters."
            )
    return await get_runner(request).call(
        "list_alerts", page, page_size, severity, status, start, end, query
    )


@router.get("/alerts/{alert_id:path}", response_model=AlertDetail)
async def get_alert(alert_id: str, request: Request):
    detail = await get_runner(request).call("get_alert", alert_id)
    return {**detail, "execution_mode": request.app.state.execution_mode}
