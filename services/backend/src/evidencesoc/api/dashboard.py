from typing import Literal

from fastapi import APIRouter, Request

from evidencesoc.api.dependencies import get_runner
from evidencesoc.api.models import (
    ERROR_RESPONSES,
    DashboardSummary,
    SourceHealthSummary,
)

router = APIRouter(prefix="/api/v1/dashboard", responses=ERROR_RESPONSES)
health_router = APIRouter(prefix="/api/v1/data-sources", responses=ERROR_RESPONSES)


@router.get("/summary", response_model=DashboardSummary)
async def summary(request: Request, window: Literal["1h", "24h", "7d"] = "24h"):
    data = await get_runner(request).call("dashboard_summary", window)
    return {**data, "execution_mode": request.app.state.execution_mode}


@health_router.get("/health", response_model=SourceHealthSummary)
async def source_health(request: Request):
    return await get_runner(request).call("source_health")
