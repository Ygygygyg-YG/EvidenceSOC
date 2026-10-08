from __future__ import annotations

import asyncio
import logging
import time
from contextlib import AsyncExitStack, asynccontextmanager

import httpx
import structlog

from evidencesoc.agents.graph import open_workflow
from evidencesoc.api import (
    alerts,
    dashboard,
    demo_session,
    investigations,
    responses,
    sse,
)
from evidencesoc.api.demo_session import DemoSessionManager
from evidencesoc.api.errors import ApiError, install_error_handlers
from evidencesoc.api.runner import InvestigationRunner
from evidencesoc.api.storage import ApiStore
from evidencesoc.config import Settings, get_settings
from evidencesoc.ids import new_ulid
from evidencesoc.logging import configure_logging, register_secrets
from evidencesoc.openapi import EvidenceSOCApp
from evidencesoc.persistence.database import (
    create_database_engine,
    create_session_factory,
)

logger = structlog.get_logger(__name__)


class RequestAuditMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        scope.setdefault("state", {})["trace_id"] = "TRACE-" + new_ulid()
        started = time.perf_counter()
        status = 503

        async def audited_send(message):
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
                message["headers"].append(
                    (b"x-trace-id", scope["state"]["trace_id"].encode("ascii"))
                )
            await send(message)

        try:
            await self.app(scope, receive, audited_send)
        finally:
            route = scope.get("route")
            logger.info(
                "http_request",
                method=scope["method"],
                route=getattr(route, "path", "<unmatched>"),
                status_code=status,
                duration_ms=round((time.perf_counter() - started) * 1000, 3),
                trace_id=scope["state"]["trace_id"],
            )


def create_app(
    *, settings: Settings | None = None, store=None, workflow=None, readiness_probe=None
) -> EvidenceSOCApp:
    settings = settings or get_settings()

    @asynccontextmanager
    async def lifespan(application):
        configure_logging()
        register_secrets(settings)
        logging.getLogger("uvicorn.access").disabled = True
        async with AsyncExitStack() as stack:
            current_store, current_workflow = store, workflow
            if current_store is None:
                engine = create_database_engine(
                    settings.database_url, bounded_tool_connections=True
                )
                stack.callback(engine.dispose)
                current_store = ApiStore(create_session_factory(engine))
            runner = InvestigationRunner(current_store, current_workflow)
            application.state.runner = runner
            application.state.dependencies_ready = False

            async def prepare():
                try:
                    if runner.workflow is None:
                        runner.workflow = await stack.enter_async_context(
                            open_workflow(settings)
                        )
                    await runner.recover()
                    application.state.dependencies_ready = True
                except Exception as error:  # noqa: BLE001 -- retry without exposing provider details
                    application.state.dependencies_ready = False
                    logger.error(
                        "workflow_unavailable", error_type=type(error).__name__
                    )

            async def supervise():
                while True:
                    await asyncio.sleep(1)
                    await prepare()

            await prepare()
            supervisor = asyncio.create_task(supervise(), name="investigation-recovery")

            async def close_supervisor():
                supervisor.cancel()
                await asyncio.gather(supervisor, return_exceptions=True)

            try:
                yield
            finally:
                await close_supervisor()
                await runner.close()
                application.state.runner = None

    application = EvidenceSOCApp(
        title="EvidenceSOC API", version="0.1.0", lifespan=lifespan
    )
    application.state.execution_mode = (
        "rules" if settings.llm_mode == "fixture" else "model"
    )
    application.state.demo_session_settings = settings
    application.state.demo_sessions = DemoSessionManager(settings)
    application.add_middleware(RequestAuditMiddleware)
    install_error_handlers(application)
    for router in (
        alerts.router,
        dashboard.router,
        dashboard.health_router,
        demo_session.router,
        investigations.router,
        responses.router,
        sse.router,
    ):
        application.include_router(router)

    @application.get("/health/live")
    async def live_health() -> dict[str, str]:
        return {"status": "ok"}

    @application.get("/health/ready")
    async def ready_health():
        runner = getattr(application.state, "runner", None)
        if (
            runner is None
            or runner.workflow is None
            or not application.state.dependencies_ready
        ):
            raise ApiError(
                503, "DEPENDENCY_UNAVAILABLE", "Required dependencies are not ready."
            )

        async def search_ready():
            async with httpx.AsyncClient(timeout=1, trust_env=False) as client:
                result = await client.get(
                    settings.opensearch_url.rstrip("/") + "/_cluster/health"
                )
                result.raise_for_status()
                if result.json().get("status") not in {"yellow", "green"}:
                    raise RuntimeError("unhealthy search dependency")

        try:
            if readiness_probe is not None:
                await asyncio.wait_for(readiness_probe(), timeout=2)
            else:
                await asyncio.wait_for(
                    asyncio.gather(runner.call("ready"), search_ready()), timeout=2
                )
        except Exception:  # noqa: BLE001 -- do not expose dependency configuration
            raise ApiError(
                503, "DEPENDENCY_UNAVAILABLE", "Required dependencies are not ready."
            ) from None
        return {"status": "ok"}

    return application


app = create_app()
