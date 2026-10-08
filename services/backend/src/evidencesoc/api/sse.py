from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Header, Request
from sse_starlette.sse import EventSourceResponse, ServerSentEvent

from evidencesoc.agents.graph import TERMINAL_STATES
from evidencesoc.api.dependencies import get_runner
from evidencesoc.api.errors import ApiError
from evidencesoc.api.models import ERROR_RESPONSES

router = APIRouter(prefix="/api/v1/investigations", responses=ERROR_RESPONSES)
BUSINESS_EVENTS = frozenset(
    {
        "investigation.started",
        "status",
        "agent.started",
        "agent.completed",
        "evidence.added",
        "approval.required",
        "decision.recorded",
        "validation.completed",
        "investigation.completed",
        "investigation.failed",
    }
)


def _control_data(investigation_id: str, **details: str) -> str:
    return json.dumps(
        {
            "schema_version": 1,
            "investigation_id": investigation_id,
            "occurred_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            **details,
        }
    )


def _reset(investigation_id: str, reason: str) -> dict[str, str]:
    return {
        "event": "stream.reset",
        "data": _control_data(investigation_id, reason=reason),
    }


def _has_gap(items: list[dict], cursor: int) -> bool:
    return any(item["id"] != cursor + offset for offset, item in enumerate(items, 1))


@router.get(
    "/{investigation_id}/stream",
    response_class=EventSourceResponse,
    responses={200: {"content": {"text/event-stream": {"schema": {"type": "string"}}}}},
)
async def stream(
    investigation_id: str,
    request: Request,
    last_event_id: Annotated[str | None, Header(max_length=20)] = None,
):
    runner = get_runner(request)
    metadata = await runner.call("get_investigation", investigation_id)
    request.state.trace_id = metadata["trace_id"]
    if last_event_id is None:
        cursor = 0
    elif not last_event_id.isascii() or not last_event_id.isdecimal():
        raise ApiError(422, "INVALID_REQUEST", "Invalid event cursor.")
    else:
        cursor = int(last_event_id)

    async def events():
        nonlocal cursor
        if cursor > metadata["last_event_id"]:
            yield _reset(investigation_id, "CURSOR_AHEAD")
            return
        while not await request.is_disconnected():
            current = await runner.call("get_investigation", investigation_id)
            pending = await runner.call("list_events", investigation_id, cursor)
            if _has_gap(pending, cursor) or (
                not pending and current["last_event_id"] > cursor
            ):
                yield _reset(investigation_id, "CURSOR_EXPIRED")
                return
            if any(item["event"] not in BUSINESS_EVENTS for item in pending):
                yield _reset(investigation_id, "UNKNOWN_EVENT")
                return
            for item in pending:
                cursor = item["id"]
                yield {
                    "id": str(cursor),
                    "event": item["event"],
                    "data": json.dumps(item["data"], ensure_ascii=False),
                }
            # Read status first and fetch the final tail afterwards: the producer
            # persists terminal events before setting terminal metadata.
            if current["status"] in TERMINAL_STATES:
                tail = await runner.call("list_events", investigation_id, cursor)
                if _has_gap(tail, cursor):
                    yield _reset(investigation_id, "CURSOR_EXPIRED")
                    return
                if any(item["event"] not in BUSINESS_EVENTS for item in tail):
                    yield _reset(investigation_id, "UNKNOWN_EVENT")
                    return
                for item in tail:
                    cursor = item["id"]
                    yield {
                        "id": str(cursor),
                        "event": item["event"],
                        "data": json.dumps(item["data"], ensure_ascii=False),
                    }
                return
            await asyncio.sleep(0.05)

    return EventSourceResponse(
        events(),
        ping=15,
        ping_message_factory=lambda: ServerSentEvent(
            event="stream.heartbeat", data=_control_data(investigation_id)
        ),
        send_timeout=10,
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
