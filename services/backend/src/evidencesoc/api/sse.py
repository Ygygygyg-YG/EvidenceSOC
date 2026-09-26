from __future__ import annotations

import asyncio
import json
from typing import Annotated

from fastapi import APIRouter, Header, Request
from sse_starlette.sse import EventSourceResponse

from evidencesoc.agents.graph import TERMINAL_STATES
from evidencesoc.api.dependencies import get_runner
from evidencesoc.api.errors import ApiError
from evidencesoc.api.models import ERROR_RESPONSES

router = APIRouter(prefix="/api/v1/investigations", responses=ERROR_RESPONSES)


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
    if cursor > metadata["last_event_id"]:
        raise ApiError(
            422, "INVALID_REQUEST", "Event cursor exceeds the current stream."
        )

    async def events():
        nonlocal cursor
        while not await request.is_disconnected():
            pending = await runner.call("list_events", investigation_id, cursor)
            for item in pending:
                cursor = item["id"]
                yield {
                    "id": str(cursor),
                    "event": item["event"],
                    "data": json.dumps(item["data"], ensure_ascii=False),
                }
            # Read status first and fetch the final tail afterwards: the producer
            # persists terminal events before setting terminal metadata.
            current = await runner.call("get_investigation", investigation_id)
            if current["status"] in TERMINAL_STATES:
                tail = await runner.call("list_events", investigation_id, cursor)
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
        send_timeout=10,
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
