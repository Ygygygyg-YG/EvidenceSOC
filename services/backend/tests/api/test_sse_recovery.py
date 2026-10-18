from __future__ import annotations

import json
from copy import deepcopy
from types import SimpleNamespace

import pytest
from evidencesoc.api import sse


class FakeRunner:
    def __init__(
        self, *, last_event_id: int, events: list[dict], status: str = "completed"
    ):
        self.metadata = {
            "last_event_id": last_event_id,
            "trace_id": "TRACE-recovery",
            "status": status,
        }
        self.events = events

    async def call(self, name: str, investigation_id: str, *args):
        assert investigation_id == "IV-recovery"
        if name == "get_investigation":
            return self.metadata
        assert name == "list_events"
        return [item for item in self.events if item["id"] > args[0]]


class TailRunner(FakeRunner):
    """Expose the last committed events only in the terminal tail read."""

    reads = 0

    async def call(self, name: str, investigation_id: str, *args):
        result = await super().call(name, investigation_id, *args)
        if name == "list_events":
            self.reads += 1
            if self.reads == 1:
                return result[:1]
        return result


def fake_request():
    async def is_disconnected():
        return False

    return SimpleNamespace(state=SimpleNamespace(), is_disconnected=is_disconnected)


@pytest.mark.asyncio
async def test_heartbeat_is_observable_control_event_without_persistent_id(monkeypatch):
    monkeypatch.setattr(
        sse, "get_runner", lambda _request: FakeRunner(last_event_id=0, events=[])
    )
    response = await sse.stream("IV-recovery", fake_request())

    frame = response.ping_message_factory().encode().decode()
    assert "event: stream.heartbeat" in frame
    assert "\nid:" not in frame
    payload = json.loads(
        next(line[6:] for line in frame.splitlines() if line.startswith("data: "))
    )
    assert payload["schema_version"] == 1
    assert payload["investigation_id"] == "IV-recovery"
    assert payload["occurred_at"].endswith("Z")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("last_event_id", "latest", "retained", "reason"),
    [
        ("5", 4, [1, 2, 3, 4], "CURSOR_AHEAD"),
        ("1", 4, [3, 4], "CURSOR_EXPIRED"),
    ],
)
async def test_stale_cursor_emits_reset_and_ends_stream(
    monkeypatch, last_event_id, latest, retained, reason
):
    events = [
        {"id": number, "event": "agent.started", "data": {}} for number in retained
    ]
    monkeypatch.setattr(
        sse,
        "get_runner",
        lambda _request: FakeRunner(last_event_id=latest, events=events),
    )
    response = await sse.stream(
        "IV-recovery", fake_request(), last_event_id=last_event_id
    )

    frames = [item async for item in response.body_iterator]
    assert len(frames) == 1
    assert frames[0]["event"] == "stream.reset"
    assert "id" not in frames[0]
    assert json.loads(frames[0]["data"])["reason"] == reason


@pytest.mark.asyncio
async def test_contiguous_cursor_replays_only_following_events(monkeypatch):
    events = [
        {"id": 1, "event": "investigation.started", "data": {}},
        {"id": 2, "event": "investigation.completed", "data": {}},
    ]
    monkeypatch.setattr(
        sse, "get_runner", lambda _request: FakeRunner(last_event_id=2, events=events)
    )
    response = await sse.stream("IV-recovery", fake_request(), last_event_id="1")

    frames = [item async for item in response.body_iterator]
    assert [frame["id"] for frame in frames] == ["2"]
    assert [frame["event"] for frame in frames] == ["investigation.completed"]


@pytest.mark.asyncio
async def test_gap_inside_replay_batch_resets_before_emitting_partial_sequence(
    monkeypatch,
):
    events = [
        {"id": 1, "event": "investigation.started", "data": {}},
        {"id": 2, "event": "agent.started", "data": {}},
        {"id": 4, "event": "investigation.completed", "data": {}},
    ]
    monkeypatch.setattr(
        sse, "get_runner", lambda _request: FakeRunner(last_event_id=4, events=events)
    )
    response = await sse.stream("IV-recovery", fake_request(), last_event_id="1")

    frames = [item async for item in response.body_iterator]
    assert len(frames) == 1
    assert frames[0]["event"] == "stream.reset"
    assert json.loads(frames[0]["data"])["reason"] == "CURSOR_EXPIRED"


@pytest.mark.asyncio
async def test_unknown_business_event_resets_instead_of_silently_skipping(monkeypatch):
    events = [
        {"id": 1, "event": "investigation.started", "data": {}},
        {"id": 2, "event": "investigation.future_kind", "data": {}},
    ]
    monkeypatch.setattr(
        sse, "get_runner", lambda _request: FakeRunner(last_event_id=2, events=events)
    )
    response = await sse.stream("IV-recovery", fake_request(), last_event_id="1")

    frames = [item async for item in response.body_iterator]
    assert len(frames) == 1
    assert frames[0]["event"] == "stream.reset"
    assert json.loads(frames[0]["data"])["reason"] == "UNKNOWN_EVENT"


@pytest.mark.asyncio
@pytest.mark.parametrize("runner_type", [FakeRunner, TailRunner])
@pytest.mark.parametrize("event_name", ["plan.renewal_requested", "plan.renewed"])
async def test_historical_renewal_replays_as_status_without_changing_stored_events(
    monkeypatch, runner_type, event_name
):
    renewal_data = {
        "response_plan_id": "RP-expired",
        "plan_version": "v-old",
        "requested_by": "demo-reviewer",
        "incident_id": "IN-recovery",
        "investigation_id": "IV-recovery",
        "trace_id": "TRACE-recovery",
        "occurred_at": "2026-10-18T02:00:00Z",
        "status": "awaiting_approval",
        "output": {"reason": "renew expired plan"},
    }
    events = [
        {"id": 1, "event": "investigation.started", "data": {}},
        {"id": 2, "event": "agent.started", "data": {}},
        {"id": 3, "event": event_name, "data": renewal_data},
        {
            "id": 4,
            "event": "approval.required",
            "data": {
                "response_plan": {"response_plan_id": "RP-fresh"},
                "status": "awaiting_approval",
            },
        },
        {"id": 5, "event": "investigation.completed", "data": {}},
    ]
    persisted = deepcopy(events)
    monkeypatch.setattr(
        sse, "get_runner", lambda _request: runner_type(last_event_id=5, events=events)
    )
    response = await sse.stream("IV-recovery", fake_request(), last_event_id="1")

    frames = [item async for item in response.body_iterator]

    assert [frame.get("event") for frame in frames] == [
        "agent.started",
        "status",
        "approval.required",
        "investigation.completed",
    ]
    assert [frame["id"] for frame in frames] == ["2", "3", "4", "5"]
    assert json.loads(frames[1]["data"]) == {**renewal_data, "status": "reconstructing"}
    assert json.loads(frames[2]["data"]) == persisted[3]["data"]
    assert events == persisted


@pytest.mark.asyncio
async def test_unknown_terminal_tail_event_still_resets(monkeypatch):
    events = [
        {"id": 1, "event": "investigation.started", "data": {}},
        {"id": 2, "event": "agent.started", "data": {}},
        {"id": 3, "event": "plan.future_kind", "data": {}},
    ]
    monkeypatch.setattr(
        sse, "get_runner", lambda _request: TailRunner(last_event_id=3, events=events)
    )
    response = await sse.stream("IV-recovery", fake_request(), last_event_id="1")

    frames = [item async for item in response.body_iterator]

    assert [frame["event"] for frame in frames] == ["agent.started", "stream.reset"]
    assert json.loads(frames[-1]["data"])["reason"] == "UNKNOWN_EVENT"
    assert "id" not in frames[-1]
