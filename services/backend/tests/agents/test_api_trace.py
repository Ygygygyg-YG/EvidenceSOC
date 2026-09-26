import pytest

from .test_graph import workflow


@pytest.mark.asyncio
async def test_api_trace_is_used_by_all_graph_events_and_survives_resume():
    flow = workflow()
    events = [
        item async for item in flow.stream_events("IN-api-trace", trace_id="TRACE-api")
    ]
    assert events and all(item["trace_id"] == "TRACE-api" for item in events)
    replay = [
        item
        async for item in flow.stream_events("IN-api-trace", trace_id="TRACE-other")
    ]
    assert all(item["trace_id"] == "TRACE-api" for item in replay)


@pytest.mark.asyncio
async def test_graph_events_have_unique_durable_replay_keys():
    flow = workflow()
    events = [item async for item in flow.stream_events("IN-api-events")]
    assert all(item.get("event_uuid") for item in events)
    assert len({item["event_uuid"] for item in events}) == len(events)
    replay = [item async for item in flow.stream_events("IN-api-events")]
    assert [item["event_uuid"] for item in replay] == [
        item["event_uuid"] for item in events
    ]
