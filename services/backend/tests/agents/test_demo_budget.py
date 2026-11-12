import asyncio
import sqlite3
from contextlib import closing

import httpx
import pytest
from evidencesoc.agents.demo_budget import (
    DemoBudgetError,
    create_demo_model_client,
    model_request_context,
    read_demo_budget,
)

URL = "https://api.deepseek.com/chat/completions"
REQUEST = {
    "model": "deepseek-flash",
    "messages": [{"role": "user", "content": "private-prompt-value"}],
    "max_tokens": 4096,
    "stream": False,
}


def completion(*, prompt_tokens=100, completion_tokens=50):
    return httpx.Response(
        200,
        headers={"x-request-id": "request-1"},
        json={
            "id": "completion-1",
            "model": "deepseek-flash",
            "choices": [{"message": {"content": "private-completion-value"}}],
            "usage": {
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "total_tokens": prompt_tokens + completion_tokens,
            },
        },
    )


@pytest.mark.asyncio
async def test_reserves_before_forward_and_persists_usage_without_payload(tmp_path):
    path = tmp_path / "budget.sqlite3"
    response_closed = False

    class ResponseStream(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield completion().content

        async def aclose(self):
            nonlocal response_closed
            response_closed = True

    async def respond(request):
        summary = read_demo_budget(path)
        assert summary.reserved_cny == 2.129920
        assert summary.in_flight == 1
        return httpx.Response(
            200, headers={"x-request-id": "request-1"}, stream=ResponseStream()
        )

    async with create_demo_model_client(
        path, transport=httpx.MockTransport(respond)
    ) as client:
        context = model_request_context.set(
            {"role": "analyze", "incident_id": "IN-demo", "model_call_id": "call-1"}
        )
        try:
            response = await client.post(
                URL,
                json=REQUEST,
                headers={"Authorization": "Bearer private-api-key-value"},
            )
        finally:
            model_request_context.reset(context)

    assert (
        response.json()["choices"][0]["message"]["content"]
        == "private-completion-value"
    )
    assert response_closed
    summary = read_demo_budget(path)
    assert summary.spent_cny == 0.000600
    assert summary.reserved_cny == 0
    assert summary.settled == summary.requests == 1
    with closing(sqlite3.connect(path)) as db:
        assert db.execute(
            "SELECT role, incident_id, model_call_id, response_model, provider_request_id, "
            "prompt_tokens, completion_tokens FROM demo_model_requests"
        ).fetchone() == (
            "analyze",
            "IN-demo",
            "call-1",
            "deepseek-flash",
            "request-1",
            100,
            50,
        )
    assert b"private-" not in path.read_bytes()


@pytest.mark.asyncio
async def test_prior_spend_reduces_reservation_capacity_after_restart(tmp_path):
    path = tmp_path / "budget.sqlite3"
    forwards = 0

    def respond(request):
        nonlocal forwards
        forwards += 1
        return completion(prompt_tokens=440_000, completion_tokens=1)

    transport = httpx.MockTransport(respond)
    async with create_demo_model_client(path, transport=transport) as client:
        await client.post(URL, json=REQUEST)
    async with create_demo_model_client(path, transport=transport) as client:
        with pytest.raises(DemoBudgetError, match="3 CNY"):
            await client.post(URL, json=REQUEST)

    assert forwards == 1
    assert read_demo_budget(path).spent_cny == 0.880008


@pytest.mark.parametrize(
    "failure", ["missing_usage", "bad_usage", "transport", "redirect"]
)
@pytest.mark.asyncio
async def test_unknown_cost_blocks_new_requests_after_restart(tmp_path, failure):
    path = tmp_path / "budget.sqlite3"
    forwards = 0

    def respond(request):
        nonlocal forwards
        forwards += 1
        if failure == "transport":
            raise httpx.ReadTimeout("offline transport failure", request=request)
        if failure == "redirect":
            return httpx.Response(
                307, headers={"Location": "https://unapproved.example/"}
            )
        if failure == "bad_usage":
            return completion(completion_tokens=4097)
        return httpx.Response(200, json={"model": "deepseek-flash"})

    transport = httpx.MockTransport(respond)
    async with create_demo_model_client(path, transport=transport) as client:
        if failure == "redirect":
            assert (await client.post(URL, json=REQUEST)).status_code == 307
        else:
            with pytest.raises((DemoBudgetError, httpx.ReadTimeout)):
                await client.post(URL, json=REQUEST)

    async with create_demo_model_client(path, transport=transport) as client:
        with pytest.raises(DemoBudgetError, match="unresolved"):
            await client.post(URL, json=REQUEST)

    assert forwards == 1
    summary = read_demo_budget(path)
    assert summary.unknown == 1
    assert summary.spent_cny == 0
    assert summary.reserved_cny == 2.129920
    assert summary.blocked


@pytest.mark.asyncio
async def test_outstanding_reservation_serializes_independent_clients(tmp_path):
    path = tmp_path / "budget.sqlite3"
    forwarded = asyncio.Event()
    finish = asyncio.Event()

    async def respond(request):
        forwarded.set()
        await finish.wait()
        return completion()

    async with (
        create_demo_model_client(path, transport=httpx.MockTransport(respond)) as first,
        create_demo_model_client(
            path, transport=httpx.MockTransport(respond)
        ) as second,
    ):
        pending = asyncio.create_task(first.post(URL, json=REQUEST))
        await asyncio.wait_for(forwarded.wait(), timeout=5)
        try:
            with pytest.raises(DemoBudgetError, match="unresolved"):
                await second.post(URL, json=REQUEST)
        finally:
            finish.set()
            await pending
        assert (await second.post(URL, json=REQUEST)).status_code == 200

    assert read_demo_budget(path).settled == 2


@pytest.mark.asyncio
async def test_process_interruption_leaves_outstanding_reservation_after_restart(
    tmp_path,
):
    path = tmp_path / "budget.sqlite3"
    forwards = 0

    class ProcessInterrupted(BaseException):
        pass

    def respond(request):
        nonlocal forwards
        forwards += 1
        raise ProcessInterrupted

    transport = httpx.MockTransport(respond)
    async with create_demo_model_client(path, transport=transport) as client:
        with pytest.raises(ProcessInterrupted):
            await client.post(URL, json=REQUEST)

    async with create_demo_model_client(path, transport=transport) as client:
        with pytest.raises(DemoBudgetError, match="unresolved"):
            await client.post(URL, json=REQUEST)

    assert forwards == 1
    summary = read_demo_budget(path)
    assert summary.in_flight == 1
    assert summary.reserved_cny == 2.129920
    assert summary.blocked


@pytest.mark.parametrize(
    ("url", "changes"),
    [
        ("https://unapproved.example/chat/completions", {}),
        ("https://api.deepseek.com/v1/chat/completions", {}),
        (URL, {"model": "deepseek-v4-pro"}),
        (URL, {"stream": True}),
        (URL, {"max_tokens": True}),
        (URL, {"max_tokens": 0}),
        (URL, {"max_tokens": 4097}),
        (URL, {"max_completion_tokens": 5000}),
        (URL, {"tools": [{"type": "web_search"}]}),
    ],
)
@pytest.mark.asyncio
async def test_unbounded_or_wrong_destination_is_never_forwarded(
    tmp_path, url, changes
):
    path = tmp_path / "budget.sqlite3"

    def respond(request):
        pytest.fail("invalid request was forwarded")

    async with create_demo_model_client(
        path, transport=httpx.MockTransport(respond)
    ) as client:
        with pytest.raises(DemoBudgetError):
            await client.post(url, json={**REQUEST, **changes})

    assert read_demo_budget(path).requests == 0
