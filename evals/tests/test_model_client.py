from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import httpx
import pytest
from pydantic import BaseModel, ValidationError

from evals.adapters.model_client import (
    BudgetAccount,
    BudgetLimit,
    TrackedModel,
    cost_cny,
    project_context,
)
from evals.contracts import ModelConfig


class Answer(BaseModel):
    verdict: str


def test_budget_reservation_is_atomic_and_unknown_cost_never_becomes_zero(tmp_path):
    account = BudgetAccount(tmp_path / "budget.sqlite", total_cny=1, dev_cny=0.5)

    def reserve(i):
        try:
            return account.reserve(str(i), 0.3, "development")
        except BudgetLimit:
            return None

    with ThreadPoolExecutor(max_workers=4) as executor:
        ids = list(executor.map(reserve, range(4)))
    assert sum(x is not None for x in ids) == 1
    account.settle(next(x for x in ids if x), None)
    assert account.summary()["accounted_cny"] == pytest.approx(0.3)
    assert account.summary()["unknown_count"] == 1


def test_no_budget_reset_on_reopen_and_no_negative_settlement(tmp_path):
    path = tmp_path / "budget.sqlite"
    account = BudgetAccount(path, total_cny=1, dev_cny=0.5)
    reservation = account.reserve("one", 0.4, "development")
    with pytest.raises(ValueError):
        account.settle(reservation, -0.1)
    reopened = BudgetAccount(path, total_cny=1, dev_cny=0.5)
    with pytest.raises(BudgetLimit):
        reopened.reserve("two", 0.2, "development")


def test_cache_and_actual_request_time_determine_price():
    offpeak = datetime(2026, 10, 18, 12, tzinfo=timezone.utc)
    peak = datetime(2026, 10, 19, 2, tzinfo=timezone.utc)
    usage = {
        "prompt_tokens": 1000,
        "prompt_cache_hit_tokens": 500,
        "prompt_cache_miss_tokens": 500,
        "completion_tokens": 100,
    }
    assert cost_cny(usage, offpeak) == pytest.approx(0.00091)
    assert cost_cny(usage, peak) == pytest.approx(0.00182)
    assert cost_cny({"prompt_tokens": 10}, offpeak) is None


@pytest.mark.asyncio
async def test_raw_schema_failure_is_charged_and_metadata_preserved(tmp_path):
    requests = []

    def respond(request):
        requests.append(request)
        return httpx.Response(
            200,
            json={
                "id": "req1",
                "model": "v1",
                "choices": [
                    {"message": {"content": '{"bad":true}'}, "finish_reason": "stop"}
                ],
                "usage": {"prompt_tokens": 20, "completion_tokens": 5},
            },
        )

    model = TrackedModel(
        ModelConfig(),
        api_key="test",
        account=BudgetAccount(tmp_path / "budget.sqlite"),
        phase="development",
        transport=httpx.MockTransport(respond),
    )
    with pytest.raises(ValidationError):
        await model.structured("analyze", Answer, {"evidence": []})
    assert len(requests) == 1  # caller owns retries
    assert model.ledger[0]["parse_status"] == "schema_error"
    assert model.ledger[0]["request_id"] == "req1"
    assert model.ledger[0]["cost_cny"] > 0
    assert model.ledger[0]["raw_response"]["choices"]
    assert b'"thinking":{"type":"disabled"}' in requests[0].content


@pytest.mark.asyncio
async def test_observable_model_change_halts_subsequent_dispatch(tmp_path):
    count = 0

    def respond(request):
        nonlocal count
        count += 1
        return httpx.Response(
            200,
            json={
                "id": str(count),
                "model": f"v{count}",
                "choices": [
                    {
                        "message": {"content": '{"verdict":"attack"}'},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {"prompt_tokens": 20, "completion_tokens": 5},
            },
        )

    account = BudgetAccount(tmp_path / "budget.sqlite")
    model = TrackedModel(
        ModelConfig(),
        api_key="test",
        account=account,
        phase="development",
        transport=httpx.MockTransport(respond),
    )
    await model.structured("analyze", Answer, {})
    with pytest.raises(RuntimeError, match="version"):
        await model.structured("analyze", Answer, {})
    with pytest.raises(RuntimeError, match="halt"):
        await model.structured("analyze", Answer, {})
    assert count == 2


@pytest.mark.asyncio
async def test_caller_validation_retries_keep_one_explicit_logical_call(tmp_path):
    def respond(request):
        return httpx.Response(
            200,
            json={
                "id": "req",
                "model": "v1",
                "choices": [
                    {
                        "message": {"content": '{"verdict":"attack"}'},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {"prompt_tokens": 20, "completion_tokens": 5},
            },
        )

    model = TrackedModel(
        ModelConfig(),
        api_key="test",
        account=BudgetAccount(tmp_path / "budget.sqlite"),
        phase="development",
        transport=httpx.MockTransport(respond),
    )
    for _ in range(3):
        await model.structured(
            "analyze", Answer, {"_model_call_id": "logical-one", "evidence": []}
        )
    assert len({entry["logical_call_id"] for entry in model.ledger}) == 1
    assert [entry["physical_attempt"] for entry in model.ledger] == [1, 2, 3]
    with pytest.raises(BudgetLimit):
        await model.structured(
            "analyze", Answer, {"_model_call_id": "logical-one", "evidence": []}
        )


def test_context_projection_keeps_seed_and_new_tool_evidence_within_frozen_limit():
    evidence = [
        {
            "evidence_id": f"EV-{i}",
            "summary": "x" * 3000,
            "raw": {"message": "y" * 3000},
            "content_sha256": "a" * 64,
        }
        for i in range(120)
    ]
    state = {
        "incident_id": "IN-case",
        "alerts": [
            {
                "title": "Observed security events",
                "event_ids": [f"SE-{i}" for i in range(4000)],
            }
        ],
        "evidence": evidence,
        "knowledge": [
            {"knowledge_chunk_id": str(i), "summary": "z" * 30000} for i in range(8)
        ],
    }
    context, details = project_context(state, ModelConfig())
    import json

    assert len(json.dumps(context, ensure_ascii=False, default=str).encode()) <= 65536
    ids = [item["evidence_id"] for item in context["evidence"]]
    assert "EV-0" in ids and "EV-119" in ids
    assert len(context["alerts"][0]["event_ids"]) <= 20
    assert details["evidence_total"] == 120
    assert details["truncated"] is True


def test_context_projection_exposes_only_public_query_scope():
    state={'collection_context':{'allowed_tools':['lookup_attack_technique'],
            'scope':{'alert_id':'AL-case','time_from':'start','time_to':'end','filters':{'host':'h'},'limit':100,
                     'source_scopes':[{'raw':{'message':'unqueried event must remain private'}}]}}}
    projected,_=project_context(state,ModelConfig())
    assert set(projected['collection_context']['scope'])=={'alert_id','time_from','time_to','filters','limit'}
