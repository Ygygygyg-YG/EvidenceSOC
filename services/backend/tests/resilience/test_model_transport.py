"""Real structured adapter over loopback HTTP; no external provider requests."""

import pytest
from evidencesoc.agents.collection import BoundedCollector
from evidencesoc.agents.model import DeepSeekStructuredModel
from tests.agents.test_collection_planner import SCOPE
from tests.security.support import model_surrogate


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("failure", "code"),
    [
        ("timeout", "MODEL_TIMEOUT"),
        ("503", "MODEL_UNAVAILABLE"),
        ("invalid", "MODEL_INVALID_OUTPUT"),
    ],
)
async def test_http_model_failure_preserves_tool_budget_and_rules_resume(
    memory_ledger, failure, code
):
    calls = []

    async def invoke(name, arguments):
        calls.append((name, arguments))
        return []

    with model_surrogate(failure=failure) as (settings, requests):
        planner = BoundedCollector(
            ledger=memory_ledger,
            invoke=invoke,
            scope=SCOPE,
            state={"incident_id": "IN-1", "approval": None, "simulation": None},
            run_id="AR-1",
            model=DeepSeekStructuredModel(settings),
            llm_mode="deepseek",
            model_timeout=0.15 if failure == "timeout" else 5,
        )
        report = await planner.run()
    assert len(requests) == report["collection_model_attempts"] == 3
    assert (
        report["fallback_used"]
        and report["collection_stop_reason"] == "no_new_evidence"
    )
    retry = [
        item
        for item in report["collection_observations"]
        if item["status"] == "planner_retry"
    ]
    assert len(retry) == 3 and {item["error_code"] for item in retry} == {code}
    assert [name for name, _ in calls] == [
        "get_alert_context",
        "search_security_events",
    ]
    assert calls[1][1] == {
        key: SCOPE[key] for key in ("time_from", "time_to", "filters", "limit")
    }
    assert report["collection_budget_used"] == report["collection_tool_attempts"] == 2
    assert report["evidence_values"] == []
    assert not {"approval", "simulation", "validation_result"} & report.keys()
    assert all(
        row.status == "completed" and row.attempts == 1
        for row in memory_ledger.calls("IN-1", 1)
    )
