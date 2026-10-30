"""Record actual serialized requests without provider or service access."""

import json
from datetime import UTC, datetime, timedelta
from hashlib import sha256

import httpx
import pytest
from evidencesoc.agents.models import ResponseOutput
from pydantic import BaseModel, ValidationError

from evals.adapters.model_client import BudgetAccount, TrackedModel
from evals.contracts import ModelConfig


class Answer(BaseModel):
    verdict: str


def recording_model(tmp_path, output):
    requests = []

    def respond(request):
        requests.append(request)
        return httpx.Response(
            200,
            json={
                "id": "offline-control",
                "model": "offline-model",
                "choices": [
                    {
                        "finish_reason": "stop",
                        "message": {"content": json.dumps(output)},
                    }
                ],
                "usage": {"prompt_tokens": 10, "completion_tokens": 10},
            },
        )

    return (
        TrackedModel(
            ModelConfig(),
            api_key="synthetic-test-only",
            account=BudgetAccount(tmp_path / "synthetic.sqlite"),
            phase="development",
            transport=httpx.MockTransport(respond),
        ),
        requests,
    )


def response_plan(action, target):
    now = datetime.now(UTC)
    target_field = "host" if action == "isolate_host_simulated" else "source_ip"
    query = {"filters": {target_field: target}, "limit": 100}
    return {
        "response_plan_id": "RP-control",
        "incident_id": "IN-control",
        "summary": "Review the cited observed target.",
        "actions": [
            {
                "action_id": "ACT-control",
                "action": action,
                "type": action,
                "target": target,
                "parameters": {target_field: target},
                "expected_effect": "Record a simulated overlay.",
                "risk": "The identifier can be shared.",
                "impact": "Simulation only.",
                "preview": "Preview the simulated overlay.",
                "rollback": "Remove the simulated overlay.",
                "rollback_ref": "RB-control",
                "verification_query": query,
                "evidence_ids": ["EV-control"],
            }
        ],
        "created_at": now.isoformat(),
        "expires_at": (now + timedelta(minutes=30)).isoformat(),
        "requires_approval": True,
        "execution_mode": "simulation",
        "evidence_ids": ["EV-control"],
        "risk_level": "low",
        "risk_reason": "The identifier can be shared.",
        "affected_assets": [target],
        "business_impact": "Simulation only.",
        "rollback_steps": [
            {
                "step_id": "RB-control",
                "description": "Remove the overlay.",
                "target": target,
                "expected_result": "Overlay removed.",
                "evidence_ids": ["EV-control"],
            }
        ],
        "validation_checks": [
            {
                "check_id": "VC-control",
                "description": "Requery the exact observed target.",
                "target": target,
                "expected_result": "Compare with the cited baseline.",
                "query": query,
                "evidence_ids": ["EV-control"],
            }
        ],
    }


@pytest.mark.asyncio
async def test_respond_payload_exposes_existing_host_target_contract(tmp_path):
    model, requests = recording_model(tmp_path, {"response_plan": None})
    await model.structured(
        "respond", ResponseOutput, {"origin": {"entry_host": "db_server"}}
    )
    payload = json.loads(requests[0].content)
    instruction = payload["messages"][0]["content"]
    for rule in (
        "canonical host identifier",
        "ASCII letters and digits",
        "1 to 63",
        "255",
        "hyphens only inside",
        "no underscores or whitespace",
        "match the observed host identifier exactly",
        "never normalize or invent",
    ):
        assert rule in instruction
    assert "db_server" not in instruction
    context = json.loads(payload["messages"][-1]["content"])
    assert context["origin"]["entry_host"] == "db_server"
    assert len(requests) == 1


@pytest.mark.asyncio
async def test_respond_payload_skips_only_unsupported_actions_and_keeps_plan_complete(
    tmp_path,
):
    model, requests = recording_model(
        tmp_path, {"response_plan": None, "no_plan_reason": "No supported action."}
    )
    await model.structured("respond", ResponseOutput, {})
    instruction = json.loads(requests[0].content)["messages"][0]["content"]
    for rule in (
        "omit only the unsupported action",
        "retain other supported actions",
        "affected_assets, rollback_steps and validation_checks",
        "remaining action targets",
        "If no supported action remains, return response_plan null",
        "no_plan_reason",
    ):
        assert rule in instruction


@pytest.mark.asyncio
async def test_respond_payload_explains_unavailable_account_verification(tmp_path):
    model, requests = recording_model(tmp_path, {"response_plan": None})
    await model.structured("respond", ResponseOutput, {})
    instruction = json.loads(requests[0].content)["messages"][0]["content"]
    assert "disable_account_simulated is unavailable" in instruction
    assert "account filter is not allowed" in instruction
    assert "do not substitute a host or IP filter" in instruction


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "role,body_sha256",
    [
        ("analyze", "b57a522133b727708824886f2d69cfb100bed25ac2c4c4e2f8f1ac1825a063c9"),
        ("collect", "0170282d6e88ef7dd97692de73dacc201ea7c13556540d94c88a8098ec70b13a"),
        (
            "reconstruct",
            "0555566df2678f4be4f80f15195cc9b14c27234994bd5b8781bd0123e018680b",
        ),
    ],
)
async def test_nonrespond_http_body_matches_pre_fix_baseline(
    tmp_path, role, body_sha256
):
    model, requests = recording_model(tmp_path, {"verdict": "attack"})
    await model.structured(
        role,
        Answer,
        {"origin": {"entry_host": "db_server"}, "evidence": [], "knowledge": []},
    )
    assert sha256(requests[0].content).hexdigest() == body_sha256


@pytest.mark.asyncio
async def test_invalid_observed_host_still_fails_and_keeps_accounting(tmp_path):
    output = {"response_plan": response_plan("isolate_host_simulated", "db_server")}
    model, requests = recording_model(tmp_path, output)
    with pytest.raises(ValidationError, match="canonical host identifier"):
        await model.structured(
            "respond", ResponseOutput, {"origin": {"entry_host": "db_server"}}
        )
    assert len(requests) == 1
    assert model.ledger[0]["parse_status"] == "schema_error"
    assert model.ledger[0]["cost_cny"] > 0
    raw = model.ledger[0]["raw_response"]["choices"][0]["message"]["content"]
    assert json.loads(raw) == output


@pytest.mark.asyncio
async def test_supported_observed_ip_action_still_parses_without_rewrite(tmp_path):
    output = {"response_plan": response_plan("block_ip_simulated", "192.0.2.10")}
    model, requests = recording_model(tmp_path, output)
    result = await model.structured(
        "respond", ResponseOutput, {"origin": {"observed_source_ip": "192.0.2.10"}}
    )
    assert result.response_plan.actions[0].target == "192.0.2.10"
    assert len(requests) == 1
    assert model.ledger[0]["parse_status"] == "valid"
    raw = model.ledger[0]["raw_response"]["choices"][0]["message"]["content"]
    assert json.loads(raw) == output
