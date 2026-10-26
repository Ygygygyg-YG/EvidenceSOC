"""Future candidate instructions; no real provider or original campaign writes."""

import json

import httpx
import pytest
from evidencesoc.agents import fallback
from evidencesoc.agents.model import DeepSeekStructuredModel
from evidencesoc.agents.nodes import validate_output_citations
from evidencesoc.config import Settings
from pydantic import BaseModel


class Answer(BaseModel):
    verdict: str


def assert_scope_rule(instruction):
    for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"):
        assert cidr in instruction
    assert "diagnosis.origin.source_scope" in instruction
    assert "observed_source_ip" in instruction
    assert "internal" in instruction and "external" in instruction
    assert "otherwise use unknown" in instruction
    assert (
        "Origin attribution and ATT&CK technique mapping are separate from the verdict"
        in instruction
    )
    assert "positively explained by the supplied evidence as routine" in instruction
    assert "Absence of attack indicators alone does not establish benign" in instruction


@pytest.mark.asyncio
async def test_product_analyze_message_explains_the_existing_scope_rule(monkeypatch):
    messages = []

    class Client:
        def with_structured_output(self, schema):
            return self

        async def ainvoke(self, value):
            messages.extend(value)
            return {"verdict": "unknown"}

    model = DeepSeekStructuredModel(Settings(_env_file=None, llm_mode="fixture"))
    monkeypatch.setattr(model, "client", lambda: Client())
    await model.structured("analyze", Answer, {"evidence": []})
    assert_scope_rule(messages[0][1])


@pytest.mark.asyncio
async def test_tracked_analyze_http_body_explains_the_same_scope_rule(tmp_path):
    from evals.adapters.model_client import BudgetAccount, TrackedModel
    from evals.contracts import ModelConfig

    captured = []

    def respond(request):
        captured.append(json.loads(request.content))
        return httpx.Response(503, json={"error": "synthetic-unavailable"})

    model = TrackedModel(
        ModelConfig(),
        api_key="synthetic",
        phase="development",
        account=BudgetAccount(tmp_path / "budget.sqlite"),
        transport=httpx.MockTransport(respond),
    )
    with pytest.raises(httpx.HTTPStatusError):
        await model.structured("analyze", Answer, {"evidence": []})
    assert len(captured) == 1
    instruction = captured[0]["messages"][0]["content"]
    assert_scope_rule(instruction)
    # Preserve the existing schema boundary: prose cannot become trailing JSON.
    assert (
        json.loads(instruction.split("JSON schema:\n", 1)[1])
        == Answer.model_json_schema()
    )
    assert instruction.index("diagnosis.origin.source_scope") < instruction.index(
        "JSON schema:\n"
    )


@pytest.mark.parametrize(
    "address,expected",
    [
        ("10.182.193.78", "internal"),
        ("172.16.0.1", "internal"),
        ("172.31.255.254", "internal"),
        ("192.168.1.2", "internal"),
        ("fd00::1", "internal"),
        ("8.8.8.8", "external"),
        ("127.0.0.1", "unknown"),
        ("192.0.2.1", "unknown"),
        (None, "unknown"),
    ],
)
def test_scope_grounding_keeps_the_original_address_semantics(address, expected):
    assert fallback.source_scope(address) == expected


def test_instruction_does_not_accept_the_observed_internal_ip_as_external():
    state = {
        "evidence": [
            {
                "evidence_id": "EV-01J8ZW4AAA0ABCDEFGHJKMNPQR",
                "event_id": "SE-01J8ZW4AAA0ABCDEFGHJKMNPQR",
                "source": "synthetic",
                "query": {},
                "summary": "Observed request",
                "content_sha256": "a" * 64,
                "observed_at": "2026-10-21T01:00:00+00:00",
                "raw": {"source_ip": "10.182.193.78", "message": "union select"},
            }
        ],
        "knowledge": [],
    }
    valid = fallback.analyze(state)
    validate_output_citations(valid, state)
    invalid = valid.model_copy(
        update={
            "origin": valid.origin.model_copy(update={"source_scope": "external"}),
        }
    )
    with pytest.raises(ValueError, match="source scope is not established"):
        validate_output_citations(invalid, state)
