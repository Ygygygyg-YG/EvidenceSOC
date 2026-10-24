"""Offline response boundary regressions; no real model, approval, or F8 writes."""

from __future__ import annotations

import json
from copy import deepcopy
from datetime import datetime
from hashlib import sha256

import pytest
from evidencesoc.agents.capabilities import InvestigationCapabilities
from evidencesoc.agents.graph import _seal_diagnosis
from evidencesoc.agents.models import ResponseOutput
from evidencesoc.agents.nodes import NodeHandlers, validate_output_citations
from evidencesoc.config import Settings
from evidencesoc.domain.response_action import SimulatedAction
from pydantic import ValidationError

EV = "EV-01J8ZW4AAA0ABCDEFGHJKMNPQR"
HOST = "CLIENT2.breach.local"


def response_state(verdict="attack", raw=None):
    state = {
        "incident_id": "IN-fixed",
        "trace_id": "TR-fixed",
        "_run_id": "RUN-fixed",
        "errors": [],
        "evidence": [
            {
                "evidence_id": EV,
                "event_id": "SE-fixed",
                "source": "dedale",
                "observed_at": "2026-10-21T01:00:00+00:00",
                "query": {},
                "summary": "Observed host",
                "content_sha256": "a" * 64,
                "raw": {"host": HOST} if raw is None else raw,
            }
        ],
        "knowledge": [],
        "origin": None,
        "classification": None,
        "diagnosis": {
            "verdict": verdict,
            "attack_types": [],
            "taxonomy_status": "out_of_taxonomy"
            if verdict == "attack"
            else "not_applicable"
            if verdict == "benign"
            else "unknown",
            "origin": None,
            "evidence_ids": [EV],
        },
    }
    state.update(_seal_diagnosis(state, "reconstruct"))
    return state


class Tape:
    def __init__(self, output=None, error=None):
        self.output, self.error, self.calls = output, error, []

    async def structured(self, role, schema, state):
        self.calls.append((role, deepcopy(state)))
        if self.error:
            raise self.error
        return schema.model_validate(deepcopy(self.output))


def handlers(model=None, *, evaluated=True):
    return NodeHandlers(
        object(),
        Settings(_env_file=None, llm_mode="deepseek" if model else "fixture"),
        model,
        capabilities=InvestigationCapabilities() if evaluated else None,
    )


@pytest.mark.asyncio
async def test_explicit_attack_with_cited_host_has_reviewable_rule_plan():
    result = await handlers().respond(response_state())
    assert result["status"] == "awaiting_approval"
    assert result["plan_source"] == "rule_fallback"
    plan = result["response_plan"]
    assert plan["actions"][0]["action"] == "isolate_host_simulated"
    assert plan["actions"][0]["target"] == HOST
    assert plan["actions"][0]["evidence_ids"] == [EV]
    assert plan["requires_approval"] is True
    assert (
        plan["business_impact"] and plan["rollback_steps"] and plan["validation_checks"]
    )
    assert (
        datetime.fromisoformat(plan["expires_at"].replace("Z", "+00:00"))
        - datetime.fromisoformat(plan["created_at"].replace("Z", "+00:00"))
    ).total_seconds() == 1800


@pytest.mark.asyncio
@pytest.mark.parametrize("verdict", ["unknown", "benign"])
async def test_non_attack_does_not_force_response_even_with_legacy_attack_fields(
    verdict,
):
    current = response_state(verdict)
    current.update(
        origin={"observed_source_ip": "8.8.8.8"},
        classification={"primary_type": "sql_injection", "evidence_ids": [EV]},
    )
    model = Tape({"response_plan": None})
    result = await handlers(model).respond(current)
    assert result["response_plan"] is None
    assert result["response_reason"] == "no_actionable_target"
    assert not model.calls


@pytest.mark.asyncio
@pytest.mark.parametrize("corruption", ["missing", "hash", "invalid_diagnosis"])
async def test_eval_response_rejects_unsealed_or_invalid_diagnosis_without_model(
    corruption,
):
    current = response_state()
    if corruption == "missing":
        current.pop("diagnostic_snapshot")
    elif corruption == "hash":
        current["diagnostic_snapshot"]["evidence"][0]["raw"]["host"] = "other"
    else:
        current["diagnostic_snapshot"]["diagnosis"]["verdict"] = "invalid"
        current["diagnostic_snapshot_sha256"] = sha256(
            json.dumps(
                current["diagnostic_snapshot"], sort_keys=True, separators=(",", ":")
            ).encode()
        ).hexdigest()
    model = Tape({"response_plan": None})
    result = await handlers(model).respond(current)
    assert result["response_plan"] is None
    assert result["response_reason"] == "invalid_diagnosis_snapshot"
    assert not model.calls


@pytest.mark.asyncio
async def test_valid_model_null_keeps_observed_reason_and_does_not_invoke_fallback():
    model = Tape({"response_plan": None})
    result = await handlers(model).respond(response_state())
    assert result["response_plan"] is None
    assert result["response_reason"] == "model_returned_null"
    assert result["stop_reason"] == "model_returned_null"
    assert result["plan_source"] == "model"
    assert len(result["response_attempts"]) == 1


@pytest.mark.asyncio
async def test_failed_drafts_keep_every_failure_source_and_fallback_reason():
    valid = (await handlers().respond(response_state()))["response_plan"]
    invalid = deepcopy(valid)
    invalid["incident_id"] = "IN-other"
    model = Tape({"response_plan": invalid})
    result = await handlers(model).respond(response_state())
    assert result["status"] == "awaiting_approval"
    assert result["response_reason"] == "draft_validation_failed"
    assert result["plan_source"] == "rule_fallback"
    attempts = result["response_attempts"]
    assert len(attempts) == 3
    assert all(a["failure_stage"] == "citation_validation" for a in attempts)
    assert all(
        a["draft"]["response_plan"]["incident_id"] == "IN-other" for a in attempts
    )
    assert [a["attempt"] for a in attempts] == [1, 2, 3]
    assert all(
        a["model_call_id"] and a["raw_source"] == "structured_model" for a in attempts
    )


@pytest.mark.asyncio
async def test_provider_exception_text_never_copied_to_response_audit():
    result = await handlers(Tape(error=RuntimeError("Bearer sk-secret-value"))).respond(
        response_state()
    )
    assert "sk-secret" not in json.dumps(result)
    assert len(result["response_attempts"]) == 3
    assert all(a["failure_stage"] == "model_call" for a in result["response_attempts"])


@pytest.mark.asyncio
async def test_response_model_only_sees_sealed_diagnostic_fields():
    current = response_state()
    current["evidence"] = []
    current["diagnosis"] = {"verdict": "unknown"}
    current["origin"] = {"entry_host": "mutated"}
    model = Tape({"response_plan": None})
    await handlers(model).respond(current)
    supplied = model.calls[0][1]
    assert supplied["evidence"] == current["diagnostic_snapshot"]["evidence"]
    assert supplied["diagnosis"] == current["diagnostic_snapshot"]["diagnosis"]
    assert supplied["origin"] is None


@pytest.mark.asyncio
async def test_action_target_must_be_observed_in_its_own_citations():
    current = response_state()
    output = (await handlers().respond(current))["response_plan"]
    other = deepcopy(current["evidence"][0])
    other["evidence_id"] = "EV-01J8ZW4AAA1ABCDEFGHJKMNPQR"
    other["raw"] = {"host": "other-host"}
    current["evidence"].append(other)
    output["evidence_ids"].append(other["evidence_id"])
    output["actions"][0]["evidence_ids"] = [other["evidence_id"]]
    with pytest.raises(ValueError, match="target"):
        validate_output_citations(ResponseOutput(response_plan=output), current)


@pytest.mark.parametrize(
    "target",
    ["alice", "DOMAIN\\alice", "alice@example.org", "alice:admin", "alice..admin"],
)
def test_account_actions_are_refused_without_allowed_account_query(target):
    with pytest.raises(ValidationError):
        SimulatedAction(
            action="disable_account_simulated",
            target=target,
            risk="risk",
            impact="impact",
            preview="preview",
            rollback="rollback",
            verification_query={"filters": {"host": HOST}, "limit": 100},
        )


@pytest.mark.asyncio
async def test_collect_refusal_codes_survive_node_projection():
    class Services:
        async def collect(self, state, run_id):
            return {"collection_refusal_codes": ["POLICY_DENIED"]}

    result = await NodeHandlers(
        Services(), Settings(_env_file=None, llm_mode="fixture")
    ).collect(response_state())
    assert result["collection_refusal_codes"] == ["POLICY_DENIED"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "raw", [{}, {"host": "not a canonical host"}, {"host": "host@example.org"}]
)
async def test_unusable_observed_targets_have_explicit_no_actionable_target(raw):
    result = await handlers().respond(response_state(raw=raw))
    assert result["response_plan"] is None
    assert result["response_reason"] == "no_actionable_target"


@pytest.mark.asyncio
async def test_b3_a4_fixed_http_tape_has_identical_preverification_requests_and_seal(
    tmp_path, monkeypatch
):
    import httpx
    from evidencesoc.agents import fallback, graph, models
    from langgraph.checkpoint.memory import InMemorySaver

    from evals.adapters import model_client
    from evals.contracts import ModelConfig

    fixed = "2026-10-23T01:00:00+00:00"

    class FrozenDateTime(datetime):
        @classmethod
        def now(cls, tz=None):
            value = datetime.fromisoformat(fixed)
            return value if tz is not None else value.replace(tzinfo=None)

    monkeypatch.setattr(graph, "_now", lambda: fixed)
    monkeypatch.setattr(model_client, "datetime", FrozenDateTime)
    monkeypatch.setattr(models, "datetime", FrozenDateTime)
    monkeypatch.setattr(fallback, "datetime", FrozenDateTime)
    seed = response_state()
    tape = [
        {"origin": None, "classification": None, "diagnosis": seed["diagnosis"]},
        {"attack_steps": []},
        {"response_plan": None},
    ]
    outputs, requests, paths = [], [], []
    for enabled in (True, False):
        captured = []

        def respond(request, captured=captured):
            payload = json.loads(request.content)
            captured.append(payload)
            return httpx.Response(
                200,
                json={
                    "id": f"tape-{len(captured)}",
                    "model": "fixed-recorded-model",
                    "choices": [
                        {
                            "finish_reason": "stop",
                            "message": {"content": json.dumps(tape[len(captured) - 1])},
                        }
                    ],
                    "usage": {"prompt_tokens": 10, "completion_tokens": 10},
                },
            )

        class Services:
            def __init__(self):
                self.path = []
                self.verifications = 0

            async def load_incident(self, incident_id):
                return {"alerts": []}

            async def start_run(self, state, role):
                self.path.append(role)
                return "RUN-" + role

            async def finish_run(self, *args):
                pass

            async def collect(self, state, run_id):
                return {"evidence": deepcopy(seed["evidence"]), "knowledge": []}

            async def save_result(self, state):
                pass

            async def verify(self, state, run_id):
                self.verifications += 1
                return {"evidence": [], "executed_checks": []}

        services = Services()
        model = model_client.TrackedModel(
            ModelConfig(),
            api_key="offline-tape-only",
            account=model_client.BudgetAccount(tmp_path / f"{enabled}.sqlite"),
            phase="development",
            transport=httpx.MockTransport(respond),
        )
        capabilities = InvestigationCapabilities(verification_enabled=enabled)
        workflow = graph.InvestigationWorkflow(
            services=services,
            settings=Settings(_env_file=None, llm_mode="deepseek"),
            checkpointer=InMemorySaver(),
            model=model,
            capabilities=capabilities,
        )
        async for _event in workflow.stream_events("IN-fixed", trace_id="TR-fixed"):
            pass
        result = await workflow.get_state("IN-fixed")
        assert result["status"] == "manual_review"
        assert result["response_reason"] == "model_returned_null"
        recorded = result["response_attempts"][0]
        assert recorded["raw_source"] == "model_ledger"
        assert recorded["ledger_request_ordinal"] == 3
        assert recorded["ledger_request_id"] == "tape-3"
        assert recorded["raw_content_sha256"] == sha256(json.dumps(tape[2]).encode()).hexdigest()
        assert services.verifications == 0
        assert len(captured) == len(tape)
        assert result["approval"] is None
        outputs.append(result)
        requests.append(captured)
        paths.append(services.path)
        # The only enabled capability difference acts after the shared seal.
        delta = await workflow.graph.aget_state(workflow._config("IN-fixed"))
        sealed = deepcopy(delta.values)
        sealed["response_plan"] = fallback.respond(sealed).model_dump(mode="json")[
            "response_plan"
        ]
        await NodeHandlers(
            services, workflow.settings, model, capabilities=capabilities
        ).validate({**sealed, "_run_id": "VERIFY-fixed"})
        assert services.verifications == int(enabled)
        assert sealed["diagnostic_snapshot"] == result["diagnostic_snapshot"]
    assert requests[0] == requests[1]
    assert (
        paths[0]
        == paths[1]
        == ["triage", "collect", "analyze", "reconstruct", "respond"]
    )
    assert outputs[0]["diagnostic_snapshot"] == outputs[1]["diagnostic_snapshot"]
    assert (
        outputs[0]["diagnostic_snapshot_sha256"]
        == outputs[1]["diagnostic_snapshot_sha256"]
    )
