from __future__ import annotations

import asyncio
import importlib
import json
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from typing import Any

import pytest
from evidencesoc.config import Settings
from pydantic import ValidationError

EV = "EV-01J8ZW4AAA0ABCDEFGHJKMNPQR"
EV2 = "EV-01J8ZW4AAA1ABCDEFGHJKMNPQR"
KC = "KC-" + "a" * 60


def evidence(evidence_id: str = EV, **raw: Any) -> dict[str, Any]:
    return {
        "evidence_id": evidence_id,
        "event_id": "EVT-1",
        "source": "web",
        "observed_at": "2026-09-26T00:00:00Z",
        "query": {"filters": {"source_ip": "198.51.100.10"}},
        "summary": "Observed web request.",
        "content_sha256": "a" * 64,
        "raw": {
            "source_ip": "198.51.100.10",
            "host": "web-1",
            "service": "http",
            "request_uri": "/users?id=1%20UNION%20SELECT%20password%20FROM%20users",
            **raw,
        },
    }


def state(**changes: Any) -> dict[str, Any]:
    return {
        "incident_id": "IN-1",
        "trace_id": "TR-1",
        "_run_id": "RUN-1",
        "status": "collecting",
        "alerts": [{"alert_id": "AL-1", "title": "SQL injection", "severity": "high"}],
        "evidence": [evidence()],
        "knowledge": [
            {
                "knowledge_chunk_id": KC,
                "technique_id": "T1190",
                "source_uri": "https://attack.mitre.org/techniques/T1190/",
            }
        ],
        "errors": [],
        "fallback_count": 0,
        "fallback_used": False,
        **changes,
    }


class Services:
    def __init__(
        self,
        *,
        collected: dict[str, Any] | None = None,
        verified: list[dict[str, Any]] | None = None,
        executed_checks: list[dict[str, Any]] | None = None,
    ) -> None:
        self.collected = collected or {"evidence": [evidence()], "knowledge": []}
        self.verified = [evidence(EV2)] if verified is None else verified
        self.executed_checks = executed_checks
        self.calls: list[tuple[str, str]] = []

    async def load_incident(self, incident_id: str) -> dict[str, Any]:
        self.calls.append(("load", incident_id))
        return {"alerts": state()["alerts"], "status": "received"}

    async def collect(self, current: dict[str, Any], run_id: str) -> dict[str, Any]:
        self.calls.append(("collect", run_id))
        return self.collected

    async def verify(self, current: dict[str, Any], run_id: str) -> dict[str, Any]:
        self.calls.append(("verify", run_id))
        result = {"evidence": self.verified}
        if self.executed_checks is None:
            plan = current["response_plan"]
            result["executed_checks"] = [
                {
                    "check_id": plan["validation_checks"][index]["check_id"],
                    "condition": {
                        "time_from": "2026-09-26T00:00:00+00:00",
                        "time_to": "2026-09-26T00:05:00+00:00",
                        "filters": action["verification_query"]["filters"],
                        "limit": action["verification_query"].get("limit", 100),
                    },
                    "evidence_ids": [item["evidence_id"] for item in self.verified],
                }
                for index, action in enumerate(plan["actions"])
            ]
        else:
            result["executed_checks"] = self.executed_checks
        return result


def handlers(services: Services | None = None, **kwargs: Any) -> Any:
    module = importlib.import_module("evidencesoc.agents.nodes")
    return module.NodeHandlers(
        services or Services(), Settings(_env_file=None, llm_mode="fixture"), **kwargs
    )


@pytest.mark.asyncio
async def test_fixture_nodes_return_json_state_without_mutating_inputs() -> None:
    current = state()
    original = deepcopy(current)
    nodes = handlers()
    for role in ("triage", "collect", "analyze", "reconstruct", "respond"):
        current = {**current, **await getattr(nodes, role)(current)}
        json.dumps(current, allow_nan=False)
    assert original == state()
    assert current["fallback_used"] is True
    assert current["origin"]["observed_source_ip"] == "198.51.100.10"
    assert current["classification"]["primary_type"] == "sql_injection"
    assert current["classification"]["technique_ids"] == ["T1190"]
    assert current["attack_steps"][0]["evidence_ids"] == [EV]
    assert current["response_plan"]["requires_approval"] is True
    assert current["status"] == "awaiting_approval"


@pytest.mark.asyncio
async def test_response_target_must_be_observed_in_its_cited_evidence() -> None:
    class InventedTarget:
        async def structured(self, role, schema, current):
            from evidencesoc.agents.fallback import respond

            output = respond(current).model_dump(mode="json")
            output["response_plan"]["actions"][0]["target"] = "8.8.4.4"
            output["response_plan"]["actions"][0]["verification_query"]["filters"] = {
                "source_ip": "8.8.4.4"
            }
            return schema.model_validate(output)

    current = await response_state()
    module = importlib.import_module("evidencesoc.agents.nodes")
    nodes = module.NodeHandlers(
        Services(), Settings(_env_file=None, llm_mode="deepseek"), InventedTarget()
    )
    result = await nodes.respond(current)
    assert result["fallback_used"] is True
    assert result["response_plan"]["actions"][0]["target"] == "198.51.100.10"


@pytest.mark.asyncio
async def test_model_schemas_reject_values_larger_than_database_columns() -> None:
    current = await response_state()
    module = importlib.import_module("evidencesoc.agents.models")
    plan = current["response_plan"]
    with pytest.raises(ValidationError):
        module.ResponseOutput.model_validate(
            {"response_plan": {**plan, "response_plan_id": "R" * 65}}
        )
    step = current["attack_steps"][0]
    with pytest.raises(ValidationError):
        module.AttackStep.model_validate({**step, "phase": "P" * 65})


@pytest.mark.asyncio
async def test_triage_loads_the_incident_and_collect_uses_current_run() -> None:
    services = Services()
    nodes = handlers(services)
    assert (await nodes.triage(state()))["status"] == "triaged"
    await nodes.collect(state())
    assert services.calls == [("load", "IN-1"), ("collect", "RUN-1")]


@pytest.mark.asyncio
async def test_collect_merges_by_citation_id_without_changing_retry_count() -> None:
    fresh = evidence(EV2)
    nodes = handlers(
        Services(
            collected={
                "evidence": [evidence(), fresh],
                "knowledge": state()["knowledge"],
            }
        )
    )
    result = await nodes.collect(state(fallback_count=1))
    assert [item["evidence_id"] for item in result["evidence"]] == [EV, EV2]
    assert len(result["knowledge"]) == 1
    assert "fallback_count" not in result


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "raw",
    [
        {"request_uri": "/home"},
        {
            "request_uri": "/home",
            "attack_type": "sql_injection",
            "labels": ["sql_injection"],
        },
    ],
)
async def test_alert_title_and_ground_truth_never_create_attack_facts(
    raw: dict[str, Any],
) -> None:
    result = await handlers().analyze(state(evidence=[evidence(**raw)]))
    assert (
        result["classification"] is None
        or result["classification"]["primary_type"] == "unknown"
    )
    assert not result.get("attack_steps")


@pytest.mark.asyncio
async def test_zero_evidence_does_not_invent_ids_to_satisfy_domain_models() -> None:
    result = await handlers().analyze(state(evidence=[]))
    assert result["origin"] is None
    assert result["classification"] is None
    result = await handlers().respond({**state(evidence=[]), **result})
    assert result["response_plan"] is None


@pytest.mark.asyncio
async def test_technique_mapping_requires_current_retrieved_knowledge() -> None:
    result = await handlers().analyze(state(knowledge=[]))
    assert result["classification"]["primary_type"] == "sql_injection"
    assert result["classification"]["technique_ids"] == []


@pytest.mark.asyncio
async def test_reconstruction_orders_observations_by_time() -> None:
    nodes = handlers()
    current = state(
        evidence=[{**evidence(EV2), "observed_at": "2026-09-26T01:00:00Z"}, evidence()]
    )
    current.update(await nodes.analyze(current))
    result = await nodes.reconstruct(current)
    assert [step["evidence_ids"] for step in result["attack_steps"]] == [[EV], [EV2]]
    assert [step["sequence"] for step in result["attack_steps"]] == [1, 2]


def action(**changes: Any) -> dict[str, Any]:
    return {
        "action": "block_ip_simulated",
        "target": "198.51.100.10",
        "risk": "May affect shared clients.",
        "impact": "Preview only.",
        "preview": "Simulate blocking this source.",
        "rollback": "Remove simulated block.",
        "verification_query": {"filters": {"source_ip": "198.51.100.10"}},
        **changes,
    }


@pytest.mark.parametrize(
    "changes",
    [
        {"action": "block_ip"},
        {"rollback": ""},
        {"target": "1; rm -rf /"},
        {"verification_query": {"shell": "echo secrets"}},
        {"verification_query": {"filters": {"url": "https://example.com"}}},
    ],
)
def test_action_schema_rejects_unbounded_actions_and_incomplete_plans(
    changes: dict[str, Any],
) -> None:
    schema = importlib.import_module("evidencesoc.agents.models").SimulatedAction
    with pytest.raises(ValidationError):
        schema.model_validate(action(**changes))


@pytest.mark.asyncio
async def test_response_actions_are_complete_and_use_only_simulated_allowlist() -> None:
    nodes = handlers()
    current = state()
    current.update(await nodes.analyze(current))
    current.update(await nodes.reconstruct(current))
    plan = (await nodes.respond(current))["response_plan"]
    schema = importlib.import_module("evidencesoc.agents.models").SimulatedAction
    assert plan["incident_id"] == "IN-1"
    assert len(plan["actions"]) >= 1
    for item in plan["actions"]:
        schema.model_validate(item)
        assert item["action_id"].startswith("ACT-")
        assert item["type"] == item["action"]
        assert item["parameters"] == {"source_ip": item["target"]}
        assert item["expected_effect"]
        assert item["rollback_ref"] in {
            step["step_id"] for step in plan["rollback_steps"]
        }
        assert item["evidence_ids"]
        assert set(item["evidence_ids"]) <= set(plan["evidence_ids"])


@pytest.mark.asyncio
async def test_response_rejects_action_citations_outside_plan_and_mismatched_target() -> (
    None
):
    current = await response_state()
    plan = current["response_plan"]
    schema = importlib.import_module("evidencesoc.agents.models").ResponseOutput

    for change in (
        {"evidence_ids": [EV2]},
        {"parameters": {"source_ip": "198.51.100.11"}},
        {"rollback_ref": "RB-not-in-plan"},
        {"type": "isolate_host_simulated"},
    ):
        invalid = deepcopy(plan)
        invalid["actions"][0].update(change)
        with pytest.raises(ValidationError):
            schema.model_validate({"response_plan": invalid})


@pytest.mark.asyncio
async def test_model_response_must_include_review_and_expiry_details() -> None:
    current = await response_state()
    plan = current["response_plan"]
    schema = importlib.import_module("evidencesoc.agents.models").ResponseOutput
    for omitted in (
        "risk_level",
        "risk_reason",
        "affected_assets",
        "business_impact",
        "expires_at",
        "rollback_steps",
        "validation_checks",
    ):
        incomplete = {key: value for key, value in plan.items() if key != omitted}
        with pytest.raises(ValidationError):
            schema.model_validate({"response_plan": incomplete})
    unbounded = {
        **plan,
        "expires_at": (datetime.now(UTC) + timedelta(days=1)).isoformat(),
    }
    with pytest.raises(ValidationError):
        schema.model_validate({"response_plan": unbounded})


class BrokenModel:
    def __init__(self, timeout: bool = False) -> None:
        self.calls = 0
        self.timeout = timeout

    async def structured(self, role: str, schema: Any, current: dict[str, Any]) -> Any:
        self.calls += 1
        if self.timeout:
            await asyncio.sleep(1)
        raise RuntimeError("API key very-secret, Authorization: token")


@pytest.mark.asyncio
@pytest.mark.parametrize("timeout", [False, True])
async def test_unavailable_model_has_three_bounded_attempts_and_sanitized_errors(
    timeout: bool,
) -> None:
    model = BrokenModel(timeout)
    module = importlib.import_module("evidencesoc.agents.nodes")
    nodes = module.NodeHandlers(
        Services(),
        Settings(_env_file=None, llm_mode="deepseek"),
        model=model,
        model_timeout=0.01,
    )
    result = await nodes.analyze(state())
    assert model.calls == 3
    assert result["fallback_used"] is True
    assert result["classification"]["primary_type"] == "sql_injection"
    encoded = json.dumps(result)
    assert "very-secret" not in encoded
    assert "Authorization" not in encoded
    assert result["errors"][-1]["code"] in {"MODEL_UNAVAILABLE", "MODEL_TIMEOUT"}


@pytest.mark.asyncio
async def test_fixture_never_calls_the_injected_model() -> None:
    model = BrokenModel()
    await handlers(model=model).analyze(state())
    assert model.calls == 0


class HallucinatingModel:
    async def structured(self, role: str, schema: Any, current: dict[str, Any]) -> Any:
        return schema.model_validate(
            {
                "origin": {
                    "observed_source_ip": "198.51.100.99",
                    "entry_host": None,
                    "entry_service": None,
                    "first_seen_at": None,
                    "source_scope": "external",
                    "confidence": 1,
                    "evidence_ids": ["EV-missing"],
                },
                "classification": {
                    "primary_type": "sql_injection",
                    "attack_types": ["sql_injection"],
                    "attack_phase": "initial_access",
                    "confidence": 1,
                    "evidence_ids": ["EV-missing"],
                },
            }
        )


@pytest.mark.asyncio
async def test_model_outputs_with_unknown_citations_cannot_become_supported_facts() -> (
    None
):
    module = importlib.import_module("evidencesoc.agents.nodes")
    nodes = module.NodeHandlers(
        Services(),
        Settings(_env_file=None, llm_mode="deepseek"),
        model=HallucinatingModel(),
    )
    result = await nodes.analyze(state())
    assert result["classification"] is None or result["classification"][
        "evidence_ids"
    ] == [EV]
    assert result["origin"] is None or result["origin"]["evidence_ids"] == [EV]
    assert result["fallback_used"] is True


async def response_state() -> dict[str, Any]:
    nodes = handlers()
    current = state()
    for role in ("analyze", "reconstruct", "respond"):
        current.update(await getattr(nodes, role)(current))
    current["approval"] = {
        "approval_id": "AP-1",
        "response_plan_id": current["response_plan"]["response_plan_id"],
        "decision": "approved",
        "reason": "Reviewed preview.",
        "decided_by": "reviewer",
        "decided_at": datetime.now(UTC).isoformat(),
    }
    current["simulation"] = [
        {
            "action": "block_ip_simulated",
            "target": "198.51.100.10",
            "status": "simulated",
        }
    ]
    plan = current["response_plan"]
    version = sha256(
        json.dumps(plan, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    current["approved_plan_sha256"] = version
    current["approved_plan_version"] = version
    current["simulation_execution"] = {
        "simulation_id": "SIM-1",
        "response_plan_id": plan["response_plan_id"],
        "plan_version": version,
        "status": "completed",
        "started_at": datetime.now(UTC).isoformat(),
        "finished_at": datetime.now(UTC).isoformat(),
        "action_results": [
            {
                "action_id": action["action_id"],
                "outcome": "success",
                "description": "The simulated action completed.",
                "started_at": datetime.now(UTC).isoformat(),
                "finished_at": datetime.now(UTC).isoformat(),
            }
            for action in plan["actions"]
        ],
        "error": None,
    }
    return current


@pytest.mark.asyncio
async def test_validation_requeries_and_explicitly_limits_success_to_simulation() -> (
    None
):
    current = await response_state()
    check_id = current["response_plan"]["validation_checks"][0]["check_id"]
    condition = {
        "time_from": "2026-09-26T00:00:00+00:00",
        "time_to": "2026-09-26T00:05:00+00:00",
        "filters": {"source_ip": "198.51.100.10"},
        "limit": 10,
    }
    services = Services(
        executed_checks=[
            {"check_id": check_id, "condition": condition, "evidence_ids": [EV2]}
        ]
    )
    result = await handlers(services).validate(current)
    assert services.calls == [("verify", "RUN-1")]
    assert result["validation_result"]["outcome"] == "success"
    assert result["validation_result"]["evidence_ids"] == [EV2]
    assert "simulat" in result["validation_result"]["summary"].lower()
    assert datetime.fromisoformat(
        result["validation_result"]["time_from"]
    ) == datetime.fromisoformat(condition["time_from"])
    assert datetime.fromisoformat(
        result["validation_result"]["time_to"]
    ) == datetime.fromisoformat(condition["time_to"])
    assert result["validation_result"]["checks"] == [
        {
            "check_id": check_id,
            "condition": condition,
            "outcome": "success",
            "evidence_ids": [EV2],
            "explanation": "The approved simulated action matched freshly queried target evidence; this does not prove a real-world effect.",
        }
    ]


@pytest.mark.asyncio
async def test_validation_empty_query_result_is_insufficient_not_success() -> None:
    current = await response_state()
    check_id = current["response_plan"]["validation_checks"][0]["check_id"]
    result = await handlers(
        Services(
            verified=[],
            executed_checks=[
                {
                    "check_id": check_id,
                    "condition": {
                        "time_from": "2026-09-26T00:00:00+00:00",
                        "time_to": "2026-09-26T00:05:00+00:00",
                        "filters": {"source_ip": "198.51.100.10"},
                        "limit": 10,
                    },
                    "evidence_ids": [],
                }
            ],
        )
    ).validate(current)
    assert result["validation_result"]["outcome"] == "insufficient_evidence"
    assert result["validation_result"]["evidence_ids"] == [EV]
    assert result["stop_reason"] == "insufficient_evidence"
    assert result["validation_result"]["checks"][0]["evidence_ids"] == []
    assert (
        result["validation_result"]["checks"][0]["outcome"] == "insufficient_evidence"
    )


@pytest.mark.asyncio
async def test_fixture_cannot_bypass_citation_gate_with_malformed_evidence() -> None:
    with pytest.raises(ValueError):
        await handlers().analyze(state(evidence=[evidence("")]))


@pytest.mark.asyncio
async def test_no_response_plan_explicitly_stops_for_human_review() -> None:
    result = await handlers().respond(state(origin=None, classification=None))
    assert result["status"] == "manual_review"


@pytest.mark.asyncio
async def test_validation_without_any_evidence_requests_human_review() -> None:
    current = await response_state()
    current["evidence"] = []
    result = await handlers(Services(verified=[])).validate(current)
    assert result["validation_result"] is None
    assert result["status"] == "manual_review"


@pytest.mark.asyncio
async def test_validation_matches_target_in_new_evidence() -> None:
    result = await handlers(
        Services(verified=[evidence(EV2, source_ip="203.0.113.9")])
    ).validate(await response_state())
    assert result["validation_result"]["outcome"] == "insufficient_evidence"


@pytest.mark.asyncio
async def test_validation_simulator_failure_remains_failure() -> None:
    current = await response_state()
    current["simulation_execution"]["action_results"][0]["outcome"] = "failure"
    result = await handlers().validate(current)
    assert result["validation_result"]["outcome"] == "failure"


@pytest.mark.asyncio
async def test_validation_requires_approval_for_the_exact_plan() -> None:
    current = await response_state()
    current["approval"]["response_plan_id"] = "RP-other"
    result = await handlers().validate(current)
    assert (
        result["validation_result"] is None
        or result["validation_result"]["outcome"] != "success"
    )


@pytest.mark.asyncio
async def test_http_path_is_observation_data_without_labels_or_truth() -> None:
    item = evidence(
        request_uri="/home",
        http={"path": "/search?q=' OR 1=1--", "labels": ["sql_injection"]},
    )
    result = await handlers().analyze(state(evidence=[item]))
    assert result["classification"]["primary_type"] == "sql_injection"
    raw = importlib.import_module("evidencesoc.agents.fallback").observed_raw(item)
    assert raw["http"] == {"path": "/search?q=' OR 1=1--"}


class UnobservedOriginModel:
    async def structured(self, role: str, schema: Any, current: dict[str, Any]) -> Any:
        output = (
            importlib.import_module("evidencesoc.agents.fallback")
            .analyze(current)
            .model_dump(mode="json")
        )
        output["origin"]["observed_source_ip"] = "203.0.113.99"
        return schema.model_validate(output)


@pytest.mark.asyncio
async def test_model_cannot_invent_origin_even_with_an_existing_citation() -> None:
    module = importlib.import_module("evidencesoc.agents.nodes")
    nodes = module.NodeHandlers(
        Services(),
        Settings(_env_file=None, llm_mode="deepseek"),
        model=UnobservedOriginModel(),
    )
    result = await nodes.analyze(state())
    assert result["origin"]["observed_source_ip"] == "198.51.100.10"
    assert result["fallback_used"] is True


@pytest.mark.asyncio
async def test_reconstruction_sorts_actual_instants_across_offsets() -> None:
    current = state(
        evidence=[
            {**evidence(), "observed_at": "2026-09-26T09:00:00+08:00"},
            {**evidence(EV2), "observed_at": "2026-09-26T02:00:00Z"},
        ]
    )
    nodes = handlers()
    current.update(await nodes.analyze(current))
    result = await nodes.reconstruct(current)
    assert [step["evidence_ids"] for step in result["attack_steps"]] == [[EV], [EV2]]


class ValidModel:
    def __init__(self) -> None:
        self.calls = 0

    async def structured(self, role: str, schema: Any, current: dict[str, Any]) -> Any:
        self.calls += 1
        output = importlib.import_module("evidencesoc.agents.fallback").analyze(current)
        return schema.model_validate(output.model_dump())


@pytest.mark.asyncio
async def test_valid_structured_model_keeps_cloud_result_without_fallback() -> None:
    module = importlib.import_module("evidencesoc.agents.nodes")
    model = ValidModel()
    result = await module.NodeHandlers(
        Services(), Settings(_env_file=None, llm_mode="deepseek"), model=model
    ).analyze(state())
    assert model.calls == 1
    assert result["fallback_used"] is False
    assert result["errors"] == []


def test_reconstruction_schema_rejects_duplicate_sequences() -> None:
    module = importlib.import_module("evidencesoc.agents.models")
    step = {
        "attack_step_id": "AS-1",
        "sequence": 1,
        "phase": "initial_access",
        "technique_id": None,
        "description": "Observed SQL pattern.",
        "occurred_at": "2026-09-26T00:00:00Z",
        "evidence_ids": [EV],
    }
    with pytest.raises(ValidationError):
        module.ReconstructionOutput.model_validate(
            {"attack_steps": [step, {**step, "attack_step_id": "AS-2"}]}
        )


def test_action_verification_query_must_match_its_target() -> None:
    schema = importlib.import_module("evidencesoc.agents.models").SimulatedAction
    with pytest.raises(ValidationError):
        schema.model_validate(
            action(verification_query={"filters": {"source_ip": "203.0.113.99"}})
        )


@pytest.mark.asyncio
async def test_simulation_missing_is_failure_even_with_target_evidence() -> None:
    current = await response_state()
    current["simulation"] = []
    current["simulation_execution"] = None
    result = await handlers().validate(current)
    assert result["validation_result"]["outcome"] == "failure"


@pytest.mark.asyncio
async def test_validation_rejects_simulation_from_another_plan_version() -> None:
    current = await response_state()
    current["simulation_execution"]["plan_version"] = "0" * 64
    result = await handlers().validate(current)
    assert result["validation_result"]["outcome"] == "failure"
    assert result["validation_result"]["checks"][0]["outcome"] == "failure"


def test_analysis_schema_rejects_evaluation_dataset_labels() -> None:
    module = importlib.import_module("evidencesoc.agents.models")
    output = (
        importlib.import_module("evidencesoc.agents.fallback")
        .analyze(state())
        .model_dump()
    )
    output["classification"]["dataset_labels"] = ["test-set-answer"]
    with pytest.raises(ValidationError):
        module.AnalysisOutput.model_validate(output)


@pytest.mark.asyncio
async def test_long_incident_identifier_keeps_attack_step_ids_database_safe() -> None:
    nodes = handlers()
    current = state(incident_id="I" * 64)
    current.update(await nodes.analyze(current))
    result = await nodes.reconstruct(current)
    assert len(result["attack_steps"][0]["attack_step_id"]) <= 64


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("address", "scope"),
    [("203.0.113.42", "unknown"), ("192.168.1.2", "internal"), ("8.8.8.8", "external")],
)
async def test_source_scope_does_not_misclassify_reserved_addresses(
    address: str, scope: str
) -> None:
    result = await handlers().analyze(state(evidence=[evidence(source_ip=address)]))
    assert result["origin"]["source_scope"] == scope
