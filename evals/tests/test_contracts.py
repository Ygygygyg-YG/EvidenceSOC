import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from evals.contracts import (
    CallBudget,
    CapabilityPolicy,
    ControllerRunSpec,
    ModelConfig,
    WorkerRunSpec,
    policy_for_group,
)


def spec(**changes):
    data = {
        "run_id": "run-001",
        "case_id": "case-001",
        "group": "B3",
        "config_sha256": "a" * 64,
    }
    data.update(changes)
    return WorkerRunSpec(**data)


@pytest.mark.parametrize(
    "field", ["gold_path", "is_attack", "dataset", "scenario", "case_root"]
)
def test_worker_rejects_controller_and_answer_fields(field):
    with pytest.raises(ValidationError):
        spec(**{field: "secret"})


def test_policy_closes_every_ablation_without_extra_budget():
    assert policy_for_group("A1").allowed_tools == ["lookup_attack_technique"]
    assert policy_for_group("A1").first_round_reserved_calls == 1
    assert policy_for_group("A1").total_reserved_calls == 1
    assert policy_for_group("A2").rag_mode == "disabled"
    assert "lookup_attack_technique" not in policy_for_group("A2").allowed_tools
    assert policy_for_group("A3").rag_mode == "semantic_only"
    assert not policy_for_group("A4").verification_enabled
    assert CallBudget().max_tool_calls == 6
    with pytest.raises(ValidationError):
        CallBudget(max_tool_calls=7)


def test_worker_policy_must_match_registered_group():
    with pytest.raises(ValidationError):
        spec(group="A2", capabilities=CapabilityPolicy())
    assert spec(group="A2").capabilities.rag_mode == "disabled"


def test_model_freezes_non_thinking_temperature_and_retry_upper_bound():
    model = ModelConfig()
    assert model.requested_model == "deepseek-flash"
    assert model.thinking == "disabled"
    assert model.temperature == 0
    with pytest.raises(ValidationError):
        ModelConfig(temperature=1)


@pytest.mark.parametrize('field',['max_tool_calls_per_round','max_tool_calls','max_tool_attempts','max_model_attempts'])
def test_contract_does_not_advertise_unimplemented_lower_retry_or_ledger_limits(field):
    with pytest.raises(ValidationError):
        CallBudget(**{field:1})


def test_registered_schema_is_generated_from_controller_contract():
    path = Path(__file__).resolve().parents[1] / "run_manifest.schema.json"
    assert (
        json.loads(path.read_text(encoding="utf-8"))
        == ControllerRunSpec.model_json_schema()
    )
