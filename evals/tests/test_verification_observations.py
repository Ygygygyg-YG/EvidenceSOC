"""Synthetic contract fixtures are not formal reviewer approvals or results."""

from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime, timedelta
from importlib import import_module

import pytest


def approved_fixture():
    from evidencesoc.agents import fallback
    from evidencesoc.agents.graph import _plan_hash

    ev = "EV-01ARZ3NDEKTSV4RRFFQ69G5FAV"
    now = datetime.now(UTC)
    state = {
        "incident_id": "IN-synthetic",
        "trace_id": "TRACE-source",
        "_run_id": "AR-test",
        "status": "validating",
        "errors": [],
        "evidence": [
            {
                "evidence_id": ev,
                "event_id": "SE-synthetic",
                "source": "fixture",
                "observed_at": now.isoformat(),
                "query": {},
                "summary": "Observed request",
                "content_sha256": "a" * 64,
                "raw": {"source_ip": "198.51.100.10", "message": "UNION SELECT"},
            }
        ],
        "knowledge": [],
    }
    state.update(fallback.analyze(state).model_dump(mode="json"))
    state.update(fallback.reconstruct(state).model_dump(mode="json"))
    state.update(fallback.respond(state).model_dump(mode="json"))
    plan = state["response_plan"]
    digest = _plan_hash(plan)
    state.update(
        approved_plan_sha256=digest,
        approved_plan_version=digest,
        approval={
            "approval_id": "AP-fixture",
            "response_plan_id": plan["response_plan_id"],
            "decision": "approved",
            "reason": "Synthetic test fixture only",
            "decided_by": "fixture-reviewer",
            "decided_at": now.isoformat(),
        },
    )
    state["diagnostic_snapshot"] = {
        "diagnosis": {"verdict": "attack", "taxonomy_status": "out_of_taxonomy"},
        "evidence": deepcopy(state["evidence"]),
        "sealed_after": "reconstruct",
    }
    state["diagnostic_snapshot_sha256"] = _plan_hash(state["diagnostic_snapshot"])
    state["simulation"] = [
        {**action, "status": "simulated", "simulated": True, "outcome": "success"}
        for action in plan["actions"]
    ]
    state["simulation_execution"] = {
        "simulation_id": "SIM-fixture",
        "response_plan_id": plan["response_plan_id"],
        "plan_version": digest,
        "status": "completed",
        "action_results": [
            {"action_id": action["action_id"], "outcome": "success"}
            for action in plan["actions"]
        ],
    }
    normal = {
        "evidence": [],
        "executed_checks": [
            {
                "check_id": check.check_id,
                "condition": {
                    "time_from": (now - timedelta(minutes=1)).isoformat(),
                    "time_to": (now + timedelta(minutes=1)).isoformat(),
                    "filters": action["verification_query"]["filters"],
                    "limit": 100,
                },
                "evidence_ids": [],
            }
            for check, action in zip(
                fallback.respond(state).response_plan.validation_checks,
                plan["actions"],
                strict=True,
            )
        ],
    }
    return state, normal


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "after,error,expected",
    [
        (True, None, "success"),
        (False, None, "insufficient_evidence"),
        (False, "ACTION_REJECTED", "failure"),
        (None, None, "insufficient_evidence"),
    ],
)
async def test_same_target_actual_observation_values_determine_original_validator(
    after, error, expected
):
    module = import_module("evals.adapters.verification_observations")
    from evidencesoc.agents.nodes import NodeHandlers
    from evidencesoc.config import Settings

    state, normal = approved_fixture()
    namespace = "a" * 32
    clone = module.clone_approved_state(state, namespace)
    clone["_run_id"] = "AR-opaque"
    action_id = clone["response_plan"]["actions"][0]["action_id"]
    values = {
        action_id: {
            "before": {"observed_at": "2026-10-18T00:00:00Z", "network_blocked": False},
            "after": {
                "observed_at": "2026-10-18T00:00:01Z",
                "network_blocked": after,
                "error_code": error,
            },
        }
    }
    registry = {}

    async def register(incident, opaque, items):
        assert incident == state["incident_id"] and opaque == namespace
        registry.update({item["evidence_id"]: item for item in items})

    adapter = module.ControlledObservationAdapter(
        namespace=namespace, observations=values, register_evidence=register
    )

    class Services:
        async def verify(self, current, run_id):
            return {**normal, **await adapter(current, run_id, normal)}

    result = await NodeHandlers(Services(), Settings(_env_file=None)).validate(clone)
    assert result["validation_result"]["outcome"] == expected
    assert len(registry) == 2
    assert clone["diagnostic_snapshot"] == state["diagnostic_snapshot"]
    payload = await adapter(clone, "AR-opaque", normal)
    assert not (
        {"condition_name", "truth", "outcome", "validation_result"}
        & set(
            payload["effect_observations"][normal["executed_checks"][0]["check_id"]][
                "after"
            ]
        )
    )


@pytest.mark.asyncio
async def test_namespaces_and_approved_plan_snapshot_are_independent():
    module = import_module("evals.adapters.verification_observations")
    state, normal = approved_fixture()
    action_id = state["response_plan"]["actions"][0]["action_id"]
    values = {
        action_id: {
            "before": {"observed_at": "2026-10-18T00:00:00Z", "network_blocked": False},
            "after": {"observed_at": "2026-10-18T00:00:01Z", "network_blocked": True},
        }
    }

    async def register(*args):
        pass

    ids = []
    for namespace in ("a" * 32, "b" * 32):
        clone = module.clone_approved_state(state, namespace)
        assert clone["response_plan"] == state["response_plan"]
        assert clone["approved_plan_sha256"] == state["approved_plan_sha256"]
        adapter = module.ControlledObservationAdapter(
            namespace=namespace, observations=values, register_evidence=register
        )
        result = await adapter(clone, "AR-1", normal)
        ids.append({item["evidence_id"] for item in result["evidence"]})
    assert ids[0].isdisjoint(ids[1])
    corrupted = deepcopy(state)
    corrupted["diagnostic_snapshot"]["diagnosis"]["verdict"] = "benign"
    with pytest.raises(ValueError, match="snapshot"):
        module.clone_approved_state(corrupted, "c" * 32)


@pytest.mark.asyncio
async def test_missing_approval_registration_or_observation_does_not_emit_evidence():
    module = import_module("evals.adapters.verification_observations")
    state, normal = approved_fixture()
    calls = []

    async def register(*args):
        calls.append(args)

    adapter = module.ControlledObservationAdapter(
        namespace="a" * 32, observations={}, register_evidence=register
    )
    state["verification_namespace"] = "a" * 32
    unapproved = {**state, "approval": None}
    with pytest.raises(PermissionError):
        await adapter(unapproved, "AR-1", normal)
    with pytest.raises(ValueError, match="observation"):
        await adapter(state, "AR-1", normal)
    assert calls == []
    with pytest.raises(ValueError, match="registr"):
        module.ControlledObservationAdapter(
            namespace="a" * 32, observations={}, register_evidence=None
        )
