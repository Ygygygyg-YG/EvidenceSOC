"""Answer-free controlled observations for the original simulation validator.

The driver supplies measured control values, never an expected outcome. Each
worker must own an isolated evidence store; namespaces only separate identifiers.
"""

from __future__ import annotations

import re
from collections.abc import Awaitable, Callable, Mapping
from copy import deepcopy
from hashlib import sha256
from typing import Any

from evidencesoc.agents.graph import _plan_hash
from evidencesoc.agents.models import SimulatedAction
from evidencesoc.agents.verification import EffectObservation
from evidencesoc.domain.models import ApprovalRecord, EvidenceItem, ResponsePlan
from evidencesoc.ingestion.normalize import calculate_content_sha256

RegisterEvidence = Callable[[str, str, list[dict[str, Any]]], Awaitable[None]]
_VALUE_FIELDS = frozenset(
    {
        "observed_at",
        "network_blocked",
        "host_isolated",
        "account_enabled",
        "error_code",
    }
)


def _namespace(value: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{32}", value) is None:
        raise ValueError("verification namespace must be an opaque 128-bit identifier")
    return value


def _approved_plan(state: Mapping[str, Any]) -> ResponsePlan:
    try:
        plan = ResponsePlan.model_validate(state.get("response_plan"))
        approval = ApprovalRecord.model_validate(state.get("approval"))
        if (
            approval.decision != "approved"
            or approval.response_plan_id != plan.response_plan_id
            or plan.incident_id != state.get("incident_id")
            or state.get("approved_plan_sha256") != _plan_hash(state["response_plan"])
        ):
            raise ValueError("approval does not bind this plan")
    except (TypeError, ValueError) as exc:
        raise PermissionError(
            "controlled observations require the exact approved plan"
        ) from exc
    return plan


def clone_approved_state(state: Mapping[str, Any], namespace: str) -> dict[str, Any]:
    """Copy an approved replay input while retaining its sealed diagnostic hash."""
    _namespace(namespace)
    _approved_plan(state)
    snapshot = state.get("diagnostic_snapshot")
    if not isinstance(snapshot, dict) or state.get(
        "diagnostic_snapshot_sha256"
    ) != _plan_hash(snapshot):
        raise ValueError("diagnostic snapshot is missing or has changed")
    cloned = deepcopy(dict(state))
    cloned.update(
        verification_namespace=namespace,
        verification_evidence=[],
        validation_result=None,
        verification_call_count=0,
        verification_attempts=0,
        verification_duration_ms=0,
    )
    return cloned


def _evidence_id(identity: list[Any]) -> str:
    # Use the established Crockford alphabet and width without embedding a case,
    # condition, action target or expected outcome in the public identifier.
    value = int(_plan_hash(identity)[:32], 16)
    alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
    result = ""
    for _ in range(26):
        result = alphabet[value & 31] + result
        value >>= 5
    return "EV-" + result


class ControlledObservationAdapter:
    def __init__(
        self,
        *,
        namespace: str,
        observations: Mapping[str, Mapping[str, Mapping[str, Any]]],
        register_evidence: RegisterEvidence | None,
    ) -> None:
        self.namespace = _namespace(namespace)
        if register_evidence is None:
            raise ValueError("an evidence registration callback is required")
        if not callable(register_evidence):
            raise TypeError("evidence registration callback must be callable")
        self.observations = deepcopy(dict(observations))
        self.register_evidence = register_evidence

    async def __call__(self, state, run_id, normal_verify_result):
        plan = _approved_plan(state)
        if state.get("verification_namespace") != self.namespace:
            raise PermissionError("observation namespace differs from this worker")
        actions = [SimulatedAction.model_validate(action) for action in plan.actions]
        checks = {check.check_id: check for check in plan.validation_checks}
        executed = normal_verify_result.get("executed_checks", [])
        observations: dict[str, dict[str, Any]] = {}
        evidence: list[dict[str, Any]] = []
        for check in executed:
            configured = checks.get(check["check_id"])
            action = next(
                (
                    action
                    for action in actions
                    if configured is not None
                    and action.target == configured.target
                    and action.verification_query == configured.query
                ),
                None,
            )
            if action is None:
                raise ValueError("observation check is not in the approved plan")
            values = self.observations.get(action.action_id)
            if not isinstance(values, dict) or set(values) != {"before", "after"}:
                raise ValueError("each action needs before and after observations")
            pair = {}
            for phase in ("before", "after"):
                measured = values[phase]
                if not isinstance(measured, dict) or set(measured) - _VALUE_FIELDS:
                    raise ValueError(
                        "observation may contain only measured control values"
                    )
                typed = EffectObservation.model_validate(
                    {
                        **measured,
                        "namespace": self.namespace,
                        "action_id": action.action_id,
                        "target": action.target,
                    }
                )
                raw = typed.model_dump(mode="json", exclude={"evidence_ids"})
                raw[
                    {
                        "block_ip_simulated": "source_ip",
                        "isolate_host_simulated": "host",
                        "disable_account_simulated": "username",
                    }[action.action]
                ] = action.target
                identity = [self.namespace, run_id, action.action_id, phase, raw]
                evidence_id = _evidence_id(identity)
                item = EvidenceItem(
                    evidence_id=evidence_id,
                    event_id="SE-"
                    + sha256(_plan_hash(identity).encode()).hexdigest()[:32],
                    source="simulated-control-observation",
                    observed_at=typed.observed_at,
                    query={"namespace": self.namespace, "action_id": action.action_id},
                    summary="Observed simulated control state.",
                    content_sha256=calculate_content_sha256(raw),
                ).model_dump(mode="json")
                evidence.append({**item, "raw": raw})
                pair[phase] = typed.model_copy(
                    update={"evidence_ids": [evidence_id]}
                ).model_dump(mode="json")
            observations[check["check_id"]] = pair
        if not observations or set(self.observations) != {
            action.action_id for action in actions
        }:
            raise ValueError("observations must cover exactly the approved actions")
        # Validate the whole observation batch before performing the registration.
        await self.register_evidence(
            state["incident_id"], self.namespace, deepcopy(evidence)
        )
        all_evidence = {
            item["evidence_id"]: deepcopy(item)
            for item in normal_verify_result.get("evidence", [])
        }
        all_evidence.update({item["evidence_id"]: item for item in evidence})
        return {
            "effect_observations": observations,
            "evidence": list(all_evidence.values()),
        }
