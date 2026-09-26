from __future__ import annotations

import asyncio
from copy import deepcopy
from hashlib import sha256
from typing import Any, Protocol

from pydantic import BaseModel, ValidationError

from evidencesoc.agents import fallback
from evidencesoc.agents.models import (
    AnalysisOutput,
    ReconstructionOutput,
    ResponseOutput,
    SimulatedAction,
)
from evidencesoc.config import Settings
from evidencesoc.domain.models import (
    ApprovalRecord,
    EvidenceItem,
    ResponsePlan,
    ValidationOutcome,
    ValidationResult,
)
from evidencesoc.evidence.citations import validate_citations


class WorkflowServices(Protocol):
    async def load_incident(self, incident_id: str) -> dict[str, Any]: ...
    async def collect(self, state: dict[str, Any], run_id: str) -> dict[str, Any]: ...
    async def verify(self, state: dict[str, Any], run_id: str) -> dict[str, Any]: ...


class StructuredModel(Protocol):
    async def structured(
        self, role: str, schema: type[BaseModel], state: dict[str, Any]
    ) -> BaseModel: ...


def merge_by_id(
    old: list[dict[str, Any]], new: list[dict[str, Any]], key: str
) -> list[dict[str, Any]]:
    merged = {item[key]: deepcopy(item) for item in old}
    merged.update({item[key]: deepcopy(item) for item in new})
    return list(merged.values())


def validate_output_citations(output: BaseModel, state: dict[str, Any]) -> None:
    allowed = {
        EvidenceItem.model_validate(item).evidence_id
        for item in state.get("evidence", [])
    }
    knowledge = {item["knowledge_chunk_id"] for item in state.get("knowledge", [])}
    data = output.model_dump(mode="json")
    facts: list[dict[str, Any]] = []

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            if "evidence_ids" in value:
                facts.append(
                    {
                        "claim_id": str(len(facts)),
                        "text": "Structured security observation.",
                        "evidence_ids": value["evidence_ids"],
                    }
                )
            for nested in value.values():
                visit(nested)
        elif isinstance(value, list):
            for nested in value:
                visit(nested)

    visit(data)
    if any(
        item.status != "supported"
        for item in validate_citations(facts, allowed, knowledge)
    ):
        raise ValueError("invalid citation")
    if isinstance(output, AnalysisOutput) and output.origin is not None:
        origin = output.origin
        items = [
            item
            for item in state.get("evidence", [])
            if item["evidence_id"] in origin.evidence_ids
        ]
        observations = [fallback.observed_raw(item) for item in items]
        if origin.observed_source_ip is not None and origin.observed_source_ip not in {
            fallback.source_ip(raw) for raw in observations
        }:
            raise ValueError("source IP is not observed in cited evidence")
        if origin.entry_host is not None and origin.entry_host not in {
            fallback.source_host(raw) for raw in observations
        }:
            raise ValueError("entry host is not observed in cited evidence")
        if origin.entry_service is not None and origin.entry_service not in {
            raw.get("service") for raw in observations
        }:
            raise ValueError("entry service is not observed in cited evidence")
        if origin.source_scope != fallback.source_scope(origin.observed_source_ip):
            raise ValueError("source scope is not established by the observed address")
        if origin.first_seen_at is not None and origin.first_seen_at not in {
            EvidenceItem.model_validate(item).observed_at for item in items
        }:
            raise ValueError("first observed time does not match cited evidence")
    available_techniques = {
        item.get("technique_id")
        for item in state.get("knowledge", [])
        if item.get("knowledge_chunk_id") and item.get("source_uri")
    }
    if (
        isinstance(output, AnalysisOutput)
        and output.classification is not None
        and set(output.classification.technique_ids) - available_techniques
    ):
        raise ValueError("technique mapping has no retrieved knowledge")
    if isinstance(output, ReconstructionOutput) and any(
        step.technique_id is not None and step.technique_id not in available_techniques
        for step in output.attack_steps
    ):
        raise ValueError("technique mapping has no retrieved knowledge")
    if (
        isinstance(output, ResponseOutput)
        and output.response_plan is not None
        and output.response_plan.incident_id != state["incident_id"]
    ):
        raise ValueError("response belongs to another incident")
    if isinstance(output, ResponseOutput) and output.response_plan is not None:
        plan = output.response_plan
        cited = [
            item
            for item in state.get("evidence", [])
            if item["evidence_id"] in plan.evidence_ids
        ]
        for value in plan.actions:
            action = SimulatedAction.model_validate(value)
            if not any(fallback.matching_target(item, action) for item in cited):
                raise ValueError("response target is not observed in cited evidence")


class NodeHandlers:
    def __init__(
        self,
        services: WorkflowServices,
        settings: Settings,
        model: StructuredModel | None = None,
        *,
        model_timeout: float = 60.0,
    ) -> None:
        if model_timeout <= 0:
            raise ValueError("model_timeout must be positive")
        self.services = services
        self.settings = settings
        self.model = model
        self.model_timeout = model_timeout

    async def _structured(
        self, role: str, schema: type[BaseModel], state: dict[str, Any], rule: Any
    ) -> tuple[BaseModel, bool, list[dict[str, Any]]]:
        errors = list(state.get("errors", []))
        if self.settings.llm_mode == "fixture":
            result = rule(state)
            validate_output_citations(result, state)
            return result, True, errors
        if self.model is None:
            try:
                from evidencesoc.agents.model import DeepSeekStructuredModel

                self.model = DeepSeekStructuredModel(self.settings)
            except Exception:  # noqa: BLE001 - Provider boundary must sanitize errors.
                errors.append({"role": role, "code": "MODEL_UNAVAILABLE"})
                result = rule(state)
                validate_output_citations(result, state)
                return result, True, errors
        code = "MODEL_UNAVAILABLE"
        for _ in range(3):
            try:
                model_state = deepcopy(state)
                model_state["evidence"] = [
                    {**item, "raw": fallback.observed_raw(item)}
                    for item in state.get("evidence", [])
                ]
                output = await asyncio.wait_for(
                    self.model.structured(role, schema, model_state),
                    timeout=self.model_timeout,
                )
                result = schema.model_validate(output)
                validate_output_citations(result, state)
                return result, bool(state.get("fallback_used")), errors
            except TimeoutError:
                code = "MODEL_TIMEOUT"
            except (ValueError, ValidationError):
                code = "MODEL_INVALID_OUTPUT"
            except Exception:  # noqa: BLE001 - Provider boundary must sanitize errors.
                code = "MODEL_UNAVAILABLE"
        errors.append({"role": role, "code": code})
        result = rule(state)
        validate_output_citations(result, state)
        return result, True, errors

    async def triage(self, state: dict[str, Any]) -> dict[str, Any]:
        loaded = await self.services.load_incident(state["incident_id"])
        return {
            "status": "triaged",
            "alerts": deepcopy(loaded["alerts"]),
            "fallback_used": self.settings.llm_mode == "fixture"
            or bool(state.get("fallback_used")),
            "stop_reason": None,
        }

    async def collect(self, state: dict[str, Any]) -> dict[str, Any]:
        result = await self.services.collect(state, state["_run_id"])
        return {
            "status": "collecting",
            "evidence": merge_by_id(
                state.get("evidence", []), result.get("evidence", []), "evidence_id"
            ),
            "knowledge": merge_by_id(
                state.get("knowledge", []),
                result.get("knowledge", []),
                "knowledge_chunk_id",
            ),
        }

    async def analyze(self, state: dict[str, Any]) -> dict[str, Any]:
        output, used, errors = await self._structured(
            "analyze", AnalysisOutput, state, fallback.analyze
        )
        data = output.model_dump(mode="json")
        unknown = not data["classification"] or data["classification"].get(
            "primary_type"
        ) in {None, "unknown"}
        return {
            **data,
            "status": "analyzing",
            "fallback_used": used,
            "errors": errors,
            "stop_reason": "insufficient_evidence" if unknown else None,
        }

    async def reconstruct(self, state: dict[str, Any]) -> dict[str, Any]:
        output, used, errors = await self._structured(
            "reconstruct", ReconstructionOutput, state, fallback.reconstruct
        )
        return {
            **output.model_dump(mode="json"),
            "status": "reconstructing",
            "fallback_used": used,
            "errors": errors,
        }

    async def respond(self, state: dict[str, Any]) -> dict[str, Any]:
        output, used, errors = await self._structured(
            "respond", ResponseOutput, state, fallback.respond
        )
        data = output.model_dump(mode="json")
        return {
            **data,
            "status": "awaiting_approval" if data["response_plan"] else "manual_review",
            "fallback_used": used,
            "errors": errors,
            "stop_reason": None if data["response_plan"] else "insufficient_evidence",
        }

    async def validate(self, state: dict[str, Any]) -> dict[str, Any]:
        result = await self.services.verify(state, state["_run_id"])
        fresh = result.get("evidence", [])
        delta: dict[str, Any] = {
            "status": "validating",
            "evidence": merge_by_id(state.get("evidence", []), fresh, "evidence_id"),
            "fallback_used": self.settings.llm_mode == "fixture"
            or bool(state.get("fallback_used")),
        }
        if not fresh:
            previous = state.get("evidence", [])
            if not previous:
                return {
                    **delta,
                    "status": "manual_review",
                    "validation_result": None,
                    "stop_reason": "insufficient_evidence",
                }
            plan = ResponsePlan.model_validate(state.get("response_plan"))
            validation = ValidationResult(
                validation_id="VR-"
                + sha256(plan.response_plan_id.encode()).hexdigest()[:24],
                response_plan_id=plan.response_plan_id,
                outcome=ValidationOutcome.INSUFFICIENT_EVIDENCE,
                summary="No fresh verification evidence was returned; prior investigation evidence cannot prove a simulated or real response succeeded.",
                checked_at=fallback.checked_timestamp(state, previous),
                evidence_ids=[item["evidence_id"] for item in previous],
            )
            return {
                **delta,
                "validation_result": validation.model_dump(mode="json"),
                "stop_reason": "insufficient_evidence",
            }
        outcome = ValidationOutcome.FAILURE
        summary = (
            "Simulation validation failed; no real system changes are demonstrated."
        )
        try:
            plan = ResponsePlan.model_validate(state.get("response_plan"))
            approval = ApprovalRecord.model_validate(state.get("approval"))
            actions = [SimulatedAction.model_validate(item) for item in plan.actions]
            simulations = state.get("simulation", [])
            authorized = (
                approval.decision == "approved"
                and approval.response_plan_id == plan.response_plan_id
                and plan.incident_id == state["incident_id"]
            )
            all_simulated = len(simulations) == len(actions) and all(
                sim.get("action") == action.action
                and sim.get("target") == action.target
                and sim.get("status") == "simulated"
                and sim.get("outcome", "success") == "success"
                for sim, action in zip(simulations, actions, strict=True)
            )
            if authorized and all_simulated:
                if all(
                    any(fallback.matching_target(item, action) for item in fresh)
                    for action in actions
                ):
                    outcome = ValidationOutcome.SUCCESS
                    summary = "Approved simulated actions match freshly queried target evidence. This verifies the simulation only, not real system changes or effective traffic blocking."
                else:
                    outcome = ValidationOutcome.INSUFFICIENT_EVIDENCE
                    summary = "Fresh evidence does not establish every simulated target; real effects remain unverified."
            response_plan_id = plan.response_plan_id
        except (ValueError, TypeError):
            response_plan_id = (state.get("response_plan") or {}).get(
                "response_plan_id", "RP-unavailable"
            )
        validation = ValidationResult(
            validation_id="VR-" + sha256(response_plan_id.encode()).hexdigest()[:24],
            response_plan_id=response_plan_id,
            outcome=outcome,
            summary=summary,
            checked_at=fallback.checked_timestamp(state, fresh),
            evidence_ids=[item["evidence_id"] for item in fresh],
        )
        return {
            **delta,
            "validation_result": validation.model_dump(mode="json"),
            "stop_reason": "insufficient_evidence"
            if outcome == "insufficient_evidence"
            else None,
        }


__all__ = ["NodeHandlers", "StructuredModel", "WorkflowServices"]
