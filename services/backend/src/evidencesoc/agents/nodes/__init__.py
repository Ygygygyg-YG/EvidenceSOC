from __future__ import annotations

import asyncio
import json
from copy import deepcopy
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Protocol

import httpx
from pydantic import BaseModel, ValidationError

from evidencesoc.agents import fallback
from evidencesoc.agents.capabilities import InvestigationCapabilities
from evidencesoc.agents.diagnosis import Diagnosis
from evidencesoc.agents.model import (
    DeepSeekStructuredModel,
    record_model_attempt,
    retrieved_techniques,
)
from evidencesoc.agents.models import (
    AnalysisOutput,
    ReconstructionOutput,
    ResponseOutput,
    SimulatedAction,
)
from evidencesoc.agents.verification import EffectObservation, evaluate_simulated_effect
from evidencesoc.config import Settings
from evidencesoc.domain.models import (
    ApprovalRecord,
    EvidenceItem,
    ResponsePlan,
    ValidationCheckResult,
    ValidationOutcome,
    ValidationResult,
)
from evidencesoc.evidence.citations import validate_citations
from evidencesoc.ids import new_ulid


class WorkflowServices(Protocol):
    async def load_incident(self, incident_id: str) -> dict[str, Any]: ...
    async def collect(self, state: dict[str, Any], run_id: str) -> dict[str, Any]: ...
    async def verify(self, state: dict[str, Any], run_id: str) -> dict[str, Any]: ...


class StructuredModel(Protocol):
    async def structured(
        self, role: str, schema: type[BaseModel], state: dict[str, Any]
    ) -> BaseModel: ...


def model_attempt_reference(model: Any, ledger_start: int) -> dict[str, Any]:
    """Point at an existing physical request; never copy provider exception text."""
    ledger = getattr(model, "ledger", [])
    if not isinstance(ledger, list) or len(ledger) <= ledger_start:
        return {"raw_source": "structured_model"}
    entry = ledger[ledger_start]
    reference = {"raw_source": "model_ledger"}
    for key in ("request_ordinal", "request_id", "logical_call_id"):
        if key in entry:
            reference["ledger_" + key] = entry[key]
    try:
        content = entry["raw_response"]["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError):
        pass
    else:
        if isinstance(content, str):
            reference["raw_content_sha256"] = sha256(content.encode()).hexdigest()
    return reference


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
            if "evidence_ids" in value and not (
                "verdict" in value and not value["evidence_ids"]
            ):
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
    diagnosis = (
        output
        if isinstance(output, Diagnosis)
        else output.diagnosis
        if isinstance(output, AnalysisOutput)
        else None
    )
    origins = (
        [output.origin]
        if isinstance(output, AnalysisOutput) and output.origin is not None
        else []
    )
    if diagnosis is not None and diagnosis.origin is not None:
        origins.append(diagnosis.origin)
    for origin in origins:
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
    available_techniques = retrieved_techniques(state)
    if (
        isinstance(output, AnalysisOutput)
        and output.classification is not None
        and set(output.classification.technique_ids) - available_techniques
    ):
        raise ValueError("technique mapping has no retrieved knowledge")
    if diagnosis is not None and set(diagnosis.technique_ids) - available_techniques:
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
        for value in plan.actions:
            action = SimulatedAction.model_validate(value)
            cited = [
                item
                for item in state.get("evidence", [])
                if item["evidence_id"] in (action.evidence_ids or [])
            ]
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
        capabilities: InvestigationCapabilities | None = None,
    ) -> None:
        if model_timeout <= 0:
            raise ValueError("model_timeout must be positive")
        self.services = services
        self.settings = settings
        self.model = model
        self.model_timeout = model_timeout
        self.capabilities = capabilities

    def _is_registered_live_demo(self, state: dict[str, Any]) -> bool:
        return (
            self.capabilities is None
            and self.settings.llm_mode == "deepseek"
            and self.settings.demo_sqli_enabled
            and bool(state.get("verification_namespace"))
        )

    async def _structured(
        self,
        role: str,
        schema: type[BaseModel],
        state: dict[str, Any],
        rule: Any,
        *,
        response_attempts: list[dict[str, Any]] | None = None,
    ) -> tuple[BaseModel, bool, list[dict[str, Any]]]:
        errors = list(state.get("errors", []))
        if self.settings.llm_mode == "fixture":
            result = rule(state)
            validate_output_citations(result, state)
            return result, True, errors
        if self.model is None:
            try:
                self.model = DeepSeekStructuredModel(self.settings)
            except Exception:  # noqa: BLE001 - Provider boundary must sanitize errors.
                errors.append({"role": role, "code": "MODEL_UNAVAILABLE"})
                result = rule(state)
                validate_output_citations(result, state)
                return result, True, errors
        code = "MODEL_UNAVAILABLE"
        model_call_id = new_ulid()
        attempt_categories: list[str] = []
        diagnostics: list[dict[str, Any]] = []
        repair = None
        deepseek_adapter = isinstance(self.model, DeepSeekStructuredModel)
        for attempt in range(1, 4):
            draft = None
            failure_stage = "model_call"
            ledger = getattr(self.model, "ledger", [])
            ledger_start = len(ledger) if isinstance(ledger, list) else 0
            try:
                model_state = deepcopy(state)
                model_state["_model_call_id"] = model_call_id
                if deepseek_adapter:
                    model_state["_evaluation_context"] = self.capabilities is not None
                    model_state["_model_repair"] = repair
                model_state["evidence"] = [
                    {**item, "raw": fallback.observed_raw(item)}
                    for item in state.get("evidence", [])
                ]
                output = await asyncio.wait_for(
                    self.model.structured(role, schema, model_state),
                    timeout=self.model_timeout,
                )
                failure_stage = "schema_validation"
                draft = (
                    output.model_dump(mode="json")
                    if isinstance(output, BaseModel)
                    else deepcopy(output)
                )
                result = schema.model_validate(output)
                if (
                    self.capabilities is not None
                    and role == "analyze"
                    and isinstance(result, AnalysisOutput)
                    and result.diagnosis is None
                ):
                    raise ValueError(
                        "evaluation analysis requires an explicit diagnosis"
                    )
                failure_stage = "citation_validation"
                validate_output_citations(result, state)
                if response_attempts is not None:
                    response_attempts.append(
                        {
                            "attempt": attempt,
                            "model_call_id": model_call_id,
                            **model_attempt_reference(self.model, ledger_start),
                            "status": "valid",
                            "draft": draft,
                        }
                    )
                return result, bool(state.get("fallback_used")), errors
            except Exception as error:  # noqa: BLE001 - Provider boundary must sanitize errors.
                if isinstance(error, TimeoutError):
                    code, category = "MODEL_TIMEOUT", "transport"
                elif isinstance(error, ValueError):
                    code, category = "MODEL_INVALID_OUTPUT", "schema"
                else:
                    code = "MODEL_UNAVAILABLE"
                    category = (
                        "transport"
                        if isinstance(error, httpx.TransportError)
                        else "application"
                    )
                if deepseek_adapter and self.capabilities is None:
                    diagnostic = record_model_attempt(
                        role, attempt, code, schema, error
                    )
                    diagnostics.append(diagnostic)
                    if category == "schema":
                        repair = diagnostic
            if response_attempts is not None:
                record = {
                    "attempt": attempt,
                    "model_call_id": model_call_id,
                    **model_attempt_reference(self.model, ledger_start),
                    "status": "failed",
                    "code": code,
                    "category": category,
                    "failure_stage": failure_stage,
                }
                if draft is not None:
                    record["draft"] = draft
                # Raw provider content remains in its existing model ledger;
                # exceptions may embed credentials and are never copied here.
                response_attempts.append(record)
            if self.capabilities is not None:
                attempt_categories.append(category)
        terminal_error: dict[str, Any] = {"role": role, "code": code}
        if self.capabilities is not None:
            terminal_error["category"] = next(
                (
                    category
                    for category in attempt_categories
                    if category not in {"infrastructure", "transport"}
                ),
                "transport",
            )
            terminal_error["attempt_categories"] = attempt_categories
        if diagnostics:
            terminal_error["attempts"] = diagnostics
        errors.append(terminal_error)
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
        recovery_failed = result.get("collection_stop_reason") == "recovery_failed"
        return {
            "status": "manual_review" if recovery_failed else "collecting",
            **(
                {
                    "stop_reason": "recovery_failed",
                    "errors": [
                        *state.get("errors", []),
                        {"node": "collect", "code": "RECOVERY_FAILED"},
                    ],
                }
                if recovery_failed
                else {}
            ),
            "evidence": merge_by_id(
                state.get("evidence", []), result.get("evidence", []), "evidence_id"
            ),
            "knowledge": merge_by_id(
                state.get("knowledge", []),
                result.get("knowledge", []),
                "knowledge_chunk_id",
            ),
            **{
                key: result[key]
                for key in (
                    "collection_round",
                    "collection_budget_used",
                    "collection_round_used",
                    "collection_ledger_ids",
                    "collection_tool_attempts",
                    "collection_model_attempts",
                    "collection_observations",
                    "collection_stop_reason",
                    "collection_refusal_codes",
                    "collection_reserved_calls",
                )
                if key in result
            },
            "fallback_used": bool(state.get("fallback_used"))
            or bool(result.get("fallback_used"))
            or self.settings.llm_mode == "fixture",
        }

    async def analyze(self, state: dict[str, Any]) -> dict[str, Any]:
        output, used, errors = await self._structured(
            "analyze", AnalysisOutput, state, fallback.analyze
        )
        data = output.model_dump(mode="json")
        diagnosis = data.get("diagnosis")
        unknown = (
            diagnosis["verdict"] == "unknown"
            if diagnosis
            else not data["classification"]
            or data["classification"].get("primary_type") in {None, "unknown"}
        )
        return {
            **data,
            "diagnosis_execution_status": "failed"
            if any(
                error.get("role") == "analyze"
                for error in errors[len(state.get("errors", [])) :]
            )
            else "completed"
            if diagnosis is not None
            else "missing",
            "status": "completed"
            if diagnosis and diagnosis["verdict"] == "benign"
            else "analyzing",
            "fallback_used": used,
            "errors": errors,
            "stop_reason": "insufficient_evidence" if unknown else None,
        }

    async def reconstruct(self, state: dict[str, Any]) -> dict[str, Any]:
        output, used, errors = await self._structured(
            "reconstruct", ReconstructionOutput, state, fallback.reconstruct
        )
        output = ReconstructionOutput.model_validate(output)
        if self._is_registered_live_demo(state):
            steps = []
            for step in output.attack_steps:
                digest = sha256(
                    f"{state['incident_id']}|{step.sequence}".encode()
                ).hexdigest()[:24]
                steps.append(step.model_copy(update={"attack_step_id": f"AS-{digest}"}))
            output = ReconstructionOutput(attack_steps=steps)
        diagnosis_delta = {}
        if state.get("diagnosis") is not None:
            diagnosis = Diagnosis.model_validate(state["diagnosis"])
            data = diagnosis.model_dump(mode="json")
            data["stage_instances"] = [
                {
                    "instance_id": step.attack_step_id,
                    "phase": step.phase or "unknown",
                    "sequence": step.sequence,
                    "evidence_ids": list(step.evidence_ids),
                }
                for step in output.attack_steps
            ]
            data["evidence_ids"] = list(
                dict.fromkeys(
                    [
                        *diagnosis.evidence_ids,
                        *(
                            evidence_id
                            for step in output.attack_steps
                            for evidence_id in step.evidence_ids
                        ),
                    ]
                )
            )
            data["technique_ids"] = list(
                dict.fromkeys(
                    [
                        *diagnosis.technique_ids,
                        *(
                            step.technique_id
                            for step in output.attack_steps
                            if step.technique_id
                        ),
                    ]
                )
            )
            diagnosis_delta["diagnosis"] = Diagnosis.model_validate(data).model_dump(
                mode="json"
            )
        return {
            **output.model_dump(mode="json"),
            **diagnosis_delta,
            "diagnosis_execution_status": "failed"
            if any(
                error.get("role") == "reconstruct"
                for error in errors[len(state.get("errors", [])) :]
            )
            else state.get(
                "diagnosis_execution_status",
                "completed" if state.get("diagnosis") is not None else "missing",
            ),
            "status": "reconstructing",
            "fallback_used": used,
            "errors": errors,
        }

    async def respond(self, state: dict[str, Any]) -> dict[str, Any]:
        response_state = deepcopy(state)
        if (
            self.capabilities is not None
            or state.get("diagnostic_snapshot") is not None
        ):
            snapshot = state.get("diagnostic_snapshot")
            try:
                if not isinstance(snapshot, dict) or sha256(
                    json.dumps(
                        snapshot, sort_keys=True, separators=(",", ":"), allow_nan=False
                    ).encode()
                ).hexdigest() != state.get("diagnostic_snapshot_sha256"):
                    raise ValueError("invalid diagnosis seal")
                diagnosis = Diagnosis.model_validate(snapshot.get("diagnosis"))
                for key in (
                    "diagnosis",
                    "origin",
                    "classification",
                    "attack_steps",
                    "claims",
                    "evidence",
                    "knowledge",
                ):
                    response_state[key] = deepcopy(snapshot.get(key))
                validate_output_citations(diagnosis, response_state)
            except (ValueError, ValidationError, TypeError, KeyError):
                return {
                    "response_plan": None,
                    "plan_source": None,
                    "response_attempts": [],
                    "response_reason": "invalid_diagnosis_snapshot",
                    "no_plan_reason": None,
                    "no_plan_reason_missing": False,
                    "stop_reason": "invalid_diagnosis_snapshot",
                    "status": "manual_review",
                    "errors": list(state.get("errors", [])),
                }
        diagnosis = response_state.get("diagnosis")
        if diagnosis is not None and diagnosis.get("verdict") != "attack":
            return {
                "response_plan": None,
                "plan_source": None,
                "response_attempts": [],
                "response_reason": "no_actionable_target",
                "no_plan_reason": None,
                "no_plan_reason_missing": False,
                "stop_reason": "no_actionable_target",
                "status": "manual_review",
                "errors": list(state.get("errors", [])),
            }
        attempts: list[dict[str, Any]] = []
        output, used, errors = await self._structured(
            "respond",
            ResponseOutput,
            response_state,
            fallback.respond,
            response_attempts=attempts,
        )
        data = output.model_dump(mode="json")
        model_valid = bool(attempts and attempts[-1]["status"] == "valid")
        source = "model" if model_valid else "rule_fallback"
        reason = (
            "model_returned_null"
            if model_valid and data["response_plan"] is None
            else "draft_validation_failed"
            if any(item.get("category") == "schema" for item in attempts)
            else "model_unavailable"
            if attempts and not model_valid
            else "no_actionable_target"
            if data["response_plan"] is None
            else None
        )
        # This is a model statement, not an independently verified finding.
        no_plan_reason = data.get("no_plan_reason")
        if reason != "model_returned_null" or not (
            no_plan_reason and no_plan_reason.strip()
        ):
            no_plan_reason = None
        data["no_plan_reason"] = no_plan_reason
        generation = state.get("plan_generation", 0)
        if data["response_plan"] and (
            generation or self._is_registered_live_demo(state)
        ):
            source_id = state["renewed_from_plan_id"] if generation else "initial"
            digest = sha256(
                f"{state['incident_id']}|{source_id}|{generation}".encode()
            ).hexdigest()[:24]
            data["response_plan"]["response_plan_id"] = f"RP-{digest}"
        return {
            **data,
            "plan_source": source,
            "response_reason": reason,
            "no_plan_reason_missing": reason == "model_returned_null"
            and no_plan_reason is None,
            "response_attempts": attempts,
            "status": "awaiting_approval" if data["response_plan"] else "manual_review",
            "fallback_used": used,
            "errors": errors,
            "stop_reason": None if data["response_plan"] else reason,
        }

    async def validate(self, state: dict[str, Any]) -> dict[str, Any]:
        if self.capabilities is not None and not self.capabilities.verification_enabled:
            return {
                "status": "completed",
                "validation_result": None,
                "verification_status": "unverified",
                "verification_call_count": 0,
                "verification_attempts": 0,
                "verification_duration_ms": 0,
            }
        result = await self.services.verify(state, state["_run_id"])
        fresh = result.get("evidence", [])
        executed_checks = result.get("executed_checks", [])
        query_starts = [
            datetime.fromisoformat(check["condition"]["time_from"])
            for check in executed_checks
        ]
        query_ends = [
            datetime.fromisoformat(check["condition"]["time_to"])
            for check in executed_checks
        ]
        time_from = min(query_starts) if query_starts else None
        time_to = max(query_ends) if query_ends else None
        delta: dict[str, Any] = {
            "status": "validating",
            "verification_status": "evaluated",
            "verification_evidence": deepcopy(fresh),
            "evidence": merge_by_id(state.get("evidence", []), fresh, "evidence_id"),
            "fallback_used": self.settings.llm_mode == "fixture"
            or bool(state.get("fallback_used")),
            **{
                key: result[key]
                for key in (
                    "verification_call_count",
                    "verification_attempts",
                    "verification_duration_ms",
                )
                if key in result
            },
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
                + sha256(
                    (
                        plan.response_plan_id
                        + "|"
                        + state.get("verification_namespace", "")
                    ).encode()
                ).hexdigest()[:24],
                response_plan_id=plan.response_plan_id,
                outcome=ValidationOutcome.INSUFFICIENT_EVIDENCE,
                summary="No fresh verification evidence was returned; prior investigation evidence cannot prove a simulated or real response succeeded.",
                checked_at=datetime.now(UTC),
                evidence_ids=[item["evidence_id"] for item in previous],
                time_from=time_from,
                time_to=time_to,
                checks=[
                    ValidationCheckResult.model_validate(
                        {
                            **check,
                            "outcome": ValidationOutcome.INSUFFICIENT_EVIDENCE,
                            "explanation": "The executed query returned no target evidence; the simulation effect remains unverified.",
                        }
                    )
                    for check in executed_checks
                ],
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
        checks: list[dict[str, Any]] = []
        try:
            plan = ResponsePlan.model_validate(state.get("response_plan"))
            approval = ApprovalRecord.model_validate(state.get("approval"))
            actions = [SimulatedAction.model_validate(item) for item in plan.actions]
            execution = state.get("simulation_execution")
            plan_digest = sha256(
                json.dumps(
                    state["response_plan"],
                    sort_keys=True,
                    separators=(",", ":"),
                    allow_nan=False,
                ).encode()
            ).hexdigest()
            authorized = (
                approval.decision == "approved"
                and approval.response_plan_id == plan.response_plan_id
                and plan.incident_id == state["incident_id"]
                and state.get("approved_plan_sha256") == plan_digest
            )
            action_ids = [action.action_id for action in actions]
            action_results = (
                execution.get("action_results", [])
                if isinstance(execution, dict)
                else []
            )
            if not isinstance(action_results, list) or any(
                not isinstance(item, dict) for item in action_results
            ):
                action_results = []
            simulation = state.get("simulation")
            legacy_matches = (
                isinstance(simulation, list)
                and len(simulation) == len(actions)
                and all(
                    isinstance(item, dict)
                    and item.get("action") == action.action
                    and item.get("target") == action.target
                    and item.get("status") == "simulated"
                    and item.get("simulated", True) is True
                    and item.get("outcome", "success") == "success"
                    and item.get("action_id", action.action_id) == action.action_id
                    for item, action in zip(simulation, actions, strict=True)
                )
            )
            all_simulated = (
                isinstance(execution, dict)
                and execution.get("response_plan_id") == plan.response_plan_id
                and bool(state.get("approved_plan_version"))
                and execution.get("plan_version") == state.get("approved_plan_version")
                and execution.get("status") == "completed"
                and all(action_ids)
                and len(set(action_ids)) == len(action_ids)
                and len(action_results) == len(actions)
                and {item.get("action_id") for item in action_results}
                == set(action_ids)
                and all(item.get("outcome") == "success" for item in action_results)
                and legacy_matches
            )
            fresh_by_id = {item["evidence_id"]: item for item in fresh}
            for index, check in enumerate(executed_checks):
                observations = result.get("effect_observations")
                pair = (
                    observations.get(check["check_id"])
                    if isinstance(observations, dict)
                    else None
                )
                try:
                    before = EffectObservation.model_validate(pair["before"])
                    after = EffectObservation.model_validate(pair["after"])
                except (ValidationError, ValueError, TypeError, KeyError):
                    before, after = None, None
                cited = [
                    evidence_id
                    for evidence_id in dict.fromkeys(
                        [
                            *check["evidence_ids"],
                            *(after.evidence_ids if after is not None else []),
                        ]
                    )
                    if evidence_id in fresh_by_id
                ]
                matched = index < len(actions) and any(
                    fallback.matching_target(fresh_by_id[evidence_id], actions[index])
                    for evidence_id in cited
                )
                if not authorized or not all_simulated:
                    check_outcome = ValidationOutcome.FAILURE
                    explanation = "The approved simulated action did not complete for this plan version."
                elif matched:
                    check_outcome = ValidationOutcome.INSUFFICIENT_EVIDENCE
                    try:
                        allowed_before = {
                            item["evidence_id"] for item in state.get("evidence", [])
                        } | set(fresh_by_id)
                        if (
                            before is not None
                            and after is not None
                            and before.namespace == state.get("verification_namespace")
                            and before.action_id == actions[index].action_id
                            and before.target == actions[index].target
                            and (after.namespace, after.action_id, after.target)
                            == (before.namespace, before.action_id, before.target)
                            and set(before.evidence_ids) <= allowed_before
                            and set(after.evidence_ids) <= set(cited)
                        ):
                            check_outcome = ValidationOutcome(
                                evaluate_simulated_effect(
                                    actions[index].action, before, after
                                )
                            )
                            if self.capabilities is None:
                                cited = list(
                                    dict.fromkeys([*cited, *before.evidence_ids])
                                )
                    except (ValidationError, ValueError, TypeError, AttributeError):
                        pass
                    explanation = (
                        "Typed before/after observations establish the simulated effect only."
                        if check_outcome == ValidationOutcome.SUCCESS
                        else "An explicit post-action observation reports failure."
                        if check_outcome == ValidationOutcome.FAILURE
                        else "Target presence alone cannot establish the simulated effect; observations are absent, unchanged, or incomplete."
                    )
                else:
                    check_outcome = ValidationOutcome.INSUFFICIENT_EVIDENCE
                    explanation = "The executed query returned no target evidence; the simulation effect remains unverified."
                checks.append(
                    {
                        **check,
                        "evidence_ids": cited,
                        "outcome": check_outcome,
                        "explanation": explanation,
                    }
                )
            if authorized and all_simulated:
                if len(checks) == len(actions) and all(
                    check["outcome"] == ValidationOutcome.SUCCESS for check in checks
                ):
                    outcome = ValidationOutcome.SUCCESS
                    summary = "Typed before/after observations establish all approved simulated effects. This does not prove real system changes or effective traffic blocking."
                elif any(
                    check["outcome"] == ValidationOutcome.FAILURE for check in checks
                ):
                    outcome = ValidationOutcome.FAILURE
                    summary = "Post-action observations explicitly report a simulated effect failure."
                else:
                    outcome = ValidationOutcome.INSUFFICIENT_EVIDENCE
                    summary = "Fresh evidence does not establish every simulated target; real effects remain unverified."
            response_plan_id = plan.response_plan_id
        except (ValueError, TypeError):
            response_plan_id = (state.get("response_plan") or {}).get(
                "response_plan_id", "RP-unavailable"
            )
        validation = ValidationResult(
            validation_id="VR-"
            + sha256(
                (
                    response_plan_id + "|" + state.get("verification_namespace", "")
                ).encode()
            ).hexdigest()[:24],
            response_plan_id=response_plan_id,
            outcome=outcome,
            summary=summary,
            checked_at=datetime.now(UTC),
            evidence_ids=list(
                dict.fromkeys(
                    [
                        *(item["evidence_id"] for item in fresh),
                        *(
                            evidence_id
                            for check in checks
                            for evidence_id in check["evidence_ids"]
                        ),
                    ]
                )
            ),
            time_from=time_from,
            time_to=time_to,
            checks=[ValidationCheckResult.model_validate(check) for check in checks],
        )
        return {
            **delta,
            "validation_result": validation.model_dump(mode="json"),
            "stop_reason": "insufficient_evidence"
            if outcome == "insufficient_evidence"
            else None,
        }


__all__ = ["NodeHandlers", "StructuredModel", "WorkflowServices"]
