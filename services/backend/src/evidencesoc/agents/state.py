from __future__ import annotations

from operator import add
from typing import Annotated, Any, TypedDict


class InvestigationState(TypedDict, total=False):
    """Checkpoint values use JSON primitives, including nested domain models."""

    incident_id: str
    trace_id: str
    status: str
    alerts: list[dict[str, Any]]
    evidence: list[dict[str, Any]]
    knowledge: list[dict[str, Any]]
    origin: dict[str, Any] | None
    classification: dict[str, Any] | None
    attack_steps: list[dict[str, Any]]
    response_plan: dict[str, Any] | None
    approval: dict[str, Any] | None
    validation_result: dict[str, Any] | None
    simulation: list[dict[str, Any]]
    simulation_execution: dict[str, Any] | None
    fallback_count: int
    fallback_used: bool
    collection_round: int
    collection_budget_used: int
    collection_round_used: int
    collection_ledger_ids: list[str]
    collection_tool_attempts: int
    collection_model_attempts: int
    collection_observations: list[dict[str, Any]]
    collection_stop_reason: str | None
    verification_call_count: int
    verification_attempts: int
    verification_duration_ms: int
    errors: list[dict[str, Any]]
    events: Annotated[list[dict[str, Any]], add]
    stop_reason: str | None
    approved_plan_sha256: str
    approved_plan_version: str
    plan_generation: int
    renewed_from_plan_id: str
    claims: list[dict[str, Any]]
    _run_id: str
