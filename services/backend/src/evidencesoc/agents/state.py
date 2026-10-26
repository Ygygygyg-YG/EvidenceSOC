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
    diagnosis: dict[str, Any] | None
    diagnostic_snapshot: dict[str, Any] | None
    diagnostic_snapshot_sha256: str | None
    diagnosis_execution_status: str
    analysis_import_provenance: dict[str, Any]
    attack_steps: list[dict[str, Any]]
    response_plan: dict[str, Any] | None
    plan_source: str | None
    response_reason: str | None
    response_attempts: list[dict[str, Any]]
    approval: dict[str, Any] | None
    validation_result: dict[str, Any] | None
    simulation: list[dict[str, Any]]
    simulation_execution: dict[str, Any] | None
    fallback_count: int
    fallback_used: bool
    collection_round: int
    collection_budget_used: int
    collection_reserved_calls: int
    collection_round_used: int
    collection_ledger_ids: list[str]
    collection_tool_attempts: int
    collection_model_attempts: int
    collection_observations: list[dict[str, Any]]
    collection_stop_reason: str | None
    collection_refusal_codes: list[str]
    verification_call_count: int
    verification_attempts: int
    verification_duration_ms: int
    verification_status: str
    verification_namespace: str
    verification_evidence: list[dict[str, Any]]
    errors: list[dict[str, Any]]
    events: Annotated[list[dict[str, Any]], add]
    stop_reason: str | None
    approved_plan_sha256: str
    approved_plan_version: str
    plan_generation: int
    renewed_from_plan_id: str
    claims: list[dict[str, Any]]
    _run_id: str
