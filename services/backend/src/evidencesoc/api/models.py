from __future__ import annotations

from datetime import datetime
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from evidencesoc.agents.models import AttackStep, SimulatedAction
from evidencesoc.domain.models import (
    AgentRun,
    Alert,
    ApprovalRecord,
    AttackClassification,
    AttackOrigin,
    EvidenceItem,
    Incident,
    IncidentStatus,
    ResponsePlan,
    Severity,
    ValidationResult,
)


class StrictRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class AlertRequest(StrictRequest):
    alert_id: str | None = Field(default=None, min_length=1, max_length=64)
    title: str = Field(min_length=1, max_length=2000)
    severity: Severity
    event_ids: list[str] = Field(min_length=1, max_length=200)
    created_at: datetime | None = None

    @field_validator("event_ids")
    @classmethod
    def valid_event_ids(cls, values: list[str]) -> list[str]:
        if any(not value.strip() or len(value) > 64 for value in values):
            raise ValueError("invalid event identifier")
        return list(dict.fromkeys(value.strip() for value in values))

    @field_validator("created_at")
    @classmethod
    def aware_timestamp(cls, value: datetime | None) -> datetime | None:
        if value is not None and value.tzinfo is None:
            raise ValueError("timestamp requires a timezone")
        return value


class InvestigationRequest(StrictRequest):
    alert_id: str | None = Field(default=None, min_length=1, max_length=64)
    incident_id: str | None = Field(default=None, min_length=1, max_length=64)

    @model_validator(mode="after")
    def one_identifier(self) -> Self:
        if (self.alert_id is None) == (self.incident_id is None):
            raise ValueError("provide one alert or incident identifier")
        return self


class DecisionRequest(StrictRequest):
    reason: str = Field(min_length=1, max_length=2000)
    decided_by: str = Field(min_length=1, max_length=128)


class InvestigationAccepted(BaseModel):
    investigation_id: str
    incident_id: str
    trace_id: str
    status: IncidentStatus
    stream_url: str


class AlertListItem(Alert):
    status: IncidentStatus


class AlertPage(BaseModel):
    items: list[AlertListItem]
    total: int
    page: int
    page_size: int


class AttackStepView(AttackStep):
    incident_id: str


class SimulationResult(SimulatedAction):
    execution_id: str
    simulated: Literal[True]
    status: str
    outcome: str


class IncidentDetail(Incident):
    investigation_id: str | None
    trace_id: str | None
    alerts: list[Alert]
    evidence: list[EvidenceItem]
    knowledge: list[dict[str, Any]]
    attack_steps: list[AttackStepView]
    runs: list[AgentRun]
    origin: AttackOrigin | None
    classification: AttackClassification | None
    response_plan: ResponsePlan | None
    approval: ApprovalRecord | None
    validation_result: ValidationResult | None
    simulation: list[SimulationResult]
    fallback_used: bool
    errors: list[dict[str, Any]]
    stop_reason: str | None


class EvaluationDetail(BaseModel):
    evaluation_run_id: str
    dataset_name: str
    configuration: dict[str, Any]
    metrics: dict[str, Any]
    status: Literal["pending", "running", "completed", "failed"]
    started_at: datetime
    finished_at: datetime | None


class DecisionAccepted(BaseModel):
    response_plan_id: str
    investigation_id: str
    incident_id: str
    trace_id: str
    decision: Literal["approved", "rejected"]
    status: Literal["accepted"]


class ErrorDetail(BaseModel):
    code: str
    message: str
    trace_id: str | None


class ErrorEnvelope(BaseModel):
    error: ErrorDetail


ERROR_RESPONSES: dict[int | str, dict[str, Any]] = {
    status: {"model": ErrorEnvelope} for status in (404, 409, 422, 503)
}
