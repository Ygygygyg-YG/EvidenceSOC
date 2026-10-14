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
from evidencesoc.domain.response_action import SimulationExecution


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
    mode: Literal["rules", "model"]

    @model_validator(mode="after")
    def one_identifier(self) -> Self:
        if (self.alert_id is None) == (self.incident_id is None):
            raise ValueError("provide one alert or incident identifier")
        return self


class DecisionRequest(StrictRequest):
    plan_version: str = Field(pattern=r"^[0-9a-f]{64}$")
    reason: str = Field(min_length=1, max_length=2000)


class PlanRenewalRequest(StrictRequest):
    plan_version: str = Field(pattern=r"^[0-9a-f]{64}$")


class InvestigationAccepted(BaseModel):
    investigation_id: str
    incident_id: str
    trace_id: str
    status: IncidentStatus
    stream_url: str


class AlertListItem(Alert):
    status: IncidentStatus


class AlertEventSummary(BaseModel):
    event_id: str
    source: str
    observed_at: datetime
    severity: Severity
    event_type: str


class AlertDetail(AlertListItem):
    execution_mode: Literal["rules", "model"]
    incident_id: str | None
    investigation_id: str | None
    events: list[AlertEventSummary]


class AlertPage(BaseModel):
    items: list[AlertListItem]
    total: int
    page: int
    page_size: int


class IncidentListItem(Incident):
    investigation_id: str | None
    alert_title: str
    severity: Severity
    evidence_count: int
    validation_outcome: Literal["success", "failure", "insufficient_evidence"] | None


class IncidentPage(BaseModel):
    items: list[IncidentListItem]
    total: int
    page: int
    page_size: int


class DashboardMetrics(BaseModel):
    alerts_in_window: int = Field(ge=0)
    high_risk_incidents: int = Field(ge=0)
    running_investigations: int = Field(ge=0)
    pending_response_plans: int = Field(ge=0)


class AlertTrendBucket(BaseModel):
    bucket_start: datetime
    bucket_end: datetime
    total: int = Field(ge=0)
    high_risk: int = Field(ge=0)


class IncidentStatusCount(BaseModel):
    status: IncidentStatus
    count: int = Field(ge=0)


class RecentActivity(BaseModel):
    event: str
    occurred_at: datetime
    incident_id: str
    investigation_id: str


class SourceHealthItem(BaseModel):
    source: str
    last_ingested_at: datetime
    ingestion_lag_seconds: int | None = Field(ge=0)
    status: Literal["ok", "degraded", "failed"] | None
    is_stale: bool | None


class SourceHealthSummary(BaseModel):
    checked_at: datetime
    postgresql_status: Literal["ok", "degraded", "failed"] | None
    opensearch_status: Literal["ok", "degraded", "failed"] | None
    is_stale: bool | None
    sources: list[SourceHealthItem]


class DashboardSummary(BaseModel):
    window: Literal["1h", "24h", "7d"]
    execution_mode: Literal["rules", "model"]
    time_from: datetime
    time_to: datetime
    generated_at: datetime
    metrics: DashboardMetrics
    alert_trend: list[AlertTrendBucket]
    incident_status_distribution: list[IncidentStatusCount]
    recent_alerts: list[AlertListItem]
    recent_activity: list[RecentActivity]
    source_health: SourceHealthSummary


class EvidenceItemView(EvidenceItem):
    incident_id: str


class EvidencePage(BaseModel):
    items: list[EvidenceItemView]
    total: int
    page: int
    page_size: int


class EvidenceRawEvent(BaseModel):
    event_id: str
    source: str
    observed_at: datetime
    severity: Severity
    event_type: str
    raw: dict[str, Any]
    content_sha256: str


class EvidenceIntegrity(BaseModel):
    algorithm: Literal["sha256"]
    canonicalization: Literal["evidencesoc-json-v1"]
    scope: Literal["postgresql"]
    status: Literal["verified", "mismatch", "unavailable"]
    checked_at: datetime
    calculated_sha256: str | None
    stored_event_sha256: str
    stored_evidence_sha256: str


class EvidenceDetail(BaseModel):
    evidence: EvidenceItemView
    raw_event: EvidenceRawEvent
    raw_access: Literal["full"]
    integrity: EvidenceIntegrity


class AttackStepView(AttackStep):
    incident_id: str


class SimulationResult(SimulatedAction):
    execution_id: str
    simulated: Literal[True]
    status: str
    outcome: str


class ResponsePlanListItem(ResponsePlan):
    plan_version: str = Field(pattern=r"^[0-9a-f]{64}$")
    is_expired: bool
    investigation_id: str | None
    alert_id: str
    alert_title: str
    severity: Severity
    incident_status: IncidentStatus
    decision_state: Literal["pending", "submitting", "approved", "rejected"]
    is_current: bool


class ResponsePlanPage(BaseModel):
    items: list[ResponsePlanListItem]
    total: int
    page: int
    page_size: int


class ResponsePlanDetail(ResponsePlanListItem):
    approval: ApprovalRecord | None
    validation_result: ValidationResult | None
    simulation: list[SimulationResult]
    simulation_execution: SimulationExecution | None = None
    pending_decision: Literal["approved", "rejected"] | None
    available_actions: list[Literal["approve", "reject"]]


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
    simulation_execution: SimulationExecution | None = None
    fallback_used: bool
    errors: list[dict[str, Any]]
    stop_reason: str | None


class InvestigationAgentRun(AgentRun):
    role_key: str | None
    attempt: int | None
    output_summary: str | None
    error: str | None


class InvestigationKnowledgeRef(BaseModel):
    knowledge_chunk_id: str
    technique_id: str | None
    title: str | None
    version: str | None
    source_uri: str
    retrieved_at: datetime | None


class AttackGraphNode(BaseModel):
    step_id: str
    sequence: int
    phase: str | None
    description: str
    host: str | None
    service: str | None
    observed_at: datetime | None
    technique_ids: list[str]
    confidence: float | None
    evidence_ids: list[str]
    support_status: Literal["supported", "candidate", "insufficient"]


class AttackGraphEdge(BaseModel):
    edge_id: str
    source_step_id: str
    target_step_id: str
    relation: str
    description: str | None
    confidence: float | None
    evidence_ids: list[str]
    support_status: Literal["supported", "candidate", "insufficient"]


class AttackGraph(BaseModel):
    revision: str = Field(pattern=r"^(0|[1-9][0-9]*)$")
    generated_at: datetime
    nodes: list[AttackGraphNode]
    edges: list[AttackGraphEdge]


class InvestigationEvidenceSummary(BaseModel):
    total: int = Field(ge=0)
    items: list[EvidenceItem]


class InvestigationReview(BaseModel):
    required: bool
    reason: str | None
    fallback_count: int = Field(ge=0)


class InvestigationFailure(BaseModel):
    code: str
    message: str
    trace_id: str


class InvestigationSnapshot(IncidentDetail):
    revision: str = Field(pattern=r"^(0|[1-9][0-9]*)$")
    stream_cursor: str = Field(pattern=r"^(0|[1-9][0-9]*)$")
    updated_at: datetime
    mode: Literal["rules", "model"]
    available_actions: list[Literal["approve", "reject"]]
    incident: Incident
    alert: Alert
    agent_runs: list[InvestigationAgentRun]
    knowledge_refs: list[InvestigationKnowledgeRef]
    attack_graph: AttackGraph
    evidence_summary: InvestigationEvidenceSummary
    validation: ValidationResult | None
    review: InvestigationReview
    error: InvestigationFailure | None


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


class PlanRenewalAccepted(BaseModel):
    response_plan_id: str
    investigation_id: str
    incident_id: str
    trace_id: str
    status: Literal["accepted"]
    stream_url: str


class ErrorDetail(BaseModel):
    code: str
    message: str
    trace_id: str | None


class ErrorEnvelope(BaseModel):
    error: ErrorDetail


ERROR_RESPONSES: dict[int | str, dict[str, Any]] = {
    status: {"model": ErrorEnvelope} for status in (404, 409, 422, 503)
}
