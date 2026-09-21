from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, Literal, Self

from pydantic import BaseModel, Field, field_validator, model_validator


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EventIndexStatus(StrEnum):
    PENDING = "pending"
    INDEXED = "indexed"
    FAILED = "failed"


class IncidentStatus(StrEnum):
    RECEIVED = "received"
    TRIAGED = "triaged"
    COLLECTING = "collecting"
    ANALYZING = "analyzing"
    RECONSTRUCTING = "reconstructing"
    AWAITING_APPROVAL = "awaiting_approval"
    SIMULATING = "simulating"
    VALIDATING = "validating"
    COMPLETED = "completed"
    FAILED = "failed"


class AgentRunStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class ApprovalDecision(StrEnum):
    APPROVED = "approved"
    REJECTED = "rejected"


class SecurityEvent(BaseModel):
    event_id: str
    source: str = Field(min_length=1, max_length=128)
    external_id: str | None = Field(default=None, max_length=255)
    deduplication_key: str = Field(min_length=1, max_length=320)
    observed_at: datetime
    ingested_at: datetime
    severity: Severity
    event_type: str = Field(min_length=1, max_length=128)
    raw: dict[str, Any]
    content_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    index_status: EventIndexStatus = EventIndexStatus.PENDING
    indexed_at: datetime | None = None
    index_error: str | None = None


class AttackOrigin(BaseModel):
    observed_source_ip: str | None
    entry_host: str | None
    entry_service: str | None
    first_seen_at: datetime | None
    source_scope: Literal["external", "internal", "unknown"]
    confidence: float = Field(ge=0, le=1)
    evidence_ids: list[str] = Field(min_length=1)


class AgentRun(BaseModel):
    run_id: str
    incident_id: str
    agent_name: str
    status: AgentRunStatus
    started_at: datetime
    finished_at: datetime | None = None
    evidence_ids: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_time_order(self) -> Self:
        if self.finished_at is not None and self.finished_at < self.started_at:
            raise ValueError("finished_at must be greater than or equal to started_at")

        return self


class ApprovalRecord(BaseModel):
    approval_id: str
    response_plan_id: str
    decision: ApprovalDecision
    reason: str
    decided_by: str
    decided_at: datetime

    @field_validator("reason")
    @classmethod
    def validate_reason(cls, value: str) -> str:
        cleaned_value = value.strip()

        if not cleaned_value:
            raise ValueError("approval reason must not be blank")

        return cleaned_value


class AttackClassification(BaseModel):
    primary_type: str | None
    attack_types: list[str] = Field(min_length=1)
    dataset_labels: list[str] = Field(default_factory=list)
    attack_phase: str | None
    technique_ids: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0, le=1)
    evidence_ids: list[str] = Field(min_length=1)


class Incident(BaseModel):
    incident_id: str
    alert_id: str
    status: IncidentStatus = IncidentStatus.RECEIVED
    created_at: datetime


class EvidenceItem(BaseModel):
    evidence_id: str = Field(pattern=r"^EV-[0-9A-HJKMNP-TV-Z]{26}$")
    event_id: str = Field(min_length=1, max_length=64)
    source: str = Field(min_length=1)
    observed_at: datetime
    query: dict[str, Any]
    summary: str = Field(min_length=1)
    content_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class Alert(BaseModel):
    alert_id: str
    title: str
    severity: Severity
    created_at: datetime
    event_ids: list[str] = Field(min_length=1)


class ResponsePlan(BaseModel):
    response_plan_id: str
    incident_id: str
    summary: str
    actions: list[dict[str, Any]] = Field(min_length=1)
    created_at: datetime
    requires_approval: Literal[True] = True
    evidence_ids: list[str] = Field(min_length=1)


class ValidationOutcome(StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"


class ValidationResult(BaseModel):
    validation_id: str
    response_plan_id: str
    outcome: ValidationOutcome
    summary: str
    checked_at: datetime
    evidence_ids: list[str] = Field(min_length=1)
