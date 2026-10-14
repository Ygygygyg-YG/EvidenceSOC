from datetime import datetime
from typing import Any

from pgvector.sqlalchemy import Vector  # type: ignore[import-untyped]
from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class SecurityEventTable(Base):
    __tablename__ = "security_events"
    __table_args__ = (
        UniqueConstraint(
            "source",
            "deduplication_key",
            name="uq_security_events_source_deduplication_key",
        ),
        CheckConstraint(
            "severity IN ('info', 'low', 'medium', 'high', 'critical')",
            name="ck_security_events_severity",
        ),
        CheckConstraint(
            "content_sha256 ~ '^[0-9a-f]{64}$'",
            name="ck_security_events_content_sha256",
        ),
        CheckConstraint(
            "index_status IN ('pending', 'indexed', 'failed')",
            name="ck_security_events_index_status",
        ),
    )

    event_id: Mapped[str] = mapped_column(
        String(64),
        primary_key=True,
    )
    source: Mapped[str] = mapped_column(String(128))
    external_id: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )
    deduplication_key: Mapped[str] = mapped_column(
        String(320),
        nullable=False,
    )
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    ingested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    severity: Mapped[str] = mapped_column(String(16))
    event_type: Mapped[str] = mapped_column(String(128))
    raw: Mapped[dict[str, Any]] = mapped_column(JSONB)
    content_sha256: Mapped[str] = mapped_column(String(64))
    index_status: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default="pending",
        server_default="pending",
    )
    indexed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    index_error: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )


class AlertTable(Base):
    __tablename__ = "alerts"
    __table_args__ = (
        CheckConstraint(
            "severity IN ('info', 'low', 'medium', 'high', 'critical')",
            name="ck_alerts_severity",
        ),
    )

    alert_id: Mapped[str] = mapped_column(
        String(64),
        primary_key=True,
    )
    title: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(16))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    event_ids: Mapped[list[str]] = mapped_column(JSONB)


class IncidentTable(Base):
    __tablename__ = "incidents"
    __table_args__ = (
        CheckConstraint(
            "status IN ("
            "'received', "
            "'triaged', "
            "'collecting', "
            "'analyzing', "
            "'reconstructing', "
            "'awaiting_approval', "
            "'simulating', "
            "'validating', "
            "'completed', "
            "'failed', "
            "'manual_review', "
            "'rejected'"
            ")",
            name="ck_incidents_status",
        ),
    )

    incident_id: Mapped[str] = mapped_column(
        String(64),
        primary_key=True,
    )
    alert_id: Mapped[str] = mapped_column(
        ForeignKey("alerts.alert_id", ondelete="CASCADE")
    )
    status: Mapped[str] = mapped_column(String(32))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class EvidenceItemTable(Base):
    __tablename__ = "evidence_items"
    __table_args__ = (
        UniqueConstraint(
            "incident_id",
            "event_id",
            "query_fingerprint",
            name="uq_evidence_items_incident_event_query",
        ),
        CheckConstraint(
            "content_sha256 ~ '^[0-9a-f]{64}$'",
            name="ck_evidence_items_content_sha256",
        ),
    )
    evidence_id: Mapped[str] = mapped_column(
        String(64),
        primary_key=True,
    )
    incident_id: Mapped[str] = mapped_column(
        ForeignKey("incidents.incident_id", ondelete="CASCADE")
    )
    event_id: Mapped[str] = mapped_column(
        ForeignKey(
            "security_events.event_id",
            ondelete="RESTRICT",
            name="fk_evidence_items_event_id_security_events",
        )
    )
    source: Mapped[str] = mapped_column(String(128))
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    query: Mapped[dict[str, Any]] = mapped_column(JSONB)
    query_fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True)
    summary: Mapped[str] = mapped_column(Text)
    content_sha256: Mapped[str] = mapped_column(String(64))


class AttackStepTable(Base):
    __tablename__ = "attack_steps"
    __table_args__ = (
        UniqueConstraint(
            "incident_id",
            "sequence",
            name="uq_attack_steps_incident_sequence",
        ),
    )

    attack_step_id: Mapped[str] = mapped_column(
        String(64),
        primary_key=True,
    )
    incident_id: Mapped[str] = mapped_column(
        ForeignKey("incidents.incident_id", ondelete="CASCADE")
    )
    sequence: Mapped[int] = mapped_column(Integer)
    phase: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )
    technique_id: Mapped[str | None] = mapped_column(
        String(32),
        nullable=True,
    )
    description: Mapped[str] = mapped_column(Text)
    occurred_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    evidence_ids: Mapped[list[str]] = mapped_column(JSONB)


class AgentRunTable(Base):
    __tablename__ = "agent_runs"
    __table_args__ = (
        CheckConstraint(
            "status IN ('pending', 'running', 'completed', 'failed')",
            name="ck_agent_runs_status",
        ),
        CheckConstraint(
            "finished_at IS NULL OR finished_at >= started_at",
            name="ck_agent_runs_time_order",
        ),
    )
    run_id: Mapped[str] = mapped_column(
        String(64),
        primary_key=True,
    )
    incident_id: Mapped[str] = mapped_column(
        ForeignKey("incidents.incident_id", ondelete="CASCADE")
    )
    agent_name: Mapped[str] = mapped_column(String(128))
    status: Mapped[str] = mapped_column(String(32))
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    evidence_ids: Mapped[list[str]] = mapped_column(JSONB)
    output_summary: Mapped[dict[str, Any] | None] = mapped_column(
        JSON().with_variant(JSONB(), "postgresql"), nullable=True
    )


class ToolCallTable(Base):
    __tablename__ = "tool_calls"
    __table_args__ = (
        CheckConstraint(
            "finished_at IS NULL OR finished_at >= started_at",
            name="ck_tool_calls_time_order",
        ),
    )
    tool_call_id: Mapped[str] = mapped_column(
        String(64),
        primary_key=True,
    )
    run_id: Mapped[str] = mapped_column(
        ForeignKey("agent_runs.run_id", ondelete="CASCADE")
    )
    tool_name: Mapped[str] = mapped_column(String(128))
    arguments: Mapped[dict[str, Any]] = mapped_column(JSONB)
    result: Mapped[dict[str, Any] | None] = mapped_column(
        JSONB,
        nullable=True,
    )
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    success: Mapped[bool] = mapped_column(Boolean)
    error_code: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )


class InvestigationToolCallTable(Base):
    """Durable logical investigation calls, separate from physical-call audit."""

    __tablename__ = "investigation_tool_calls"
    __table_args__ = (
        CheckConstraint("round_no > 0", name="ck_investigation_tool_calls_round"),
        CheckConstraint(
            "purpose IN ('collection', 'verification')",
            name="ck_investigation_tool_calls_purpose",
        ),
        CheckConstraint(
            "status IN ('reserved', 'running', 'completed', 'failed')",
            name="ck_investigation_tool_calls_status",
        ),
        CheckConstraint(
            "attempts >= 0 AND attempts <= 3",
            name="ck_investigation_tool_calls_attempts",
        ),
        Index(
            "ix_investigation_tool_calls_fingerprint",
            "incident_id",
            "purpose",
            "fingerprint",
        ),
    )

    call_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    incident_id: Mapped[str] = mapped_column(
        ForeignKey("incidents.incident_id", ondelete="CASCADE"), nullable=False
    )
    run_id: Mapped[str] = mapped_column(
        ForeignKey("agent_runs.run_id", ondelete="CASCADE"), nullable=False
    )
    round_no: Mapped[int] = mapped_column(Integer, nullable=False)
    purpose: Mapped[str] = mapped_column(String(16), nullable=False)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    tool_name: Mapped[str] = mapped_column(String(128), nullable=False)
    arguments: Mapped[dict[str, Any]] = mapped_column(
        JSON().with_variant(JSONB(), "postgresql"), nullable=False
    )
    rationale: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    charged: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    source_call_id: Mapped[str | None] = mapped_column(
        ForeignKey("investigation_tool_calls.call_id"), nullable=True
    )
    result: Mapped[Any | None] = mapped_column(
        JSON().with_variant(JSONB(), "postgresql"), nullable=True
    )
    error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )


class ResponsePlanTable(Base):
    __tablename__ = "response_plans"
    __table_args__ = (
        CheckConstraint(
            "requires_approval = true",
            name="ck_response_plans_requires_approval",
        ),
    )
    response_plan_id: Mapped[str] = mapped_column(
        String(64),
        primary_key=True,
    )
    incident_id: Mapped[str] = mapped_column(
        ForeignKey("incidents.incident_id", ondelete="CASCADE")
    )
    summary: Mapped[str] = mapped_column(Text)
    actions: Mapped[list[dict[str, Any]]] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    requires_approval: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
    )
    evidence_ids: Mapped[list[str]] = mapped_column(JSONB)
    execution_mode: Mapped[str] = mapped_column(
        String(16), default="simulation", server_default="simulation"
    )
    risk_level: Mapped[str | None] = mapped_column(String(16), nullable=True)
    risk_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    affected_assets: Mapped[list[str]] = mapped_column(
        JSONB, default=list, server_default=text("'[]'")
    )
    business_impact: Mapped[str | None] = mapped_column(Text, nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    rollback_steps: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, default=list, server_default=text("'[]'")
    )
    validation_checks: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, default=list, server_default=text("'[]'")
    )


class ApprovalTable(Base):
    __tablename__ = "approvals"
    __table_args__ = (
        CheckConstraint(
            "decision IN ('approved', 'rejected')",
            name="ck_approvals_decision",
        ),
        CheckConstraint(
            "btrim(reason) <> ''",
            name="ck_approvals_reason_nonblank",
        ),
    )
    approval_id: Mapped[str] = mapped_column(
        String(64),
        primary_key=True,
    )
    response_plan_id: Mapped[str] = mapped_column(
        ForeignKey(
            "response_plans.response_plan_id",
            ondelete="CASCADE",
        )
    )
    decision: Mapped[str] = mapped_column(String(16))
    reason: Mapped[str] = mapped_column(Text)
    decided_by: Mapped[str] = mapped_column(String(128))
    decided_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class ValidationResultTable(Base):
    __tablename__ = "validation_results"
    __table_args__ = (
        CheckConstraint(
            "outcome IN ('success', 'failure', 'insufficient_evidence')",
            name="ck_validation_results_outcome",
        ),
    )
    validation_id: Mapped[str] = mapped_column(
        String(64),
        primary_key=True,
    )
    response_plan_id: Mapped[str] = mapped_column(
        ForeignKey(
            "response_plans.response_plan_id",
            ondelete="CASCADE",
        )
    )
    outcome: Mapped[str] = mapped_column(String(32))
    summary: Mapped[str] = mapped_column(Text)
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    evidence_ids: Mapped[list[str]] = mapped_column(JSONB)
    time_from: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    time_to: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    checks: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, default=list, server_default=text("'[]'")
    )


class KnowledgeChunkTable(Base):
    __tablename__ = "knowledge_chunks"

    knowledge_chunk_id: Mapped[str] = mapped_column(
        String(64),
        primary_key=True,
    )
    source: Mapped[str] = mapped_column(String(255))
    content: Mapped[str] = mapped_column(Text)
    chunk_metadata: Mapped[dict[str, Any]] = mapped_column(
        "metadata",
        JSONB,
    )
    embedding: Mapped[list[float] | None] = mapped_column(
        Vector(),
        nullable=True,
    )


class EvaluationRunTable(Base):
    __tablename__ = "evaluation_runs"
    __table_args__ = (
        CheckConstraint(
            "status IN ('pending', 'running', 'completed', 'failed')",
            name="ck_evaluation_runs_status",
        ),
        CheckConstraint(
            "finished_at IS NULL OR finished_at >= started_at",
            name="ck_evaluation_runs_time_order",
        ),
    )

    evaluation_run_id: Mapped[str] = mapped_column(
        String(64),
        primary_key=True,
    )
    dataset_name: Mapped[str] = mapped_column(String(255))
    configuration: Mapped[dict[str, Any]] = mapped_column(JSONB)
    metrics: Mapped[dict[str, Any]] = mapped_column(JSONB)
    status: Mapped[str] = mapped_column(String(32))
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
