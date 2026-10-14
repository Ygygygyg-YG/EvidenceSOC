"""API coordination tables, separate from the workflow's domain metadata."""

from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from evidencesoc.persistence.tables import AlertTable, IncidentTable


class ApiBase(DeclarativeBase):
    pass


class ApiAlertPayloadTable(ApiBase):
    __tablename__ = "api_alert_payloads"

    alert_id: Mapped[str] = mapped_column(
        ForeignKey(AlertTable.alert_id, ondelete="CASCADE"),
        primary_key=True,
    )
    payload_sha256: Mapped[str] = mapped_column(String(64))


class ApiIdempotencyKeyTable(ApiBase):
    __tablename__ = "api_idempotency_keys"

    key: Mapped[str] = mapped_column(String(255), primary_key=True)
    alert_id: Mapped[str] = mapped_column(
        ForeignKey(AlertTable.alert_id, ondelete="CASCADE")
    )
    payload_sha256: Mapped[str] = mapped_column(String(64))


class ApiDecisionReceiptTable(ApiBase):
    __tablename__ = "api_decision_receipts"

    key: Mapped[str] = mapped_column(String(255), primary_key=True)
    plan_id: Mapped[str] = mapped_column(String(64))
    payload_sha256: Mapped[str] = mapped_column(String(64))
    accepted_response: Mapped[dict[str, Any]] = mapped_column(
        JSON().with_variant(JSONB(), "postgresql")
    )


class ApiInvestigationTable(ApiBase):
    __tablename__ = "api_investigations"
    __table_args__ = (
        UniqueConstraint("incident_id", name="uq_api_investigations_incident_id"),
        UniqueConstraint("trace_id", name="uq_api_investigations_trace_id"),
        CheckConstraint(
            "last_sequence >= 0", name="ck_api_investigations_last_sequence"
        ),
    )

    investigation_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    incident_id: Mapped[str] = mapped_column(
        ForeignKey(IncidentTable.incident_id, ondelete="CASCADE")
    )
    trace_id: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(32))
    state: Mapped[dict[str, Any]] = mapped_column(
        JSON().with_variant(JSONB(), "postgresql")
    )
    last_sequence: Mapped[int] = mapped_column(Integer, default=0, server_default="0")


class ApiInvestigationEventTable(ApiBase):
    __tablename__ = "api_investigation_events"
    __table_args__ = (
        UniqueConstraint(
            "investigation_id",
            "dedup_key",
            name="uq_api_investigation_events_dedup_key",
        ),
        CheckConstraint("sequence > 0", name="ck_api_investigation_events_sequence"),
    )

    investigation_id: Mapped[str] = mapped_column(
        ForeignKey("api_investigations.investigation_id", ondelete="CASCADE"),
        primary_key=True,
    )
    sequence: Mapped[int] = mapped_column(Integer, primary_key=True)
    event: Mapped[str] = mapped_column(String(64))
    data: Mapped[dict[str, Any]] = mapped_column(
        JSON().with_variant(JSONB(), "postgresql")
    )
    dedup_key: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
