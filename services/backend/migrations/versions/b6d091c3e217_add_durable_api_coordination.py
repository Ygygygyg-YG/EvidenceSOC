"""Persist API idempotency, investigation metadata, and replayable events."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "b6d091c3e217"
down_revision = "a8f02c68d901"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "api_alert_payloads",
        sa.Column(
            "alert_id",
            sa.String(64),
            sa.ForeignKey("alerts.alert_id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("payload_sha256", sa.String(64), nullable=False),
    )
    op.create_table(
        "api_idempotency_keys",
        sa.Column("key", sa.String(255), primary_key=True),
        sa.Column(
            "alert_id",
            sa.String(64),
            sa.ForeignKey("alerts.alert_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("payload_sha256", sa.String(64), nullable=False),
    )
    op.create_table(
        "api_investigations",
        sa.Column("investigation_id", sa.String(64), primary_key=True),
        sa.Column(
            "incident_id",
            sa.String(64),
            sa.ForeignKey("incidents.incident_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("trace_id", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("state", postgresql.JSONB(), nullable=False),
        sa.Column("last_sequence", sa.Integer(), nullable=False, server_default="0"),
        sa.UniqueConstraint("incident_id", name="uq_api_investigations_incident_id"),
        sa.UniqueConstraint("trace_id", name="uq_api_investigations_trace_id"),
        sa.CheckConstraint(
            "last_sequence >= 0", name="ck_api_investigations_last_sequence"
        ),
    )
    op.create_table(
        "api_investigation_events",
        sa.Column(
            "investigation_id",
            sa.String(64),
            sa.ForeignKey("api_investigations.investigation_id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("sequence", sa.Integer(), primary_key=True),
        sa.Column("event", sa.String(64), nullable=False),
        sa.Column("data", postgresql.JSONB(), nullable=False),
        sa.Column("dedup_key", sa.String(255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "investigation_id",
            "dedup_key",
            name="uq_api_investigation_events_dedup_key",
        ),
        sa.CheckConstraint("sequence > 0", name="ck_api_investigation_events_sequence"),
    )


def downgrade() -> None:
    op.drop_table("api_investigation_events")
    op.drop_table("api_investigations")
    op.drop_table("api_idempotency_keys")
    op.drop_table("api_alert_payloads")
