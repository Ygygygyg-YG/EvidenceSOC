"""Add durable investigation calls and idempotent evidence identity."""

import base64
import hashlib
import json

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "c74a62f911ab"
down_revision = "b6d091c3e217"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "evidence_items",
        sa.Column("query_fingerprint", sa.String(64), nullable=True),
    )
    connection = op.get_bind()
    existing = connection.execute(
        sa.text(
            "SELECT evidence_id, incident_id, event_id, query "
            "FROM evidence_items ORDER BY evidence_id"
        )
    )
    seen: set[tuple[str, str, str]] = set()
    for row in existing:
        stored_query = row._mapping["query"]
        if (
            set(stored_query) == {"_audit_encoding", "value"}
            and stored_query["_audit_encoding"] == "base64-json"
        ):
            stored_query = json.loads(base64.b64decode(stored_query["value"]))
        fingerprint = hashlib.sha256(
            json.dumps(
                stored_query,
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
        ).hexdigest()
        key = (row.incident_id, row.event_id, fingerprint)
        if key in seen:
            continue
        seen.add(key)
        connection.execute(
            sa.text(
                "UPDATE evidence_items SET query_fingerprint = :fingerprint "
                "WHERE evidence_id = :evidence_id"
            ),
            {"fingerprint": fingerprint, "evidence_id": row.evidence_id},
        )
    op.create_unique_constraint(
        "uq_evidence_items_incident_event_query",
        "evidence_items",
        ["incident_id", "event_id", "query_fingerprint"],
    )
    op.add_column(
        "agent_runs",
        sa.Column("output_summary", postgresql.JSONB(), nullable=True),
    )
    op.create_table(
        "investigation_tool_calls",
        sa.Column("call_id", sa.String(64), primary_key=True),
        sa.Column(
            "incident_id",
            sa.String(64),
            sa.ForeignKey("incidents.incident_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "run_id",
            sa.String(64),
            sa.ForeignKey("agent_runs.run_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("round_no", sa.Integer(), nullable=False),
        sa.Column("purpose", sa.String(16), nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("tool_name", sa.String(128), nullable=False),
        sa.Column("arguments", postgresql.JSONB(), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("charged", sa.Boolean(), nullable=False),
        sa.Column(
            "source_call_id",
            sa.String(64),
            sa.ForeignKey("investigation_tool_calls.call_id"),
            nullable=True,
        ),
        sa.Column("result", postgresql.JSONB(), nullable=True),
        sa.Column("error_code", sa.String(64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("round_no > 0", name="ck_investigation_tool_calls_round"),
        sa.CheckConstraint(
            "purpose IN ('collection', 'verification')",
            name="ck_investigation_tool_calls_purpose",
        ),
        sa.CheckConstraint(
            "status IN ('reserved', 'running', 'completed', 'failed')",
            name="ck_investigation_tool_calls_status",
        ),
        sa.CheckConstraint(
            "attempts >= 0 AND attempts <= 3",
            name="ck_investigation_tool_calls_attempts",
        ),
    )
    op.create_index(
        "ix_investigation_tool_calls_fingerprint",
        "investigation_tool_calls",
        ["incident_id", "purpose", "fingerprint"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_investigation_tool_calls_fingerprint", table_name="investigation_tool_calls"
    )
    op.drop_table("investigation_tool_calls")
    op.drop_column("agent_runs", "output_summary")
    op.drop_constraint(
        "uq_evidence_items_incident_event_query", "evidence_items", type_="unique"
    )
    op.drop_column("evidence_items", "query_fingerprint")
