"""Persist idempotent response plan decision receipts."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "c0e8c2a18a7d"
down_revision = "b6d091c3e217"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "api_decision_receipts",
        sa.Column("key", sa.String(255), primary_key=True),
        sa.Column("plan_id", sa.String(64), nullable=False),
        sa.Column("payload_sha256", sa.String(64), nullable=False),
        sa.Column("accepted_response", postgresql.JSONB(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("api_decision_receipts")
