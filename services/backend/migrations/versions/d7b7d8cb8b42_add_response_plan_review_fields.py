"""Persist response plan review details and expiry."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "d7b7d8cb8b42"
down_revision = "c0e8c2a18a7d"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "response_plans",
        sa.Column(
            "execution_mode", sa.String(16), nullable=False, server_default="simulation"
        ),
    )
    op.add_column("response_plans", sa.Column("risk_level", sa.String(16)))
    op.add_column("response_plans", sa.Column("risk_reason", sa.Text()))
    op.add_column(
        "response_plans",
        sa.Column(
            "affected_assets",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
    )
    op.add_column("response_plans", sa.Column("business_impact", sa.Text()))
    op.add_column("response_plans", sa.Column("expires_at", sa.DateTime(timezone=True)))
    op.add_column(
        "response_plans",
        sa.Column(
            "rollback_steps",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
    )
    op.add_column(
        "response_plans",
        sa.Column(
            "validation_checks",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
    )


def downgrade() -> None:
    for column in (
        "validation_checks",
        "rollback_steps",
        "expires_at",
        "business_impact",
        "affected_assets",
        "risk_reason",
        "risk_level",
        "execution_mode",
    ):
        op.drop_column("response_plans", column)
