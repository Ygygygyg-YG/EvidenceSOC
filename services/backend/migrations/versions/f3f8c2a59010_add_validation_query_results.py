"""Store the executed validation query windows and per-check outcomes."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "f3f8c2a59010"
down_revision = "d7b7d8cb8b42"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "validation_results", sa.Column("time_from", sa.DateTime(timezone=True))
    )
    op.add_column(
        "validation_results", sa.Column("time_to", sa.DateTime(timezone=True))
    )
    op.add_column(
        "validation_results",
        sa.Column(
            "checks",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
    )


def downgrade() -> None:
    op.drop_column("validation_results", "checks")
    op.drop_column("validation_results", "time_to")
    op.drop_column("validation_results", "time_from")
