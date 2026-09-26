"""Add explicit investigation review and rejection states."""

from alembic import op

revision = "a8f02c68d901"
down_revision = "f311d6238878"
branch_labels = None
depends_on = None

OLD_STATES = (
    "'received', 'triaged', 'collecting', 'analyzing', 'reconstructing', "
    "'awaiting_approval', 'simulating', 'validating', 'completed', 'failed'"
)


def upgrade() -> None:
    op.drop_constraint("ck_incidents_status", "incidents", type_="check")
    op.create_check_constraint(
        "ck_incidents_status",
        "incidents",
        f"status IN ({OLD_STATES}, 'manual_review', 'rejected')",
    )


def downgrade() -> None:
    op.execute(
        "UPDATE incidents SET status = 'failed' WHERE status IN ('manual_review', 'rejected')"
    )
    op.drop_constraint("ck_incidents_status", "incidents", type_="check")
    op.create_check_constraint(
        "ck_incidents_status", "incidents", f"status IN ({OLD_STATES})"
    )
