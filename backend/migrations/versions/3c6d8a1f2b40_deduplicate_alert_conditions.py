"""deduplicate alerts and record their source mode

Revision ID: 3c6d8a1f2b40
Revises: 2a7f9b06d4c1
Create Date: 2026-10-27 19:49:00.000000
"""
from alembic import op
import sqlalchemy as sa


revision = "3c6d8a1f2b40"
down_revision = "2a7f9b06d4c1"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "alerts",
        sa.Column("simulated", sa.Boolean(), server_default=sa.true(), nullable=False),
    )
    with op.batch_alter_table("alerts") as batch_op:
        batch_op.create_unique_constraint("uq_alert_user_deduplication", ["user_id", "deduplication_key"])


def downgrade() -> None:
    with op.batch_alter_table("alerts") as batch_op:
        batch_op.drop_constraint("uq_alert_user_deduplication", type_="unique")
    op.drop_column("alerts", "simulated")
