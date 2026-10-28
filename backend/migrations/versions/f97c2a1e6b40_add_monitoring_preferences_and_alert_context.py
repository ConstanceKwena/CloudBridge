"""add monitoring preferences and alert context

Revision ID: f97c2a1e6b40
Revises: 3c6d8a1f2b40
Create Date: 2026-10-28 10:00:00.000000
"""
from alembic import op
import sqlalchemy as sa


revision = "f97c2a1e6b40"
down_revision = "3c6d8a1f2b40"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("cpu_alert_threshold", sa.Float(), server_default="80.0", nullable=False),
    )
    op.add_column(
        "users",
        sa.Column("memory_alert_threshold", sa.Float(), server_default="85.0", nullable=False),
    )
    op.add_column("cloud_connections", sa.Column("last_scan_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column(
        "cloud_connections",
        sa.Column("last_successful_scan_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "cloud_connections",
        sa.Column("scan_checks", sa.JSON(), server_default=sa.text("'{}'"), nullable=False),
    )
    op.add_column(
        "alerts",
        sa.Column("affected_resource", sa.String(length=180), server_default="Unknown resource", nullable=False),
    )
    op.add_column("alerts", sa.Column("recommendation", sa.Text(), server_default="", nullable=False))


def downgrade() -> None:
    op.drop_column("alerts", "recommendation")
    op.drop_column("alerts", "affected_resource")
    op.drop_column("cloud_connections", "scan_checks")
    op.drop_column("cloud_connections", "last_successful_scan_at")
    op.drop_column("cloud_connections", "last_scan_at")
    op.drop_column("users", "memory_alert_threshold")
    op.drop_column("users", "cpu_alert_threshold")