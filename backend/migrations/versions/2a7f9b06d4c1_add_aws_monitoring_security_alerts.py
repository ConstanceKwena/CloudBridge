"""add AWS monitoring, security findings, and alert lifecycle fields

Revision ID: 2a7f9b06d4c1
Revises: 45e522c87883
Create Date: 2026-10-27 19:45:00.000000
"""
from alembic import op
import sqlalchemy as sa


revision = "2a7f9b06d4c1"
down_revision = "45e522c87883"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("cloud_connections", sa.Column("last_synced_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column(
        "cloud_resources",
        sa.Column("metrics", sa.JSON(), server_default=sa.text("'{}'"), nullable=False),
    )
    op.add_column("cloud_resources", sa.Column("last_synced_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column(
        "security_findings",
        sa.Column("finding_id", sa.String(length=180), server_default="", nullable=False),
    )
    op.add_column(
        "security_findings",
        sa.Column("affected_resource", sa.String(length=180), server_default="Unknown resource", nullable=False),
    )
    op.add_column("security_findings", sa.Column("recommendation", sa.Text(), server_default="", nullable=False))
    op.add_column(
        "security_findings",
        sa.Column("detected_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index(op.f("ix_security_findings_finding_id"), "security_findings", ["finding_id"], unique=False)
    op.add_column("alerts", sa.Column("status", sa.String(length=24), server_default="active", nullable=False))
    op.add_column("alerts", sa.Column("deduplication_key", sa.String(length=200), nullable=True))
    op.add_column("alerts", sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("alerts", sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True))
    op.create_index(op.f("ix_alerts_deduplication_key"), "alerts", ["deduplication_key"], unique=False)
    with op.batch_alter_table("alerts") as batch_op:
        batch_op.create_check_constraint("ck_alert_status", "status IN ('active', 'acknowledged', 'resolved')")


def downgrade() -> None:
    with op.batch_alter_table("alerts") as batch_op:
        batch_op.drop_constraint("ck_alert_status", type_="check")
    op.drop_index(op.f("ix_alerts_deduplication_key"), table_name="alerts")
    op.drop_column("alerts", "resolved_at")
    op.drop_column("alerts", "acknowledged_at")
    op.drop_column("alerts", "deduplication_key")
    op.drop_column("alerts", "status")
    op.drop_index(op.f("ix_security_findings_finding_id"), table_name="security_findings")
    op.drop_column("security_findings", "detected_at")
    op.drop_column("security_findings", "recommendation")
    op.drop_column("security_findings", "affected_resource")
    op.drop_column("security_findings", "finding_id")
    op.drop_column("cloud_resources", "last_synced_at")
    op.drop_column("cloud_resources", "metrics")
    op.drop_column("cloud_connections", "last_synced_at")
