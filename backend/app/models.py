from datetime import datetime, timezone

from sqlalchemy import Boolean, CheckConstraint, DateTime, ForeignKey, Integer, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False
    )


class User(TimestampMixin, Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(254), unique=True, index=True, nullable=False)
    full_name: Mapped[str] = mapped_column(String(120), nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    cloud_connections: Mapped[list["CloudConnection"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )
    cloud_resources: Mapped[list["CloudResource"]] = relationship(back_populates="user", cascade="all, delete-orphan")
    security_findings: Mapped[list["SecurityFinding"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )
    alerts: Mapped[list["Alert"]] = relationship(back_populates="user", cascade="all, delete-orphan")


class CloudConnection(TimestampMixin, Base):
    __tablename__ = "cloud_connections"
    __table_args__ = (UniqueConstraint("user_id", "display_name", name="uq_connection_user_name"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    display_name: Mapped[str] = mapped_column(String(100), nullable=False)
    status: Mapped[str] = mapped_column(String(24), default="connected", nullable=False)
    region: Mapped[str | None] = mapped_column(String(64))
    account_identifier: Mapped[str | None] = mapped_column(String(128))
    simulated: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    last_synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    user: Mapped[User] = relationship(back_populates="cloud_connections")
    resources: Mapped[list["CloudResource"]] = relationship(back_populates="connection")


class CloudResource(TimestampMixin, Base):
    __tablename__ = "cloud_resources"
    __table_args__ = (
        CheckConstraint("monthly_cost >= 0", name="ck_resource_nonnegative_cost"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    connection_id: Mapped[int | None] = mapped_column(
        ForeignKey("cloud_connections.id", ondelete="SET NULL"), index=True
    )
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(64), nullable=False)
    region: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    monthly_cost: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    tags: Mapped[dict[str, str]] = mapped_column(JSON, default=dict, nullable=False)
    metrics: Mapped[dict[str, float | None]] = mapped_column(JSON, default=dict, nullable=False)
    last_synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    simulated: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    user: Mapped[User] = relationship(back_populates="cloud_resources")
    connection: Mapped[CloudConnection | None] = relationship(back_populates="resources")
    security_findings: Mapped[list["SecurityFinding"]] = relationship(back_populates="resource")


class SecurityFinding(TimestampMixin, Base):
    __tablename__ = "security_findings"
    __table_args__ = (
        CheckConstraint("severity IN ('critical', 'high', 'medium', 'low', 'info')", name="ck_finding_severity"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    finding_id: Mapped[str] = mapped_column(String(180), index=True, nullable=False, default="")
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    resource_id: Mapped[int | None] = mapped_column(ForeignKey("cloud_resources.id", ondelete="SET NULL"))
    affected_resource: Mapped[str] = mapped_column(String(180), default="Unknown resource", nullable=False)
    title: Mapped[str] = mapped_column(String(180), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    recommendation: Mapped[str] = mapped_column(Text, default="", nullable=False)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(String(24), default="open", nullable=False)
    simulated: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    user: Mapped[User] = relationship(back_populates="security_findings")
    resource: Mapped[CloudResource | None] = relationship(back_populates="security_findings")


class Alert(TimestampMixin, Base):
    __tablename__ = "alerts"
    __table_args__ = (
        CheckConstraint("severity IN ('critical', 'high', 'medium', 'low', 'info')", name="ck_alert_severity"),
        CheckConstraint("status IN ('active', 'acknowledged', 'resolved')", name="ck_alert_status"),
        UniqueConstraint("user_id", "deduplication_key", name="uq_alert_user_deduplication"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    title: Mapped[str] = mapped_column(String(180), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    is_read: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    simulated: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    status: Mapped[str] = mapped_column(String(24), default="active", nullable=False)
    deduplication_key: Mapped[str | None] = mapped_column(String(200), index=True)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    user: Mapped[User] = relationship(back_populates="alerts")
