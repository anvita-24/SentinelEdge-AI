from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, DateTime, Float, Integer, String, event
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base


def now() -> datetime:
    """Naive UTC (portable across SQLite/Postgres)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Device(Base):
    __tablename__ = "devices"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    type: Mapped[str] = mapped_column(String(32))
    site: Mapped[str] = mapped_column(String(32), default="hq")
    firmware: Mapped[str] = mapped_column(String(16), default="1.0.0")
    status: Mapped[str] = mapped_column(String(16), default="online")  # online|quarantined
    risk: Mapped[float] = mapped_column(Float, default=0.0)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class Telemetry(Base):
    __tablename__ = "telemetry"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    device_id: Mapped[str] = mapped_column(String(32), index=True)
    ts: Mapped[datetime] = mapped_column(DateTime, default=now, index=True)
    temperature: Mapped[float] = mapped_column(Float)
    cpu: Mapped[float] = mapped_column(Float)
    memory: Mapped[float] = mapped_column(Float)
    msg_rate: Mapped[float] = mapped_column(Float)
    rssi: Mapped[float] = mapped_column(Float)
    battery: Mapped[float] = mapped_column(Float)
    bytes_out: Mapped[float] = mapped_column(Float)
    failed_auth: Mapped[float] = mapped_column(Float, default=0)
    anomaly_score: Mapped[float] = mapped_column(Float, default=0)
    risk: Mapped[float] = mapped_column(Float, default=0)
    flagged: Mapped[bool] = mapped_column(Boolean, default=False)
    label: Mapped[str | None] = mapped_column(String(32), nullable=True)  # simulator ground truth


class AuthEvent(Base):
    __tablename__ = "auth_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    device_id: Mapped[str] = mapped_column(String(32), index=True)
    ts: Mapped[datetime] = mapped_column(DateTime, default=now)
    kind: Mapped[str] = mapped_column(String(24))  # login_fail | cert_rotate
    count: Mapped[int] = mapped_column(Integer, default=1)
    source_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)


class Incident(Base):
    __tablename__ = "incidents"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    device_id: Mapped[str] = mapped_column(String(32), index=True)
    ts: Mapped[datetime] = mapped_column(DateTime, default=now)
    severity: Mapped[str] = mapped_column(String(12))
    category: Mapped[str] = mapped_column(String(32))
    title: Mapped[str] = mapped_column(String(160))
    status: Mapped[str] = mapped_column(String(16), default="open")  # open|investigating|mitigated
    risk: Mapped[float] = mapped_column(Float)
    signals: Mapped[list] = mapped_column(JSON, default=list)
    report: Mapped[dict | None] = mapped_column(JSON, nullable=True)


class Action(Base):
    __tablename__ = "actions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    incident_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    device_id: Mapped[str] = mapped_column(String(32), index=True)
    action: Mapped[str] = mapped_column(String(32))
    params: Mapped[dict] = mapped_column(JSON, default=dict)
    critical: Mapped[bool] = mapped_column(Boolean, default=False)
    status: Mapped[str] = mapped_column(String(20))  # pending_approval|executed|rejected
    requested_by: Mapped[str] = mapped_column(String(48))
    approved_by: Mapped[str | None] = mapped_column(String(48), nullable=True)
    ts: Mapped[datetime] = mapped_column(DateTime, default=now)
    signature: Mapped[str | None] = mapped_column(String(64), nullable=True)
    command: Mapped[dict | None] = mapped_column(JSON, nullable=True)


class AuditLog(Base):
    """Append-only, hash-chained. ORM updates/deletes are blocked below."""

    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[str] = mapped_column(String(32))
    actor: Mapped[str] = mapped_column(String(48))
    role: Mapped[str] = mapped_column(String(16))
    event: Mapped[str] = mapped_column(String(48))
    payload: Mapped[dict] = mapped_column(JSON)
    prev_hash: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64))


@event.listens_for(AuditLog, "before_update")
@event.listens_for(AuditLog, "before_delete")
def _immutable(*_):
    raise PermissionError("audit_log is append-only")
