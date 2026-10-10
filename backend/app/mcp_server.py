"""MCP server: controlled agent-to-IoT interface.

Run (stdio):  SE_MCP_API_KEY=operator-key python -m app.mcp_server
Every tool authenticates a key -> role (RBAC), critical actions are approval-gated,
commands are HMAC-signed, and everything lands in the hash-chained audit log.
"""
import os

from mcp.server.fastmcp import FastMCP

from . import agent, security, services
from .db import SessionLocal, init_db
from .models import AuditLog, Telemetry
from sqlalchemy import select

mcp = FastMCP("sentineledge")


def _key(k: str) -> str:
    return k or os.getenv("SE_MCP_API_KEY", "")


def _guard(fn):
    def wrapper(*a, **kw):
        init_db()
        try:
            return fn(*a, **kw)
        except (security.AuthError, services.ServiceError) as e:
            raise ValueError(str(e))
    wrapper.__name__, wrapper.__doc__ = fn.__name__, fn.__doc__
    return wrapper


@mcp.tool()
@_guard
def list_devices(min_risk: float = 0.0, api_key: str = "") -> list[dict]:
    """List fleet devices ordered by risk (needs 'read')."""
    with SessionLocal() as db:
        security.authorize(db, _key(api_key), "read")
        return [services.serialize_device(d) for d in services.list_devices(db, min_risk, 50)]


@mcp.tool()
@_guard
def get_device_telemetry(device_id: str, limit: int = 20, api_key: str = "") -> list[dict]:
    """Recent telemetry readings for a device (needs 'read')."""
    with SessionLocal() as db:
        security.authorize(db, _key(api_key), "read")
        rows = db.scalars(select(Telemetry).where(Telemetry.device_id == device_id).order_by(Telemetry.id.desc()).limit(min(limit, 100)))
        return [{"ts": r.ts.isoformat(), "temperature": r.temperature, "cpu": r.cpu, "memory": r.memory,
                 "msg_rate": r.msg_rate, "risk": r.risk, "flagged": r.flagged} for r in rows]


@mcp.tool()
@_guard
def investigate_incident(incident_id: int, api_key: str = "") -> dict:
    """Run the investigation agent: evidence, explanation and remediation plan (needs 'investigate')."""
    with SessionLocal() as db:
        who = security.authorize(db, _key(api_key), "investigate")
        return agent.investigate(db, incident_id, who)


@mcp.tool()
@_guard
def request_remediation(device_id: str, action: str, incident_id: int | None = None, api_key: str = "") -> dict:
    """Request a remediation. Non-critical actions run immediately; critical ones
    (isolate_device, rotate_credentials, firmware_rollback) wait for admin approval (needs 'request_action')."""
    with SessionLocal() as db:
        who = security.authorize(db, _key(api_key), "request_action")
        return services.serialize_action(services.request_action(db, who, device_id, action, {}, incident_id))


@mcp.tool()
@_guard
def decide_remediation(action_id: int, approve: bool, note: str = "", api_key: str = "") -> dict:
    """Approve or reject a pending critical action (needs 'approve_action'; admin, not the requester)."""
    with SessionLocal() as db:
        who = security.authorize(db, _key(api_key), "approve_action")
        return services.serialize_action(services.decide_action(db, who, action_id, approve, note))


@mcp.tool()
@_guard
def verify_audit_log(api_key: str = "") -> dict:
    """Verify integrity of the hash-chained audit log (needs 'audit')."""
    with SessionLocal() as db:
        security.authorize(db, _key(api_key), "audit")
        return security.verify_chain(db)


if __name__ == "__main__":
    mcp.run()
