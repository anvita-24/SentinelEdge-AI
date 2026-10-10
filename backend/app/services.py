"""Business logic shared by the REST API and the MCP server."""
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import security
from .models import Action, AuthEvent, Device, Incident, now
from .mqtt_client import publish_command

ACTIONS = {  # name -> critical?
    "throttle_telemetry": False,
    "restart_device": False,
    "rotate_credentials": True,
    "isolate_device": True,
    "firmware_rollback": True,
}


class ServiceError(Exception):
    def __init__(self, msg: str, status: int = 400):
        super().__init__(msg)
        self.status = status


def request_action(db: Session, who: security.Principal, device_id: str, action: str,
                   params: dict | None = None, incident_id: int | None = None) -> Action:
    if action not in ACTIONS:
        raise ServiceError(f"unknown action '{action}'; allowed: {sorted(ACTIONS)}", 422)
    dev = db.get(Device, device_id)
    if not dev:
        raise ServiceError(f"device '{device_id}' not found", 404)
    crit = ACTIONS[action]
    act = Action(device_id=device_id, action=action, params=params or {}, critical=crit,
                 incident_id=incident_id, requested_by=who.actor,
                 status="pending_approval" if crit else "approved")
    db.add(act)
    db.flush()
    security.audit(db, who.actor, who.role, "action_requested",
                   {"action_id": act.id, "device_id": device_id, "action": action, "critical": crit})
    if not crit:
        _execute(db, act, approver=who.actor)
    db.commit()
    return act


def decide_action(db: Session, who: security.Principal, action_id: int, approve: bool, note: str = "") -> Action:
    act = db.get(Action, action_id)
    if not act:
        raise ServiceError("action not found", 404)
    if act.status != "pending_approval":
        raise ServiceError(f"action is already {act.status}", 409)
    if who.actor == act.requested_by:
        security.audit(db, who.actor, who.role, "self_approval_blocked", {"action_id": act.id})
        db.commit()
        raise ServiceError("two-person rule: requester cannot approve their own action", 409)
    if not approve:
        act.status, act.approved_by = "rejected", who.actor
        security.audit(db, who.actor, who.role, "action_rejected", {"action_id": act.id, "note": note})
    else:
        security.audit(db, who.actor, who.role, "action_approved", {"action_id": act.id, "note": note})
        _execute(db, act, approver=who.actor)
    db.commit()
    return act


def _execute(db: Session, act: Action, approver: str) -> None:
    cmd = security.build_command(act.id, act.device_id, act.action, act.params, act.requested_by, approver)
    if not security.verify_command(cmd):  # pragma: no cover - defensive
        raise ServiceError("command signature failed verification", 500)
    dev = db.get(Device, act.device_id)
    if act.action == "isolate_device":
        dev.status = "quarantined"
    elif act.action == "restart_device":
        dev.status, dev.risk = "online", round(dev.risk * 0.3, 2)
    elif act.action == "rotate_credentials":
        db.add(AuthEvent(device_id=dev.id, kind="cert_rotate", count=1))
    elif act.action == "firmware_rollback":
        dev.firmware = act.params.get("version", "1.0.0")
    act.status, act.approved_by, act.signature, act.command = "executed", approver, cmd["signature"], cmd
    if act.incident_id and (inc := db.get(Incident, act.incident_id)):
        inc.status = "mitigated"
    delivered = publish_command(act.device_id, cmd)
    security.audit(db, approver, "system", "action_executed",
                   {"action_id": act.id, "action": act.action, "device_id": act.device_id,
                    "signature": cmd["signature"], "delivered_via_mqtt": delivered})


def list_devices(db: Session, min_risk: float = 0.0, limit: int = 200) -> list[Device]:
    q = select(Device).where(Device.risk >= min_risk).order_by(Device.risk.desc(), Device.id).limit(limit)
    return list(db.scalars(q))


def serialize_action(a: Action) -> dict:
    return {"id": a.id, "device_id": a.device_id, "action": a.action, "params": a.params, "critical": a.critical,
            "status": a.status, "requested_by": a.requested_by, "approved_by": a.approved_by,
            "signature": a.signature, "incident_id": a.incident_id, "ts": a.ts.isoformat()}


def serialize_device(d: Device) -> dict:
    return {"id": d.id, "type": d.type, "site": d.site, "firmware": d.firmware, "status": d.status,
            "risk": d.risk, "last_seen": d.last_seen.isoformat() if d.last_seen else None}


def serialize_incident(i: Incident, full: bool = False) -> dict:
    d = {"id": i.id, "device_id": i.device_id, "ts": i.ts.isoformat(), "severity": i.severity,
         "category": i.category, "title": i.title, "status": i.status, "risk": i.risk, "signals": i.signals}
    if full:
        d["report"] = i.report
    return d
