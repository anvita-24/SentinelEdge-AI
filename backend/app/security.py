"""RBAC, HMAC-signed commands and the hash-chained audit log."""
import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import settings
from .models import AuditLog, now

PERMS = {
    "device": {"ingest"},
    "viewer": {"read"},
    "operator": {"read", "investigate", "request_action"},
    "admin": {"read", "investigate", "request_action", "approve_action", "audit"},
}
GENESIS = "0" * 64


class AuthError(Exception):
    def __init__(self, msg: str, status: int = 403):
        super().__init__(msg)
        self.status = status


@dataclass(frozen=True)
class Principal:
    actor: str
    role: str


def _canon(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def identify(key: str) -> Principal:
    role = settings.api_keys.get(key or "")
    if not role:
        raise AuthError("invalid or missing API key", 401)
    return Principal(f"{role}-{hashlib.sha256(key.encode()).hexdigest()[:6]}", role)


def authorize(db: Session, key: str, perm: str) -> Principal:
    p = identify(key)
    if perm not in PERMS.get(p.role, set()):
        audit(db, p.actor, p.role, "authz_denied", {"permission": perm})
        db.commit()
        raise AuthError(f"role '{p.role}' lacks permission '{perm}'", 403)
    return p


# --- signed operations -------------------------------------------------------
def sign(payload: dict) -> str:
    return hmac.new(settings.signing_secret.encode(), _canon(payload).encode(), hashlib.sha256).hexdigest()


def verify(payload: dict, signature: str) -> bool:
    return hmac.compare_digest(sign(payload), signature or "")


def build_command(action_id, device_id, action, params, requested_by, approved_by) -> dict:
    body = {
        "action_id": action_id, "device_id": device_id, "action": action, "params": params,
        "requested_by": requested_by, "approved_by": approved_by,
        "issued_at": now().isoformat(), "nonce": secrets.token_hex(8),
    }
    return {**body, "signature": sign(body)}


def verify_command(cmd: dict) -> bool:
    body = {k: v for k, v in cmd.items() if k != "signature"}
    return verify(body, cmd.get("signature", ""))


# --- audit log ---------------------------------------------------------------
def _digest(row: dict) -> str:
    return hashlib.sha256(_canon(row).encode()).hexdigest()


def audit(db: Session, actor: str, role: str, event: str, payload: dict) -> AuditLog:
    last = db.scalars(select(AuditLog).order_by(AuditLog.id.desc()).limit(1)).first()
    prev = last.hash if last else GENESIS
    safe = json.loads(_canon(payload))
    row = {"ts": now().isoformat(), "actor": actor, "role": role, "event": event, "payload": safe, "prev_hash": prev}
    entry = AuditLog(**row, hash=_digest(row))
    db.add(entry)
    db.flush()
    return entry


def verify_chain(db: Session) -> dict:
    prev = GENESIS
    n = 0
    for e in db.scalars(select(AuditLog).order_by(AuditLog.id)):
        row = {"ts": e.ts, "actor": e.actor, "role": e.role, "event": e.event,
               "payload": e.payload, "prev_hash": e.prev_hash}
        if e.prev_hash != prev or _digest(row) != e.hash:
            return {"valid": False, "entries": n, "broken_at": e.id}
        prev = e.hash
        n += 1
    return {"valid": True, "entries": n, "broken_at": None}
