import pytest
from sqlalchemy import text

from app import security
from app.models import AuditLog
from tests.conftest import ADMIN, DEVICE, OP, VIEWER


def test_unauthenticated_is_401(client):
    assert client.get("/api/fleet").status_code == 401
    assert client.get("/api/fleet", headers={"X-API-Key": "nope"}).status_code == 401


@pytest.mark.parametrize("path,method,hdr,code", [
    ("/api/audit", "get", VIEWER, 403), ("/api/audit", "get", OP, 403), ("/api/audit", "get", ADMIN, 200),
    ("/api/fleet", "get", DEVICE, 403), ("/api/incidents/1/investigate", "post", VIEWER, 403),
    ("/api/actions/1/decision", "post", OP, 403),
])
def test_rbac_matrix(client, path, method, hdr, code):
    kw = {"json": {"approve": True}} if "decision" in path else {}
    assert getattr(client, method)(path, headers=hdr, **kw).status_code == code


def test_denials_are_audited(client, db):
    client.get("/api/audit", headers=VIEWER)
    e = db.query(AuditLog).filter_by(event="authz_denied").one()
    assert e.role == "viewer" and e.payload["permission"] == "audit"


def test_signature_roundtrip_and_tamper():
    cmd = security.build_command(1, "dev-001", "isolate_device", {}, "operator-x", "admin-y")
    assert security.verify_command(cmd)
    assert not security.verify_command({**cmd, "device_id": "dev-002"})
    assert not security.verify_command({**cmd, "signature": "0" * 64})
    assert not security.verify_command({k: v for k, v in cmd.items() if k != "signature"})


def test_audit_chain_valid_then_detects_tamper(db):
    for i in range(5):
        security.audit(db, "a", "admin", "evt", {"i": i})
    db.commit()
    assert security.verify_chain(db) == {"valid": True, "entries": 5, "broken_at": None}
    db.execute(text("UPDATE audit_log SET actor='mallory' WHERE id=3"))  # bypass ORM
    db.commit()
    res = security.verify_chain(db)
    assert res["valid"] is False and res["broken_at"] == 3


def test_audit_log_orm_is_immutable(db):
    security.audit(db, "a", "admin", "evt", {})
    db.commit()
    row = db.query(AuditLog).first()
    row.actor = "x"
    with pytest.raises(PermissionError):
        db.commit()
    db.rollback()
    db.delete(db.query(AuditLog).first())
    with pytest.raises(PermissionError):
        db.commit()
    db.rollback()


def test_audit_verify_endpoint(client):
    client.get("/api/audit", headers=VIEWER)
    assert client.get("/api/audit/verify", headers=ADMIN).json()["valid"] is True
