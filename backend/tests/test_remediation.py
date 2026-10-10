from app import security
from app.models import AuditLog, Device
from tests.conftest import ADMIN, DEVICE, OP, VIEWER, make_event


def _seed(client):
    client.post("/api/telemetry", json=make_event(seed=1), headers=DEVICE)


def _req(client, action, hdr=OP, **kw):
    return client.post("/api/actions", json={"device_id": "dev-001", "action": action, **kw}, headers=hdr)


def test_non_critical_action_executes_immediately_and_signed(client):
    _seed(client)
    r = _req(client, "restart_device").json()
    assert r["status"] == "executed" and len(r["signature"]) == 64 and not r["critical"]


def test_critical_action_waits_for_admin_and_is_not_applied(client, db):
    _seed(client)
    r = _req(client, "isolate_device").json()
    assert r["status"] == "pending_approval" and r["signature"] is None
    assert db.get(Device, "dev-001").status == "online"


def test_admin_approval_executes_with_verifiable_signature(client, db):
    _seed(client)
    aid = _req(client, "isolate_device").json()["id"]
    d = client.post(f"/api/actions/{aid}/decision", json={"approve": True, "note": "ok"}, headers=ADMIN).json()
    assert d["status"] == "executed" and d["approved_by"].startswith("admin")
    assert db.get(Device, "dev-001").status == "quarantined"
    from app.models import Action
    cmd = db.get(Action, aid).command
    assert security.verify_command(cmd) and cmd["requested_by"] != cmd["approved_by"]


def test_operator_cannot_approve(client):
    _seed(client)
    aid = _req(client, "isolate_device").json()["id"]
    assert client.post(f"/api/actions/{aid}/decision", json={"approve": True}, headers=OP).status_code == 403


def test_two_person_rule_blocks_self_approval(client, db):
    _seed(client)
    aid = _req(client, "rotate_credentials", hdr=ADMIN).json()["id"]
    r = client.post(f"/api/actions/{aid}/decision", json={"approve": True}, headers=ADMIN)
    assert r.status_code == 409 and "two-person" in r.json()["detail"]
    assert db.query(AuditLog).filter_by(event="self_approval_blocked").count() == 1


def test_second_admin_can_approve(client):
    _seed(client)
    aid = _req(client, "rotate_credentials", hdr=ADMIN).json()["id"]
    from app.config import settings
    settings.api_keys["admin2-key"] = "admin"
    try:
        r = client.post(f"/api/actions/{aid}/decision", json={"approve": True}, headers={"X-API-Key": "admin2-key"})
        assert r.status_code == 200 and r.json()["status"] == "executed"
    finally:
        settings.api_keys.pop("admin2-key")


def test_reject_and_no_double_decision(client, db):
    _seed(client)
    aid = _req(client, "firmware_rollback").json()["id"]
    r = client.post(f"/api/actions/{aid}/decision", json={"approve": False}, headers=ADMIN).json()
    assert r["status"] == "rejected" and r["signature"] is None
    assert client.post(f"/api/actions/{aid}/decision", json={"approve": True}, headers=ADMIN).status_code == 409


def test_unknown_action_and_device(client):
    _seed(client)
    assert _req(client, "format_disk").status_code == 422
    assert client.post("/api/actions", json={"device_id": "nope", "action": "restart_device"}, headers=OP).status_code == 404
    assert _req(client, "restart_device", hdr=VIEWER).status_code == 403


def test_execution_mitigates_incident_and_everything_audited(client, db, incident):
    r = _req(client, "isolate_device", incident_id=incident.id).json()
    client.post(f"/api/actions/{r['id']}/decision", json={"approve": True}, headers=ADMIN)
    db.refresh(incident)
    assert incident.status == "mitigated"
    events = [e.event for e in db.query(AuditLog).order_by(AuditLog.id)]
    assert events == ["action_requested", "action_approved", "action_executed"]
    assert client.get("/api/audit/verify", headers=ADMIN).json()["valid"]


def test_simulated_device_rejects_forged_commands():
    from app.simulator import Simulator
    sim = Simulator(5, seed=1)
    good = security.build_command(1, "dev-001", "isolate_device", {}, "op", "adm")
    forged = {**good, "action": "restart_device", "signature": "f" * 64}
    assert sim.handle_command(forged) is False and not sim.by_id["dev-001"]["quarantined"]
    assert sim.handle_command(good) is True and sim.by_id["dev-001"]["quarantined"]
