import pytest

from app import pipeline, rag
from app.models import Incident
from tests.conftest import ADMIN, OP, VIEWER, make_event


def test_rag_retrieves_relevant_runbook():
    top = rag.retrieve("brute force failed authentication credential", k=1)[0]
    assert top["section"] == "credential_attack"
    assert rag.retrieve("outbound bytes exfiltration data theft", k=1)[0]["section"] == "data_exfiltration"


def test_investigation_report_is_evidence_backed(client, incident):
    r = client.post(f"/api/incidents/{incident.id}/investigate", headers=OP).json()
    assert r["category"] == "credential_attack" and r["classification"] == "security"
    types = {e["type"] for e in r["evidence"]}
    assert {"telemetry", "auth", "runbook"} <= types
    assert any("failed logins" in e["detail"] and "burst" in e["detail"] for e in r["evidence"])
    assert any(e["ref"] and e["ref"].startswith("runbook") or e["ref"] and "runbooks#" in e["ref"] for e in r["evidence"])
    assert 0.5 < r["confidence"] <= 0.98 and r["narrative_source"] == "deterministic"


def test_plan_marks_critical_actions_requiring_admin(client, incident):
    plan = client.post(f"/api/incidents/{incident.id}/investigate", headers=OP).json()["remediation_plan"]
    assert plan[0]["action"] == "rotate_credentials" and plan[0]["critical"] is True
    assert "admin" in plan[0]["requires"]


def test_viewer_cannot_investigate_and_missing_incident_404(client, incident):
    assert client.post(f"/api/incidents/{incident.id}/investigate", headers=VIEWER).status_code == 403
    assert client.post("/api/incidents/9999/investigate", headers=OP).status_code == 404


def test_investigation_persists_updates_status_and_audits(client, db, incident):
    client.post(f"/api/incidents/{incident.id}/investigate", headers=OP)
    db.refresh(incident)
    assert incident.report and incident.status == "investigating"
    assert client.get("/api/audit", headers=ADMIN).json()[0]["event"] == "incident_investigated"


def test_fleet_wide_correlation_detected(client, db):
    for i in range(4):
        pipeline.process_batch(db, [make_event(f"dev-{i:03d}", scenario="data_exfiltration", seed=i)])
    first = db.query(Incident).order_by(Incident.id).first()
    r = client.post(f"/api/incidents/{first.id}/investigate", headers=OP).json()
    assert r["fleet_wide"] is True and "fleet-wide" in r["summary"]


def test_recurrence_escalates_to_isolation(client, db):
    from datetime import timedelta
    from app.models import now
    for s in range(3):
        pipeline.process_batch(db, [make_event(scenario="overheating", seed=s * 10 + i) for i in range(4)])
        inc = db.query(Incident).order_by(Incident.id.desc()).first()
        inc.ts = now() - timedelta(hours=2 + s); inc.status = "mitigated"; db.commit()
    pipeline.process_batch(db, [make_event(scenario="overheating", seed=90 + i) for i in range(4)])
    last = db.query(Incident).order_by(Incident.id.desc()).first()
    plan = client.post(f"/api/incidents/{last.id}/investigate", headers=OP).json()["remediation_plan"]
    assert "isolate_device" in [p["action"] for p in plan]


def test_background_login_noise_is_not_reported_as_evidence(client, db):
    from app.models import AuthEvent
    pipeline.process_batch(db, [make_event(scenario="overheating", seed=i, failed_auth=1.0) for i in range(4)])
    inc = db.query(Incident).first()
    assert db.query(AuthEvent).count() == 4
    r = client.post(f"/api/incidents/{inc.id}/investigate", headers=OP).json()
    assert not any(e["type"] == "auth" for e in r["evidence"])
