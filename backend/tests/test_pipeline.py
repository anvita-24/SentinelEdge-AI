from app import pipeline
from app.models import AuthEvent, Device, Incident, Telemetry
from tests.conftest import make_event


def test_ingest_persists_device_and_telemetry(db):
    res = pipeline.process_batch(db, [make_event("dev-001", seed=1), make_event("dev-002", "sensor", seed=2)])
    assert res["processed"] == 2 and res["rejected"] == 0
    assert db.query(Device).count() == 2 and db.query(Telemetry).count() == 2


def test_invalid_events_rejected(db):
    bad = {"device_id": "x", "type": "toaster", "temperature": 1}
    res = pipeline.process_batch(db, [bad, make_event(seed=1)])
    assert res["processed"] == 1 and res["rejected"] == 1


def test_anomaly_opens_one_incident_with_dedupe(db):
    evs = [make_event(scenario="data_exfiltration", seed=s) for s in range(5)]
    res = pipeline.process_batch(db, evs)
    assert len(res["incidents"]) == 1
    inc = db.query(Incident).one()
    assert inc.category == "data_exfiltration" and inc.severity in {"medium", "high", "critical"}
    assert inc.signals and db.query(Telemetry).filter_by(flagged=True).count() == 5


def test_failed_auth_creates_auth_events(db):
    pipeline.process_batch(db, [make_event(scenario="credential_attack", seed=3, src_ip="10.1.1.1")])
    a = db.query(AuthEvent).one()
    assert a.kind == "login_fail" and a.count >= 3 and a.source_ip == "10.1.1.1"


def test_quarantined_device_does_not_open_new_incident(db):
    pipeline.process_batch(db, [make_event(seed=1)])
    d = db.get(Device, "dev-001"); d.status = "quarantined"; db.commit()
    res = pipeline.process_batch(db, [make_event(scenario="cpu_hijack", seed=4)])
    assert res["incidents"] == []


def test_device_risk_decays_toward_normal(db):
    pipeline.process_batch(db, [make_event(scenario="overheating", seed=5)])
    hi = db.get(Device, "dev-001").risk
    for s in range(10, 16):
        pipeline.process_batch(db, [make_event(seed=s)])
    assert db.get(Device, "dev-001").risk < hi


def test_batch_throughput_reasonable(db):
    import time
    evs = [make_event(f"dev-{i % 100:03d}", seed=i) for i in range(500)]
    t = time.time(); pipeline.process_batch(db, evs)
    assert 500 / (time.time() - t) > 100  # events/s floor on slow CI


def test_single_weak_blip_does_not_open_incident(db):
    """Persistence filter: one mild flagged reading is noise, a sustained one is an incident."""
    weak = make_event(scenario="overheating", seed=5)
    pipeline.process_batch(db, [weak])
    assert db.query(Incident).count() == 0 and db.query(Telemetry).filter_by(flagged=True).count() == 1
    pipeline.process_batch(db, [make_event(scenario="overheating", seed=6 + i) for i in range(3)])
    assert db.query(Incident).count() == 1


def test_incident_severity_escalates_with_risk(db):
    pipeline.process_batch(db, [make_event(scenario="overheating", seed=i) for i in range(4)])
    inc = db.query(Incident).one()
    inc.severity, inc.risk = "low", 1.0; db.commit()
    pipeline.process_batch(db, [make_event(scenario="data_exfiltration", seed=1)])
    db.refresh(inc)
    assert inc.severity in {"high", "critical"}
