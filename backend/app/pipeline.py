"""Telemetry ingestion: persist -> score -> flag -> open incidents."""
import threading
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from .cache import cache
from .config import settings
from .ml.detector import Detector, train_default
from .ml.scenarios import FEATURES, TYPES
from .models import AuthEvent, Device, Incident, Telemetry, now

_det: Detector | None = None
_lock = threading.Lock()
SEV = [(75, "critical"), (50, "high"), (30, "medium"), (0, "low")]
INCIDENT_COOLDOWN = timedelta(minutes=10)
PERSIST_MIN, STRONG_RISK = 3, 60.0


def get_detector() -> Detector:
    global _det
    with _lock:
        if _det is None:
            try:
                _det = Detector.load(settings.model_path)
            except Exception:
                _det = train_default(settings.train_rows)
                try:
                    _det.save(settings.model_path)
                except OSError:  # pragma: no cover
                    pass
    return _det


def threshold() -> float:
    return settings.risk_threshold or get_detector().threshold


def severity(risk: float) -> str:
    return next(name for lim, name in SEV if risk >= lim)


def process_batch(db: Session, events: list[dict]) -> dict:
    """events: [{device_id, type, <features>, ts?, src_ip?, label?, site?, firmware?}]"""
    det, th = get_detector(), threshold()
    valid = [e for e in events if e.get("type") in TYPES and all(f in e for f in FEATURES)]
    scored = det.assess_batch([(e["type"], e) for e in valid])
    states, new_incidents, flagged_n = {}, [], 0
    for e, a in zip(valid, scored):
        dev = db.get(Device, e["device_id"])
        if dev is None:
            dev = Device(id=e["device_id"], type=e["type"], site=e.get("site", "hq"),
                         firmware=e.get("firmware", "1.0.0"), risk=0.0)
            db.add(dev)
        ts = _parse_ts(e.get("ts"))
        flagged = a["risk"] >= th
        flagged_n += flagged
        dev.last_seen = ts
        dev.risk = round(max(a["risk"], 0.7 * (dev.risk or 0) + 0.3 * a["risk"]), 2)
        db.add(Telemetry(device_id=dev.id, ts=ts, anomaly_score=a["anomaly_score"], risk=a["risk"],
                         flagged=flagged, label=e.get("label"), **{f: float(e[f]) for f in FEATURES}))
        if e["failed_auth"] > 0:
            db.add(AuthEvent(device_id=dev.id, ts=ts, kind="login_fail", count=int(e["failed_auth"]),
                             source_ip=e.get("src_ip")))
        if flagged and dev.status != "quarantined":
            inc = _maybe_open_incident(db, dev, a, ts)
            if inc:
                new_incidents.append(inc)
        states[dev.id] = {"id": dev.id, "type": dev.type, "site": dev.site, "status": dev.status,
                          "risk": dev.risk, "flagged": flagged,
                          "last_seen": ts.isoformat()}
    db.commit()
    cache.set_devices(states)
    out = {"processed": len(valid), "rejected": len(events) - len(valid), "flagged": flagged_n,
           "states": states,
           "incidents": [{"id": i.id, "device_id": i.device_id, "severity": i.severity,
                          "category": i.category, "title": i.title, "risk": i.risk} for i in new_incidents]}
    cache.publish("events", {"processed": out["processed"], "incidents": out["incidents"]})
    return out


def _parse_ts(v) -> datetime:
    if not v:
        return now()
    try:
        d = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
        return d.replace(tzinfo=None)
    except ValueError:
        return now()


def _maybe_open_incident(db: Session, dev: Device, a: dict, ts: datetime) -> Incident | None:
    # de-dupe: one open incident per device inside the cooldown window
    recent = db.scalars(
        select(Incident).where(Incident.device_id == dev.id, Incident.status.in_(["open", "investigating"]),
                               Incident.ts > now() - INCIDENT_COOLDOWN).limit(1)).first()
    if recent:
        if a["risk"] > recent.risk:
            recent.risk, recent.severity = a["risk"], severity(a["risk"])
        return None
    # persistence filter: suppress one-off blips (false positives) - need >=3 of last 5 flagged or a strong reading
    last5 = db.scalars(select(Telemetry.flagged).where(Telemetry.device_id == dev.id)
                       .order_by(Telemetry.id.desc()).limit(5)).all()
    if sum(last5) < PERSIST_MIN and a["risk"] < STRONG_RISK:
        return None
    cat = a["category"] or "unknown_anomaly"
    inc = Incident(device_id=dev.id, ts=ts, severity=severity(a["risk"]), category=cat, risk=a["risk"],
                   signals=a["signals"], title=f"{cat.replace('_', ' ').title()} on {dev.id} ({dev.type})")
    db.add(inc)
    db.flush()
    return inc
