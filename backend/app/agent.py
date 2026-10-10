"""AI investigation agent: gathers evidence (telemetry, auth, history, RAG) -> explanation + plan.

Deterministic evidence-backed report by default; if ANTHROPIC_API_KEY is set the narrative
is additionally written by Claude from the *same evidence bundle* (it never invents evidence).
"""
import logging
from datetime import timedelta

import httpx
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import rag, security
from .config import settings
from .models import AuthEvent, Device, Incident, Telemetry, now
from .services import ACTIONS, ServiceError

log = logging.getLogger("sentineledge.agent")
PLAYBOOK = {
    "credential_attack": ["rotate_credentials", "isolate_device"],
    "data_exfiltration": ["isolate_device", "rotate_credentials"],
    "message_flood": ["throttle_telemetry", "isolate_device"],
    "cpu_hijack": ["isolate_device", "firmware_rollback"],
    "overheating": ["throttle_telemetry", "restart_device"],
    "signal_interference": ["restart_device"],
    "battery_drain": ["throttle_telemetry"],
    "memory_leak": ["restart_device", "firmware_rollback"],
    "unknown_anomaly": ["throttle_telemetry"],
}
SECURITY_CATS = {"credential_attack", "data_exfiltration", "message_flood", "cpu_hijack"}


def investigate(db: Session, incident_id: int, who: security.Principal) -> dict:
    inc = db.get(Incident, incident_id)
    if not inc:
        raise ServiceError("incident not found", 404)
    dev = db.get(Device, inc.device_id)
    ev: list[dict] = []

    # 1. device telemetry vs. its own healthy baseline
    recent = list(db.scalars(select(Telemetry).where(Telemetry.device_id == dev.id)
                             .order_by(Telemetry.id.desc()).limit(30)))
    healthy = list(db.scalars(select(Telemetry).where(Telemetry.device_id == dev.id, Telemetry.flagged.is_(False))
                              .order_by(Telemetry.id.desc()).limit(200)))
    for s in inc.signals[:4]:
        f = s["feature"]
        peak = max((getattr(t, f) for t in recent), default=None, key=lambda v: abs(v - _mean(healthy, f)) if healthy else v)
        ev.append({"type": "telemetry", "ref": f"telemetry:{recent[0].id}" if recent else None,
                   "detail": f"{f} peaked at {peak:.1f} vs healthy baseline {_mean(healthy, f):.1f} (z={s['z']}, severity {s['severity']})"
                   if healthy else f"{f} z-score {s['z']} (severity {s['severity']}); no healthy baseline yet"})
    n_flag = sum(t.flagged for t in recent)
    ev.append({"type": "telemetry", "ref": None, "detail": f"{n_flag} of the last {len(recent)} readings were flagged"})

    # 2. authentication events
    since = now() - timedelta(minutes=30)
    fails = list(db.scalars(select(AuthEvent).where(AuthEvent.device_id == dev.id, AuthEvent.kind == "login_fail",
                                                    AuthEvent.ts > since)))
    fails = [a for a in fails if a.count >= 3]  # bursts only; ignore background typo noise
    total_fail = sum(a.count for a in fails)
    ips = sorted({a.source_ip for a in fails if a.source_ip})
    if total_fail:
        ev.append({"type": "auth", "ref": f"auth_events:{fails[-1].id}",
                   "detail": f"{total_fail} failed logins in {len(fails)} burst(s) within 30 min" + (f" from {', '.join(ips[:5])}" if ips else "")})
    rot = db.scalars(select(AuthEvent).where(AuthEvent.device_id == dev.id, AuthEvent.kind == "cert_rotate")).first()
    if rot:
        ev.append({"type": "auth", "ref": f"auth_events:{rot.id}", "detail": "credentials were rotated previously"})

    # 3. history: this device and fleet-wide correlation
    prior = list(db.scalars(select(Incident).where(Incident.device_id == dev.id, Incident.id != inc.id)
                            .order_by(Incident.id.desc()).limit(10)))
    same_cat = [p for p in prior if p.category == inc.category]
    if prior:
        ev.append({"type": "history", "ref": f"incident:{prior[0].id}",
                   "detail": f"{len(prior)} earlier incidents on this device ({len(same_cat)} of the same category)"})
    peers = db.scalar(select(func.count(func.distinct(Incident.device_id))).where(
        Incident.category == inc.category, Incident.ts > now() - timedelta(hours=24), Incident.device_id != dev.id)) or 0
    if peers:
        ev.append({"type": "history", "ref": None, "detail": f"{peers} other device(s) raised '{inc.category}' in the last 24h"})

    # 4. RAG context
    ctx = rag.retrieve(f"{inc.category} " + " ".join(s["feature"] for s in inc.signals), k=3)
    for c in ctx:
        ev.append({"type": "runbook", "ref": c["id"], "detail": c["text"][:160] + ("…" if len(c["text"]) > 160 else "")})

    # reasoning
    conf = min(0.98, 0.35 + 0.4 * (inc.risk / 100) + 0.08 * len(inc.signals) + (0.1 if total_fail and inc.category == "credential_attack" else 0)
               + (0.05 if same_cat else 0))
    is_sec = inc.category in SECURITY_CATS
    fleet = peers >= 2
    summary = (f"{dev.id} ({dev.type}, {dev.site}) shows a pattern consistent with "
               f"{inc.category.replace('_', ' ')}; this looks like a "
               f"{'security event' if is_sec else 'operational fault'}. "
               + (f"{peers} other devices show the same pattern, so treat it as fleet-wide and escalate. " if fleet else "")
               + ("It has happened on this device before. " if same_cat else ""))
    steps = list(PLAYBOOK.get(inc.category, PLAYBOOK["unknown_anomaly"]))
    if len(same_cat) >= 2 and "isolate_device" not in steps:
        steps.append("isolate_device")  # recurrence escalation
    plan = [{"action": a, "critical": ACTIONS[a],
             "requires": "admin approval (two-person rule)" if ACTIONS[a] else "operator",
             "rationale": _why(a, inc.category)} for a in steps]
    report = {"incident_id": inc.id, "device_id": dev.id, "category": inc.category,
              "classification": "security" if is_sec else "operational", "confidence": round(conf, 2),
              "fleet_wide": fleet, "summary": summary.strip(), "evidence": ev, "remediation_plan": plan,
              "narrative_source": "deterministic"}
    if settings.anthropic_key:
        text = _llm_narrative(report)
        if text:
            report["narrative"], report["narrative_source"] = text, f"llm:{settings.anthropic_model}"
    inc.report = report
    if inc.status == "open":
        inc.status = "investigating"
    security.audit(db, who.actor, who.role, "incident_investigated",
                   {"incident_id": inc.id, "category": inc.category, "confidence": report["confidence"],
                    "evidence_items": len(ev)})
    db.commit()
    return report


def _mean(rows, f):
    return sum(getattr(r, f) for r in rows) / len(rows) if rows else 0.0


def _why(action: str, cat: str) -> str:
    return {"rotate_credentials": "invalidate any credentials that may have been guessed or leaked",
            "isolate_device": "contain the device while the cause is confirmed",
            "throttle_telemetry": "reduce load/traffic with no loss of control",
            "restart_device": "recover from a transient fault",
            "firmware_rollback": "return to the last known-good firmware"}[action] + f" ({cat.replace('_', ' ')})"


def _llm_narrative(report: dict) -> str | None:  # pragma: no cover - needs network/key
    try:
        r = httpx.post("https://api.anthropic.com/v1/messages", timeout=30,
                       headers={"x-api-key": settings.anthropic_key, "anthropic-version": "2023-06-01"},
                       json={"model": settings.anthropic_model, "max_tokens": 500,
                             "system": "You are an IoT SOC analyst. Using ONLY the evidence JSON given, write a concise incident "
                                       "explanation and remediation rationale. Cite evidence refs. Do not invent facts.",
                             "messages": [{"role": "user", "content": str(report)}]})
        r.raise_for_status()
        return r.json()["content"][0]["text"]
    except Exception as e:
        log.warning("LLM narrative failed: %s", e)
        return None
