import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Header, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from . import agent, pipeline, security, services
from .cache import cache
from .config import settings
from .db import SessionLocal, get_db, init_db
from .models import Action, AuditLog, Device, Incident, Telemetry
from .mqtt_client import Ingestor

log = logging.getLogger("sentineledge")


class WSManager:
    def __init__(self):
        self.clients: set[WebSocket] = set()

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.clients.add(ws)

    def disconnect(self, ws: WebSocket):
        self.clients.discard(ws)

    async def broadcast(self, msg: dict):
        for ws in list(self.clients):
            try:
                await ws.send_json(msg)
            except Exception:
                self.clients.discard(ws)


ws_manager = WSManager()
_loop: asyncio.AbstractEventLoop | None = None


def emit(result: dict) -> None:
    """Thread-safe fan-out of a processed batch to WebSocket clients."""
    if not _loop or not ws_manager.clients:
        return
    msgs = [{"type": "batch", "count": result["processed"], "flagged": result["flagged"], "devices": result["states"]}]
    msgs += [{"type": "incident", **i} for i in result["incidents"]]
    for m in msgs:
        asyncio.run_coroutine_threadsafe(ws_manager.broadcast(m), _loop)


def ingest_events(events: list) -> dict:
    with SessionLocal() as db:
        res = pipeline.process_batch(db, events)
    emit(res)
    return res


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _loop
    _loop = asyncio.get_running_loop()
    init_db()
    await asyncio.to_thread(pipeline.get_detector)
    ing = None
    if settings.mqtt_host:
        ing = Ingestor(ingest_events)
        ing.start()
    yield
    if ing:
        ing.close()


app = FastAPI(title="SentinelEdge AI", version="1.0.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origins, allow_methods=["*"], allow_headers=["*"])


@app.exception_handler(security.AuthError)
async def _auth_err(_, e: security.AuthError):
    from fastapi.responses import JSONResponse
    return JSONResponse({"detail": str(e)}, status_code=e.status)


@app.exception_handler(services.ServiceError)
async def _svc_err(_, e: services.ServiceError):
    from fastapi.responses import JSONResponse
    return JSONResponse({"detail": str(e)}, status_code=e.status)


def auth(perm: str):
    def dep(x_api_key: str = Header(default=""), db: Session = Depends(get_db)) -> security.Principal:
        return security.authorize(db, x_api_key, perm)
    return dep


class TelemetryIn(BaseModel):
    device_id: str = Field(max_length=32)
    type: str
    temperature: float; cpu: float; memory: float; msg_rate: float
    rssi: float; battery: float; bytes_out: float; failed_auth: float = 0
    ts: str | None = None; src_ip: str | None = None; label: str | None = None
    site: str = "hq"; firmware: str = "1.0.0"


class ActionIn(BaseModel):
    device_id: str
    action: str
    params: dict = {}
    incident_id: int | None = None


class DecisionIn(BaseModel):
    approve: bool
    note: str = ""


@app.get("/health")
def health():
    return {"status": "ok", "threshold": pipeline.threshold()}


@app.post("/api/telemetry", status_code=202)
def ingest(body: TelemetryIn | list[TelemetryIn], _=Depends(auth("ingest"))):
    items = body if isinstance(body, list) else [body]
    if len(items) > 1000:
        raise HTTPException(413, "max 1000 events per request")
    res = ingest_events([i.model_dump() for i in items])
    return {k: res[k] for k in ("processed", "rejected", "flagged", "incidents")}


@app.get("/api/fleet")
def fleet(_=Depends(auth("read")), db: Session = Depends(get_db)):
    live = cache.fleet()
    devs = [services.serialize_device(d) for d in services.list_devices(db)]
    for d in devs:  # overlay hot state from cache
        if d["id"] in live:
            d["risk"] = live[d["id"]]["risk"]
    return {"devices": devs, "count": len(devs)}


@app.get("/api/devices/{device_id}/telemetry")
def device_telemetry(device_id: str, limit: int = 60, _=Depends(auth("read")), db: Session = Depends(get_db)):
    rows = db.scalars(select(Telemetry).where(Telemetry.device_id == device_id)
                      .order_by(Telemetry.id.desc()).limit(min(limit, 500)))
    return [{"ts": r.ts.isoformat(), "temperature": r.temperature, "cpu": r.cpu, "memory": r.memory,
             "msg_rate": r.msg_rate, "rssi": r.rssi, "risk": r.risk, "flagged": r.flagged} for r in rows]


@app.get("/api/incidents")
def incidents(status: str | None = None, limit: int = 50, _=Depends(auth("read")), db: Session = Depends(get_db)):
    q = select(Incident).order_by(Incident.id.desc()).limit(min(limit, 200))
    if status:
        q = q.where(Incident.status == status)
    return [services.serialize_incident(i, full=True) for i in db.scalars(q)]


@app.post("/api/incidents/{incident_id}/investigate")
def investigate(incident_id: int, who=Depends(auth("investigate")), db: Session = Depends(get_db)):
    return agent.investigate(db, incident_id, who)


@app.get("/api/actions")
def actions(status: str | None = None, _=Depends(auth("read")), db: Session = Depends(get_db)):
    q = select(Action).order_by(Action.id.desc()).limit(100)
    if status:
        q = q.where(Action.status == status)
    return [services.serialize_action(a) for a in db.scalars(q)]


@app.post("/api/actions", status_code=201)
def create_action(body: ActionIn, who=Depends(auth("request_action")), db: Session = Depends(get_db)):
    return services.serialize_action(services.request_action(db, who, body.device_id, body.action, body.params, body.incident_id))


@app.post("/api/actions/{action_id}/decision")
def decide(action_id: int, body: DecisionIn, who=Depends(auth("approve_action")), db: Session = Depends(get_db)):
    return services.serialize_action(services.decide_action(db, who, action_id, body.approve, body.note))


@app.get("/api/audit")
def audit_log(limit: int = 100, _=Depends(auth("audit")), db: Session = Depends(get_db)):
    rows = db.scalars(select(AuditLog).order_by(AuditLog.id.desc()).limit(min(limit, 500)))
    return [{"id": r.id, "ts": r.ts, "actor": r.actor, "role": r.role, "event": r.event,
             "payload": r.payload, "hash": r.hash[:16]} for r in rows]


@app.get("/api/audit/verify")
def audit_verify(_=Depends(auth("audit")), db: Session = Depends(get_db)):
    return security.verify_chain(db)


@app.get("/api/metrics")
def metrics(_=Depends(auth("read")), db: Session = Depends(get_db)):
    pos = Telemetry.label.isnot(None) & (Telemetry.label != "normal")
    row = db.execute(select(
        func.count(Telemetry.id),
        func.coalesce(func.sum(case((Telemetry.flagged & pos, 1), else_=0)), 0),
        func.coalesce(func.sum(case((Telemetry.flagged & ~pos & Telemetry.label.isnot(None), 1), else_=0)), 0),
        func.coalesce(func.sum(case((~Telemetry.flagged & pos, 1), else_=0)), 0),
    )).one()
    total, tp, fp, fn = row
    prec, rec = tp / max(tp + fp, 1), tp / max(tp + fn, 1)
    return {"events_total": total, "devices": db.scalar(select(func.count(Device.id))),
            "open_incidents": db.scalar(select(func.count(Incident.id)).where(Incident.status.in_(["open", "investigating"]))),
            "pending_approvals": db.scalar(select(func.count(Action.id)).where(Action.status == "pending_approval")),
            "live_detection": {"precision": round(prec, 4), "recall": round(rec, 4),
                               "f1": round(2 * prec * rec / max(prec + rec, 1e-9), 4), "tp": tp, "fp": fp, "fn": fn}}


@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket, key: str = ""):
    try:
        who = security.identify(key)
        if "read" not in security.PERMS[who.role]:
            raise security.AuthError("forbidden")
    except security.AuthError:
        await ws.close(code=4401)
        return
    await ws_manager.connect(ws)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(ws)
