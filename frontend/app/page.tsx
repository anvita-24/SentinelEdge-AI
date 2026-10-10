"use client";
import { useCallback, useEffect, useRef, useState } from "react";
import { API, WS, ActionRow, Device, Incident, Metrics, Report, call } from "../lib/api";

const KEYS: Record<string, string> = { viewer: "viewer-key", operator: "operator-key", admin: "admin-key" };
const heat = (r: number) => `hsl(${Math.max(0, 150 - r * 1.5)}, 60%, ${r > 30 ? 55 : 42}%)`;

export default function Dashboard() {
  const [role, setRole] = useState("operator");
  const key = KEYS[role];
  const [devices, setDevices] = useState<Record<string, Device>>({});
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [actions, setActions] = useState<ActionRow[]>([]);
  const [metrics, setMetrics] = useState<Metrics | null>(null);
  const [sel, setSel] = useState<string | null>(null);
  const [live, setLive] = useState(false);
  const [msg, setMsg] = useState("");
  const [busy, setBusy] = useState<number | null>(null);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const refresh = useCallback(async () => {
    try {
      const [f, i, a, m] = await Promise.all([
        call<{ devices: Device[] }>("/api/fleet", key), call<Incident[]>("/api/incidents?limit=30", key),
        call<ActionRow[]>("/api/actions", key), call<Metrics>("/api/metrics", key)]);
      setDevices(Object.fromEntries(f.devices.map((d) => [d.id, d])));
      setIncidents(i); setActions(a); setMetrics(m); setMsg("");
    } catch (e) { setMsg((e as Error).message); }
  }, [key]);

  useEffect(() => { refresh(); }, [refresh]);
  useEffect(() => {
    const ws = new WebSocket(`${WS}/ws?key=${key}`);
    ws.onopen = () => setLive(true); ws.onclose = () => setLive(false);
    ws.onmessage = (e) => {
      const m = JSON.parse(e.data);
      if (m.type === "batch") setDevices((prev) => { const n = { ...prev }; for (const [id, s] of Object.entries<any>(m.devices)) n[id] = { ...(n[id] ?? { firmware: "", last_seen: null }), ...s }; return n; });
      if (m.type === "incident" && !timer.current) timer.current = setTimeout(() => { timer.current = null; refresh(); }, 1500);
    };
    return () => ws.close();
  }, [key, refresh]);

  const act = async (fn: () => Promise<unknown>) => { try { await fn(); await refresh(); } catch (e) { setMsg((e as Error).message); } };
  const investigate = (id: number) => { setBusy(id); act(() => call(`/api/incidents/${id}/investigate`, key, { method: "POST" })).finally(() => setBusy(null)); };
  const request = (device_id: string, action: string, incident_id: number) =>
    act(() => call("/api/actions", key, { method: "POST", body: JSON.stringify({ device_id, action, incident_id }) }));
  const decide = (id: number, approve: boolean) =>
    act(() => call(`/api/actions/${id}/decision`, key, { method: "POST", body: JSON.stringify({ approve, note: approve ? "approved in console" : "rejected in console" }) }));

  const list = Object.values(devices).sort((a, b) => a.id.localeCompare(b.id));
  const shown = incidents.filter((i) => !sel || i.device_id === sel);
  const pending = actions.filter((a) => a.status === "pending_approval");

  return (<>
    <header>
      <h1>SentinelEdge AI <span className="mute" style={{ fontWeight: 400, fontSize: 13 }}>{live ? "live" : "reconnecting…"} · {API}</span></h1>
      <div className="stats">
        <div><b>{metrics?.devices ?? "–"}</b><span>devices</span></div>
        <div><b>{metrics?.events_total.toLocaleString() ?? "–"}</b><span>events</span></div>
        <div><b>{metrics?.open_incidents ?? "–"}</b><span>open incidents</span></div>
        <div><b>{metrics ? `${(metrics.live_detection.recall * 100).toFixed(0)}%` : "–"}</b><span>live recall</span></div>
        <div><b>{metrics ? metrics.live_detection.f1.toFixed(2) : "–"}</b><span>live F1</span></div>
      </div>
      <label>Signed in as <select value={role} onChange={(e) => setRole(e.target.value)}>{Object.keys(KEYS).map((r) => <option key={r}>{r}</option>)}</select></label>
    </header>
    {msg && <p className="err" style={{ padding: "0 24px" }} role="alert">{msg}</p>}
    <main>
      <div style={{ display: "grid", gap: 20, alignContent: "start" }}>
        <section>
          <h2>Fleet risk {sel && <button onClick={() => setSel(null)}>clear filter ({sel})</button>}</h2>
          {list.length === 0 && <p className="mute">No devices yet. Start the simulator: <code>python -m app.simulator --mqtt localhost</code></p>}
          <div className="grid">{list.map((d) => (
            <div key={d.id} className="dev" tabIndex={0} role="button" data-sel={sel === d.id ? 1 : 0} data-q={d.status === "quarantined" ? 1 : 0}
              style={{ background: heat(d.risk) }} title={`${d.id} · ${d.type} · risk ${d.risk.toFixed(0)} · ${d.status}`}
              onClick={() => setSel(d.id)} onKeyDown={(e) => e.key === "Enter" && setSel(d.id)}>{d.id.slice(4)}</div>))}</div>
          <p className="mute" style={{ fontSize: 12 }}>Green is healthy, red is high risk, striped devices are quarantined. Click a device to filter incidents.</p>
        </section>
        <section>
          <h2>Incidents</h2>
          {shown.length === 0 && <p className="mute">No incidents{sel ? ` for ${sel}` : ""}.</p>}
          {shown.map((i) => (<div className="row" key={i.id}>
            <span className={`pill ${i.severity}`}>{i.severity}</span><b>{i.title}</b> <span className="mute">· risk {i.risk.toFixed(0)} · {i.status}</span>
            <div style={{ marginTop: 6 }}>
              <button onClick={() => investigate(i.id)} disabled={busy === i.id}>{i.report ? "Re-investigate" : "Investigate"}</button>
            </div>
            {i.report && <ReportView r={i.report} deviceId={i.device_id} incidentId={i.id} request={request} role={role} />}
          </div>))}
        </section>
      </div>
      <section style={{ alignSelf: "start" }}>
        <h2>Approval queue ({pending.length})</h2>
        {pending.length === 0 && <p className="mute">No critical actions waiting.</p>}
        {pending.map((a) => (<div className="row" key={a.id}>
          <b>{a.action}</b> on {a.device_id}<div className="mute">requested by {a.requested_by}</div>
          <button className="primary" disabled={role !== "admin"} onClick={() => decide(a.id, true)} title={role !== "admin" ? "Admin role required" : ""}>Approve</button>{" "}
          <button className="danger" disabled={role !== "admin"} onClick={() => decide(a.id, false)}>Reject</button>
        </div>))}
        <h2 style={{ marginTop: 20 }}>Recent actions</h2>
        {actions.filter((a) => a.status !== "pending_approval").slice(0, 8).map((a) => (<div className="row mute" key={a.id}>
          {a.action} → {a.device_id} · {a.status}{a.signature && <span title={a.signature}> · signed {a.signature.slice(0, 8)}</span>}</div>))}
      </section>
    </main></>);
}

function ReportView({ r, deviceId, incidentId, request, role }: { r: Report; deviceId: string; incidentId: number; request: (d: string, a: string, i: number) => void; role: string }) {
  const can = role !== "viewer";
  return (<div style={{ marginTop: 8 }}>
    <p style={{ margin: "4px 0" }}>{r.summary} <span className="mute">({r.classification}, confidence {(r.confidence * 100).toFixed(0)}%)</span></p>
    {r.narrative && <p className="mute">{r.narrative}</p>}
    <ul>{r.evidence.map((e, k) => <li key={k}><span className="mute">{e.type}{e.ref ? ` · ${e.ref}` : ""}:</span> {e.detail}</li>)}</ul>
    <div>{r.remediation_plan.map((p) => (
      <button key={p.action} disabled={!can} onClick={() => request(deviceId, p.action, incidentId)} title={p.rationale} style={{ marginRight: 6 }}>
        {p.action.replace(/_/g, " ")}{p.critical ? " (needs admin)" : ""}</button>))}</div>
  </div>);
}
