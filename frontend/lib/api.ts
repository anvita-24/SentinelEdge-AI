export const API = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";
export const WS = API.replace(/^http/, "ws");

export type Device = { id: string; type: string; site: string; firmware: string; status: string; risk: number; last_seen: string | null };
export type Evidence = { type: string; ref: string | null; detail: string };
export type PlanStep = { action: string; critical: boolean; requires: string; rationale: string };
export type Report = { category: string; classification: string; confidence: number; summary: string; fleet_wide: boolean;
  evidence: Evidence[]; remediation_plan: PlanStep[]; narrative?: string };
export type Incident = { id: number; device_id: string; ts: string; severity: string; category: string; title: string;
  status: string; risk: number; report: Report | null };
export type ActionRow = { id: number; device_id: string; action: string; critical: boolean; status: string;
  requested_by: string; approved_by: string | null; signature: string | null };
export type Metrics = { events_total: number; devices: number; open_incidents: number; pending_approvals: number;
  live_detection: { precision: number; recall: number; f1: number } };

export async function call<T>(path: string, key: string, init: RequestInit = {}): Promise<T> {
  const r = await fetch(`${API}${path}`, { ...init, headers: { "X-API-Key": key, "Content-Type": "application/json", ...(init.headers ?? {}) } });
  const body = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(body.detail ?? `HTTP ${r.status}`);
  return body as T;
}
