# SentinelEdge AI — Agentic IoT Security & Operations Platform

Next.js · TypeScript · FastAPI · MQTT · PostgreSQL · Redis · MCP · scikit-learn · Docker

```
simulator (100 devices) --MQTT--> ingest worker (batched) --> anomaly + risk scoring --> PostgreSQL
                                        |                          |--> incidents (persistence-filtered)
                                        +--> Redis (fleet cache)   +--> WebSocket --> Next.js dashboard
investigation agent (telemetry + auth + history + RAG) --> evidence-backed report + remediation plan
MCP server / REST --> RBAC --> approval gate (critical) --> HMAC-signed command --> device --> audit log
```

## Run it

**Everything (Docker):** `cp .env.example .env && docker compose up --build` → dashboard http://localhost:3000, API docs http://localhost:8000/docs

**In VS Code (no Docker):**
```bash
cd backend && python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements-dev.txt
uvicorn app.main:app --reload                       # terminal 1 (SQLite by default)
python -m app.simulator --http http://localhost:8000 --interval 0.5   # terminal 2
cd ../frontend && npm install && npm run dev        # terminal 3 -> http://localhost:3000
```
Run/Debug configs and tasks are in `.vscode/`. Dev API keys: `viewer-key`, `operator-key`, `admin-key`, `device-key` (change via `SE_API_KEYS`).

**Demo flow:** wait for a red device → *Investigate* → click a critical remediation (e.g. isolate) as operator → switch to **admin** → *Approve* → simulated device verifies the HMAC signature and executes → `GET /api/audit/verify`.

**MCP:** `SE_MCP_API_KEY=operator-key python -m app.mcp_server` (stdio; `.vscode/mcp.json` included). Tools: `list_devices`, `get_device_telemetry`, `investigate_incident`, `request_remediation`, `decide_remediation`, `verify_audit_log`.

## Measured results (not placeholders)

| Metric | Result | How measured |
|---|---|---|
| Detection (combined risk) | **F1 0.872, recall 83.2%, precision 91.7%**, FPR 3.0% | `python -m app.ml.evaluate` — 28,000 held-out events (8,000 anomalous) across **8 scenarios**, separate seeds from train/validation |
| Isolation Forest alone | best F1 0.764 | same test set, threshold tuned for IF-only |
| Per-scenario recall | 58% (signal interference) → 100% (credential attack, message flood) | `docs/metrics.json` |
| Ingest throughput | **~800 events/s** on one process + SQLite (~69M/day equivalent) | `python scripts/benchmark.py 30000` |
| Tests | **72 API/unit/integration tests, 93% coverage** | `pytest --cov=app` (CI enforces ≥85%) |
| Live end-to-end | 100 devices over real MQTT broker, 20k+ events, incident → agent → approval → signed command accepted → audit chain valid | manual run with mosquitto |

Resume wording that is true to these numbers:
- "...simulating 100 devices and ingesting 800+ telemetry events/s (benchmarked 30K+ events; ~20K live over MQTT)..." — **do not claim "M+ events" unless you actually run the simulator long enough** (at 100 events/s ≈ 1M events per ~2.8 h; `--interval 0.1` gives 1,000/s).
- "...Isolation Forest + multi-signal risk scoring, F1 0.87 / 83% recall across 8 simulated anomaly scenarios."
- "...72 automated tests, 93% coverage."

**Caveat to be upfront about in interviews:** the data is *synthetic* (generated in `app/ml/scenarios.py`), so these numbers show the pipeline works, not real-world accuracy.

## Design notes
- **Per-type normalisation** (z-scores per device type) lets one Isolation Forest serve sensors, gateways, cameras and actuators; rule signals add interpretable evidence and lift F1 vs IF alone.
- **Incident persistence filter**: an incident opens only after ≥3 of the last 5 readings are flagged (or one strong reading) — found via the live run, where per-event false positives were flooding the queue.
- **Agent** is deterministic and evidence-cited (telemetry vs baseline, auth bursts, device history, fleet-wide correlation, RAG over `backend/knowledge/*.md`). With `ANTHROPIC_API_KEY` set it also writes a narrative from that same evidence bundle.
- **Safety**: RBAC (viewer/operator/admin/device), critical actions need a *different* admin (two-person rule), commands are HMAC-SHA256 signed and re-verified device-side, audit log is hash-chained and ORM-immutable (`/api/audit/verify` detects tampering, incl. raw-SQL edits).

## Known limits / next steps
Auth is static API keys (swap for OIDC/JWT); audit chain is single-writer (use a DB advisory lock for multi-writer); telemetry retention/partitioning not implemented; MQTT broker is anonymous in the demo compose (add TLS + per-device certs); Docker images were not built in my sandbox (no Docker there) — CI's `docker compose build` job covers it.
