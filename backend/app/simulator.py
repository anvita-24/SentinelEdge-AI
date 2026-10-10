"""Fleet simulator: 100 devices publishing telemetry over MQTT (or HTTP), injecting anomalies,
and executing *signed* commands (rejecting anything with a bad signature).

  python -m app.simulator --mqtt localhost --interval 1.0
  python -m app.simulator --http http://localhost:8000 --interval 0.5
"""
import argparse
import json
import time
from datetime import datetime, timezone

import numpy as np

from .ml.scenarios import SCENARIOS, TYPES, apply_anomaly, normal_event
from .security import verify_command


def build_fleet(n: int = 100) -> list[dict]:
    mix = ["sensor"] * 4 + ["gateway", "camera", "actuator", "sensor", "gateway", "camera"]  # ~ 50/20/20/10
    return [{"device_id": f"dev-{i:03d}", "type": mix[i % len(mix)], "site": ["hq", "plant-a", "plant-b"][i % 3],
             "firmware": "1.2.0", "anomaly": None, "ttl": 0, "quarantined": False} for i in range(n)]


class Simulator:
    def __init__(self, n=100, p_anomaly=0.002, seed=None):
        self.rng = np.random.default_rng(seed)
        self.fleet = build_fleet(n)
        self.by_id = {d["device_id"]: d for d in self.fleet}
        self.p = p_anomaly

    def tick(self) -> list[dict]:
        out = []
        for d in self.fleet:
            if d["quarantined"]:
                continue
            if d["ttl"] <= 0 and self.rng.random() < self.p:
                d["anomaly"], d["ttl"] = str(self.rng.choice(SCENARIOS)), int(self.rng.integers(20, 60))
            ev = normal_event(d["type"], self.rng)
            label = "normal"
            if d["ttl"] > 0:
                ev, label, d["ttl"] = apply_anomaly(ev, d["anomaly"], d["type"], self.rng), d["anomaly"], d["ttl"] - 1
            out.append({"device_id": d["device_id"], "type": d["type"], "site": d["site"], "firmware": d["firmware"],
                        "ts": datetime.now(timezone.utc).isoformat(), "label": label,
                        "src_ip": f"10.0.{self.rng.integers(0, 255)}.{self.rng.integers(1, 255)}" if ev["failed_auth"] else None, **ev})
        return out

    def handle_command(self, cmd: dict) -> bool:
        """Device-side check: only act on commands with a valid HMAC signature."""
        if not verify_command(cmd):
            return False
        d = self.by_id.get(cmd.get("device_id"))
        if not d:
            return False
        if cmd["action"] == "isolate_device":
            d["quarantined"] = True
        elif cmd["action"] in ("restart_device", "firmware_rollback", "throttle_telemetry"):
            d["anomaly"], d["ttl"] = None, 0
        return True


def main():  # pragma: no cover
    ap = argparse.ArgumentParser()
    ap.add_argument("--mqtt"); ap.add_argument("--http"); ap.add_argument("--port", type=int, default=1883)
    ap.add_argument("--interval", type=float, default=1.0); ap.add_argument("--devices", type=int, default=100)
    ap.add_argument("--p-anomaly", type=float, default=0.002); ap.add_argument("--key", default="device-key")
    a = ap.parse_args()
    sim = Simulator(a.devices, a.p_anomaly)
    client = None
    if a.mqtt:
        import paho.mqtt.client as mqtt
        client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="sentineledge-sim")
        client.on_connect = lambda c, u, f, rc, p=None: c.subscribe("sentineledge/devices/+/cmd", qos=1)
        client.on_message = lambda c, u, m: print("command", "ACCEPTED" if sim.handle_command(json.loads(m.payload)) else "REJECTED (bad signature)", flush=True)
        client.connect(a.mqtt, a.port)
        client.loop_start()
    else:
        import httpx
        http = httpx.Client(base_url=a.http or "http://localhost:8000", headers={"X-API-Key": a.key}, timeout=10)
    sent = 0
    while True:
        t0 = time.time()
        evs = sim.tick()
        if client:
            for e in evs:
                client.publish(f"sentineledge/telemetry/{e['device_id']}", json.dumps(e), qos=0)
        else:
            http.post("/api/telemetry", json=evs)
        sent += len(evs)
        if sent % (len(evs) * 10) == 0:
            print(f"sent {sent:,} events", flush=True)
        time.sleep(max(0, a.interval - (time.time() - t0)))


if __name__ == "__main__":
    main()
