"""Synthetic device behaviour: normal baselines + 8 operational/security anomaly scenarios."""
import numpy as np

FEATURES = ["temperature", "cpu", "memory", "msg_rate", "rssi", "battery", "bytes_out", "failed_auth"]
TYPES = ["sensor", "gateway", "camera", "actuator"]
# (mean, std) per feature
BASELINE = {
    "sensor":   dict(temperature=(35, 2), cpu=(15, 4), memory=(30, 4), msg_rate=(1, .2), rssi=(-60, 4), battery=(80, 10), bytes_out=(2, .5)),
    "gateway":  dict(temperature=(50, 3), cpu=(35, 6), memory=(50, 5), msg_rate=(20, 3), rssi=(-45, 3), battery=(100, .5), bytes_out=(200, 30)),
    "camera":   dict(temperature=(55, 3), cpu=(45, 6), memory=(60, 5), msg_rate=(5, .8), rssi=(-55, 4), battery=(100, .5), bytes_out=(800, 100)),
    "actuator": dict(temperature=(40, 2.5), cpu=(20, 4), memory=(35, 4), msg_rate=(2, .4), rssi=(-58, 4), battery=(90, 5), bytes_out=(5, 1)),
}
SCENARIOS = ["overheating", "cpu_hijack", "data_exfiltration", "credential_attack",
             "signal_interference", "battery_drain", "memory_leak", "message_flood"]


def normal_event(dtype: str, rng: np.random.Generator) -> dict:
    b = BASELINE[dtype]
    ev = {f: float(rng.normal(*b[f])) for f in b}
    ev["failed_auth"] = float(rng.poisson(0.15))
    if rng.random() < 0.02:  # benign transient (hard negatives)
        f = str(rng.choice(list(b)))
        ev[f] += float(rng.uniform(2.5, 4.5)) * b[f][1]
    return _clip(ev)


def _clip(ev: dict) -> dict:
    for f in ("cpu", "memory", "battery"):
        ev[f] = float(min(100.0, max(0.0, ev[f])))
    ev["msg_rate"] = max(0.0, ev["msg_rate"])
    ev["bytes_out"] = max(0.0, ev["bytes_out"])
    return ev


def apply_anomaly(ev: dict, scenario: str, dtype: str, rng: np.random.Generator, k: float | None = None) -> dict:
    """k in [0.35,1] is intensity - low values create subtle, hard-to-detect cases."""
    k = float(rng.uniform(0.35, 1.0)) if k is None else k
    sd = {f: BASELINE[dtype][f][1] for f in BASELINE[dtype]}
    u = lambda a, b: float(rng.uniform(a, b)) * k  # noqa: E731
    mult = lambda a, b: 1 + (float(rng.uniform(a, b)) - 1) * k  # noqa: E731
    e = dict(ev)
    if scenario == "overheating":
        e["temperature"] += u(6, 10) * sd["temperature"]; e["cpu"] += u(1, 2) * sd["cpu"]
    elif scenario == "cpu_hijack":
        e["cpu"] += u(6, 10) * sd["cpu"]; e["temperature"] += u(3, 5) * sd["temperature"]; e["bytes_out"] += u(1, 3) * sd["bytes_out"]
    elif scenario == "data_exfiltration":
        e["bytes_out"] *= mult(4, 10); e["msg_rate"] += u(2, 4) * sd["msg_rate"]
    elif scenario == "credential_attack":
        e["failed_auth"] = float(rng.integers(8, 31)) * k + e["failed_auth"]; e["cpu"] += u(1, 2) * sd["cpu"]
    elif scenario == "signal_interference":
        e["rssi"] -= u(15, 30); e["msg_rate"] *= mult(0.1, 0.4)
    elif scenario == "battery_drain":
        e["battery"] -= u(35, 60)
    elif scenario == "memory_leak":
        e["memory"] += u(6, 10) * sd["memory"]; e["cpu"] += u(2, 3) * sd["cpu"]
    elif scenario == "message_flood":
        e["msg_rate"] *= mult(8, 20); e["cpu"] += u(3, 5) * sd["cpu"]; e["failed_auth"] += float(rng.integers(0, 4))
    else:
        raise ValueError(scenario)
    return _clip(e)


def make_dataset(n_normal: int, n_anom: int, seed: int):
    """Returns list of (dtype, features, label)."""
    rng = np.random.default_rng(seed)
    rows = []
    for _ in range(n_normal):
        t = str(rng.choice(TYPES))
        rows.append((t, normal_event(t, rng), "normal"))
    for i in range(n_anom):
        t, s = str(rng.choice(TYPES)), SCENARIOS[i % len(SCENARIOS)]
        rows.append((t, apply_anomaly(normal_event(t, rng), s, t, rng), s))
    return rows
