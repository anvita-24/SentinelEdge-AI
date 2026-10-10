"""Isolation Forest + multi-signal risk scoring.

Features are z-normalised per device type, so one forest serves the whole fleet.
risk = 100 * clip(0.45*iforest + 0.55*max_signal_severity + 0.10*(>=2 signals))
"""
import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from .scenarios import BASELINE, FEATURES, TYPES, make_dataset, normal_event

SIGNAL_Z = 4.0


def categorize(z: dict) -> str:
    g = lambda f: z.get(f, 0.0)  # noqa: E731
    if g("failed_auth") >= 6: return "credential_attack"
    if g("bytes_out") >= 6: return "data_exfiltration"
    if g("msg_rate") >= 6: return "message_flood"
    if g("msg_rate") <= -2 and g("rssi") <= -2.5: return "signal_interference"
    if g("battery") <= -5: return "battery_drain"
    if g("memory") >= 5: return "memory_leak"
    if g("cpu") >= 4 and g("temperature") >= 2.5: return "cpu_hijack"
    if g("temperature") >= 5: return "overheating"
    return "unknown_anomaly"


class Detector:
    def __init__(self, seed: int = 42):
        self.seed, self.stats, self.threshold = seed, {}, 50.0
        self.model = IsolationForest(n_estimators=200, random_state=seed, n_jobs=1)
        self.lo = self.scale = 0.0

    # -- training ------------------------------------------------------------
    def fit(self, rows):
        by = {t: [] for t in TYPES}
        for t, f in rows:
            by[t].append([f[x] for x in FEATURES])
        for t, v in by.items():
            a = np.array(v)
            mu, sd = a.mean(0), a.std(0)
            floor = np.maximum(np.maximum(0.05 * np.abs(mu), 0.3), 1e-3)
            self.stats[t] = (mu, np.maximum(sd, floor))
        Z = np.array([self._z(t, f) for t, f in rows])
        self.model.fit(Z)
        raw = -self.model.decision_function(Z)
        self.lo = float(np.median(raw))
        self.scale = max(float(np.percentile(raw, 99) - self.lo), 1e-6)
        return self

    def calibrate_threshold(self, labelled_rows):
        """Pick the risk threshold that maximises F1 on a validation set."""
        risks = np.array([o["risk"] for o in self.assess_batch([(t, f) for t, f, _ in labelled_rows])])
        y = np.array([l != "normal" for _, _, l in labelled_rows])
        best = (0.0, self.threshold)
        for th in np.arange(10, 90, 1.0):
            p = risks >= th
            tp, fp, fn = (p & y).sum(), (p & ~y).sum(), (~p & y).sum()
            f1 = 2 * tp / max(2 * tp + fp + fn, 1)
            if f1 > best[0]:
                best = (f1, float(th))
        self.threshold = best[1]
        return best

    # -- inference -----------------------------------------------------------
    def _z(self, t, f):
        mu, sd = self.stats[t]
        return np.clip((np.array([f[x] for x in FEATURES]) - mu) / sd, -60, 60)

    def assess(self, dtype: str, feats: dict) -> dict:
        return self.assess_batch([(dtype, feats)])[0]

    def assess_batch(self, items) -> list:
        """Vectorised scoring: items = [(dtype, feats), ...]"""
        if not items:
            return []
        Z = np.array([self._z(t, f) for t, f in items])
        raw = -self.model.decision_function(Z)
        iso = np.clip((raw - self.lo) / (2 * self.scale), 0, 1)
        out = []
        for zrow, i in zip(Z, iso):
            zd = {f: float(v) for f, v in zip(FEATURES, zrow)}
            sev = {f: float(np.clip((abs(v) - 3) / 7, 0, 1)) for f, v in zd.items() if abs(v) >= SIGNAL_Z}
            top = max(sev.values(), default=0.0)
            risk = 100 * min(1.0, 0.45 * float(i) + 0.55 * top + (0.10 if len(sev) >= 2 else 0.0))
            signals = sorted(({"feature": f, "z": round(zd[f], 2), "severity": round(s, 2)} for f, s in sev.items()),
                             key=lambda s: -s["severity"])
            out.append({"anomaly_score": round(float(i), 4), "risk": round(risk, 2), "signals": signals,
                        "z": zd, "category": categorize(zd) if sev or risk >= self.threshold else None})
        return out

    # -- persistence ---------------------------------------------------------
    def save(self, path):
        joblib.dump(self, path)

    @staticmethod
    def load(path):
        return joblib.load(path)


def train_default(n_rows: int = 20000, seed: int = 42) -> Detector:
    import numpy as _np
    rng = _np.random.default_rng(seed)
    rows = []
    for _ in range(n_rows):
        t = str(rng.choice(TYPES))
        rows.append((t, normal_event(t, rng)))
    det = Detector(seed).fit(rows)
    det.calibrate_threshold(make_dataset(n_rows // 4, n_rows // 12, seed + 1))
    return det
