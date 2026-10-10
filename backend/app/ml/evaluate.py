"""Held-out evaluation. Run: python -m app.ml.evaluate  ->  docs/metrics.json"""
import json
import sys
from pathlib import Path

import numpy as np

from .detector import train_default
from .scenarios import SCENARIOS, make_dataset


def _prf(pred, y):
    tp, fp, fn, tn = int((pred & y).sum()), int((pred & ~y).sum()), int((~pred & y).sum()), int((~pred & ~y).sum())
    p, r = tp / max(tp + fp, 1), tp / max(tp + fn, 1)
    return {"precision": round(p, 4), "recall": round(r, 4), "f1": round(2 * p * r / max(p + r, 1e-9), 4),
            "fpr": round(fp / max(fp + tn, 1), 4), "tp": tp, "fp": fp, "fn": fn, "tn": tn}


def evaluate(n_train=20000, n_normal=20000, n_anom=8000, seed=7) -> dict:
    det = train_default(n_train, seed=42)
    test = make_dataset(n_normal, n_anom, seed)  # seeds differ from train/validation
    out = det.assess_batch([(t, f) for t, f, _ in test])
    risk = np.array([o["risk"] for o in out])
    y = np.array([l != "normal" for _, _, l in test])
    labels = np.array([l for _, _, l in test])
    iso_only = np.array([o["anomaly_score"] for o in out])
    best_iso = max(((_prf(iso_only >= t, y)["f1"], t) for t in np.arange(0.05, 0.95, 0.01)))
    per = {s: round(float(((risk >= det.threshold) & (labels == s)).sum() / max((labels == s).sum(), 1)), 4) for s in SCENARIOS}
    cat_ok = sum(1 for (t, f, l), o in zip(test, out) if l != "normal" and o["category"] == l)
    return {
        "test_events": len(test), "anomalous_events": int(y.sum()), "scenarios": len(SCENARIOS),
        "threshold": det.threshold, "combined_risk": _prf(risk >= det.threshold, y),
        "isolation_forest_only_best_f1": round(best_iso[0], 4),
        "per_scenario_recall": per,
        "root_cause_category_accuracy_on_anomalies": round(cat_ok / max(int(y.sum()), 1), 4),
    }


if __name__ == "__main__":
    m = evaluate()
    p = Path(sys.argv[1] if len(sys.argv) > 1 else "../docs/metrics.json")
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(m, indent=2))
    print(json.dumps(m, indent=2))
