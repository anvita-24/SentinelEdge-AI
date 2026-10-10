import numpy as np
import pytest

from app import pipeline
from app.ml import evaluate
from app.ml.detector import categorize
from app.ml.scenarios import SCENARIOS, TYPES, apply_anomaly, normal_event


def test_normal_traffic_rarely_flagged():
    det, rng = pipeline.get_detector(), np.random.default_rng(1)
    items = [(t, normal_event(t, rng)) for t in TYPES * 250]
    flagged = sum(a["risk"] >= det.threshold for a in det.assess_batch(items))
    assert flagged / len(items) < 0.08


@pytest.mark.parametrize("scenario", SCENARIOS)
def test_full_intensity_scenarios_detected(scenario):
    det, rng = pipeline.get_detector(), np.random.default_rng(2)
    items = []
    for i in range(60):
        t = TYPES[i % 4]
        items.append((t, apply_anomaly(normal_event(t, rng), scenario, t, rng, k=1.0)))
    hits = sum(a["risk"] >= det.threshold for a in det.assess_batch(items))
    assert hits / len(items) >= 0.85, scenario


def test_risk_bounded_and_signals_explain():
    det = pipeline.get_detector()
    rng = np.random.default_rng(3)
    ev = apply_anomaly(normal_event("camera", rng), "data_exfiltration", "camera", rng, k=1.0)
    a = det.assess("camera", ev)
    assert 0 <= a["risk"] <= 100
    assert a["signals"][0]["feature"] == "bytes_out"
    assert a["category"] == "data_exfiltration"


@pytest.mark.parametrize("z,expected", [
    ({"failed_auth": 12}, "credential_attack"),
    ({"bytes_out": 20, "msg_rate": 3}, "data_exfiltration"),
    ({"msg_rate": 10, "cpu": 4}, "message_flood"),
    ({"cpu": 8, "temperature": 4}, "cpu_hijack"),
    ({"temperature": 8, "cpu": 1}, "overheating"),
    ({"rssi": -6, "msg_rate": -4}, "signal_interference"),
    ({"battery": -9}, "battery_drain"),
    ({"memory": 8, "cpu": 2}, "memory_leak"),
    ({}, "unknown_anomaly"),
])
def test_categorize(z, expected):
    assert categorize(z) == expected


def test_combined_beats_isolation_forest_alone():
    m = evaluate.evaluate(n_train=8000, n_normal=6000, n_anom=2400)
    assert m["combined_risk"]["f1"] > m["isolation_forest_only_best_f1"]
    assert m["combined_risk"]["f1"] > 0.80 and m["combined_risk"]["recall"] > 0.75
    assert m["scenarios"] == 8


def test_model_persistence(tmp_path):
    from app.ml.detector import Detector
    det = pipeline.get_detector()
    p = tmp_path / "m.joblib"
    det.save(p)
    loaded = Detector.load(p)
    ev = normal_event("sensor", np.random.default_rng(0))
    assert loaded.assess("sensor", ev)["risk"] == det.assess("sensor", ev)["risk"]
