from tests.conftest import ADMIN, DEVICE, OP, VIEWER, make_event


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200 and r.json()["status"] == "ok"


def test_ingest_requires_device_role(client):
    ev = make_event()
    assert client.post("/api/telemetry", json=ev).status_code == 401
    assert client.post("/api/telemetry", json=ev, headers=VIEWER).status_code == 403
    assert client.post("/api/telemetry", json=ev, headers=DEVICE).status_code == 202


def test_batch_ingest_and_fleet(client):
    evs = [make_event(f"dev-{i:03d}", seed=i) for i in range(5)]
    r = client.post("/api/telemetry", json=evs, headers=DEVICE)
    assert r.json()["processed"] == 5
    fleet = client.get("/api/fleet", headers=VIEWER).json()
    assert fleet["count"] == 5


def test_validation_error_on_bad_payload(client):
    assert client.post("/api/telemetry", json={"device_id": "a"}, headers=DEVICE).status_code == 422


def test_batch_size_limit(client):
    evs = [make_event(seed=1)] * 1001
    assert client.post("/api/telemetry", json=evs, headers=DEVICE).status_code == 413


def test_incident_flow_and_metrics(client):
    client.post("/api/telemetry", json=make_event(scenario="message_flood", seed=2), headers=DEVICE)
    inc = client.get("/api/incidents", headers=VIEWER).json()
    assert len(inc) == 1 and inc[0]["category"] == "message_flood"
    m = client.get("/api/metrics", headers=VIEWER).json()
    assert m["events_total"] == 1 and m["open_incidents"] == 1 and m["live_detection"]["tp"] == 1


def test_device_telemetry_endpoint(client):
    client.post("/api/telemetry", json=[make_event(seed=i) for i in range(3)], headers=DEVICE)
    rows = client.get("/api/devices/dev-001/telemetry?limit=2", headers=VIEWER).json()
    assert len(rows) == 2


def test_websocket_requires_valid_key_and_streams(client):
    import pytest
    from starlette.websockets import WebSocketDisconnect
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/ws?key=bad"):
            pass
    with client.websocket_connect("/ws?key=viewer-key") as ws:
        client.post("/api/telemetry", json=make_event(scenario="data_exfiltration", seed=1), headers=DEVICE)
        types = {ws.receive_json()["type"], ws.receive_json()["type"]}
        assert types == {"batch", "incident"}
