import pytest

pytest.importorskip("mcp")
from app import mcp_server as m  # noqa: E402
from app.models import Action  # noqa: E402
from tests.conftest import make_event  # noqa: E402


def test_tools_registered():
    import asyncio
    names = {t.name for t in asyncio.run(m.mcp.list_tools())}
    assert {"list_devices", "investigate_incident", "request_remediation", "decide_remediation", "verify_audit_log"} <= names


def test_rbac_enforced_through_mcp(db, incident):
    with pytest.raises(ValueError, match="invalid or missing"):
        m.list_devices(api_key="bad")
    with pytest.raises(ValueError, match="lacks permission"):
        m.investigate_incident(incident.id, api_key="viewer-key")
    with pytest.raises(ValueError, match="lacks permission"):
        m.decide_remediation(1, True, api_key="operator-key")


def test_agent_workflow_with_approval_gate(db, incident):
    rep = m.investigate_incident(incident.id, api_key="operator-key")
    assert rep["remediation_plan"]
    act = m.request_remediation("dev-001", "isolate_device", incident.id, api_key="operator-key")
    assert act["status"] == "pending_approval"
    done = m.decide_remediation(act["id"], True, "approved", api_key="admin-key")
    assert done["status"] == "executed" and done["signature"]
    assert m.verify_audit_log(api_key="admin-key")["valid"]


def test_default_key_from_env(monkeypatch, db, incident):
    monkeypatch.setenv("SE_MCP_API_KEY", "viewer-key")
    assert isinstance(m.list_devices(), list)
    assert len(m.get_device_telemetry("dev-001")) >= 1
