import os
import tempfile

_d = tempfile.mkdtemp()
os.environ["DATABASE_URL"] = f"sqlite:///{_d}/test.db"
os.environ["SE_MODEL_PATH"] = f"{_d}/model.joblib"
os.environ["SE_TRAIN_ROWS"] = "8000"
os.environ["SE_SIGNING_SECRET"] = "test-secret"

import numpy as np  # noqa: E402
import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app import pipeline  # noqa: E402
from app.cache import cache  # noqa: E402
from app.db import Base, SessionLocal, engine  # noqa: E402
from app.main import app  # noqa: E402
from app.ml.scenarios import apply_anomaly, normal_event  # noqa: E402

VIEWER = {"X-API-Key": "viewer-key"}
OP = {"X-API-Key": "operator-key"}
ADMIN = {"X-API-Key": "admin-key"}
DEVICE = {"X-API-Key": "device-key"}


@pytest.fixture(scope="session")
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture(autouse=True)
def fresh_db(client):
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    cache.clear()
    yield


@pytest.fixture
def db():
    with SessionLocal() as s:
        yield s


def make_event(device_id="dev-001", dtype="gateway", scenario=None, seed=0, **over):
    rng = np.random.default_rng(seed)
    ev = normal_event(dtype, rng)
    ev["failed_auth"] = 0.0
    if scenario:
        ev = apply_anomaly(ev, scenario, dtype, rng, k=1.0)
    return {"device_id": device_id, "type": dtype, "site": "hq", "firmware": "1.2.0",
            "label": scenario or "normal", **ev, **over}


@pytest.fixture
def incident(db):
    """An open credential-attack incident on dev-001."""
    pipeline.process_batch(db, [make_event(scenario="credential_attack", seed=3, src_ip="10.0.0.9")])
    from app.models import Incident
    return db.query(Incident).first()
