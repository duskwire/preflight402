from fastapi.testclient import TestClient

from preflight402 import __version__
from preflight402.api.rest import app

client = TestClient(app)


def test_healthz_returns_ok() -> None:
    resp = client.get("/healthz")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["version"] == __version__
    assert body["environment"] in ("dev", "prod")


def test_unknown_route_is_404() -> None:
    resp = client.get("/nonexistent")
    assert resp.status_code == 404
