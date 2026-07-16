"""Live end-to-end acceptance for task 1.5 (deselected by default).

Run with: uv run pytest -m slow tests/integration/test_preflight_live.py
"""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from preflight402 import service
from preflight402.api import rest
from preflight402.config import Settings

pytestmark = pytest.mark.slow


@pytest.fixture()
def client(tmp_path: Path, monkeypatch) -> TestClient:
    monkeypatch.setattr(
        rest, "settings", Settings(_env_file=None, db_path=tmp_path / "preflight.db")
    )
    service.ensure_migrated.cache_clear()
    return TestClient(rest.app)


def test_live_payment_endpoint(client) -> None:
    # A Bazaar-listed endpoint from the golden corpus; if it has died since
    # capture, the verdict flips to avoid — assert the pipeline, not fate.
    response = client.get(
        "/preflight", params={"url": "https://pro-api.coingecko.com/api/v3/x402/simple/price"}
    )
    assert response.status_code == 200
    doc = response.json()
    assert doc["schema"] == "trust-preview.v1"
    if doc["endpoint"]["payment_endpoint"]:
        assert doc["endpoint"]["protocol"] in ("x402-v2", "x402-v1", "mpp")
        assert doc["verdict"]["recommendation"] in ("proceed", "caution")


def test_live_dead_url(client) -> None:
    doc = client.get(
        "/preflight", params={"url": "https://preflight402-does-not-exist.invalid/"}
    ).json()
    assert doc["health"]["status"] == "down"
    assert doc["verdict"]["recommendation"] == "avoid"


def test_live_not_a_payment_endpoint(client) -> None:
    doc = client.get("/preflight", params={"url": "https://www.google.com/"}).json()
    assert doc["endpoint"]["payment_endpoint"] is False
    assert "not a payment endpoint" in doc["verdict"]["reasons"][0]
