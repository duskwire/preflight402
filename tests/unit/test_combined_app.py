"""The single-port deployment app: REST routes + /mcp on one server.

The MCP session manager can only be started once per process, so one client
context (module-scoped) serves every test here.
"""

import json

import pytest
from fastapi.testclient import TestClient

from preflight402.api import app as app_module

MCP_HEADERS = {
    "content-type": "application/json",
    "accept": "application/json, text/event-stream",
}


@pytest.fixture(scope="module")
def client():
    # None of these tests write the DB (and conftest chdirs the session to a
    # tmp dir regardless); one shared context because the MCP session manager
    # can only be started once per process.
    with TestClient(app_module.app) as test_client:  # context manager runs the lifespan
        yield test_client


def test_rest_routes_are_served(client: TestClient) -> None:
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_invalid_preflight_url_is_400(client: TestClient) -> None:
    assert client.get("/preflight", params={"url": "junk"}).status_code == 400


def test_mcp_endpoint_answers_initialize(client: TestClient) -> None:
    # stateless_http + json_response means a bare JSON-RPC POST gets a JSON
    # reply — enough to prove the /mcp mount and session-manager lifespan
    # are wired (full protocol coverage lives in the MCP transport tests).
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "combined-app-test", "version": "0"},
        },
    }
    response = client.post("/mcp", content=json.dumps(payload), headers=MCP_HEADERS)
    assert response.status_code == 200
    body = response.json()
    assert body["result"]["serverInfo"]["name"] == "preflight402"
    assert "tools" in body["result"]["capabilities"]


def test_rest_semantics_survive_the_mcp_mount(client: TestClient) -> None:
    # Mounting MCP at /mcp (not "/") keeps FastAPI's own 405 / redirect / JSON
    # 404 for the REST routes instead of the MCP app's plain-text 404.
    unknown = client.get("/nonexistent")
    assert unknown.status_code == 404
    assert unknown.json()["detail"] == "Not Found"  # FastAPI JSON, not MCP text
    wrong_method = client.post("/healthz")
    assert wrong_method.status_code == 405
    assert "GET" in wrong_method.headers.get("allow", "")
