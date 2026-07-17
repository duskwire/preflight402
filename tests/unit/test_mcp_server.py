import json
from pathlib import Path

import pytest
from mcp.shared.memory import create_connected_server_and_client_session

from preflight402 import service
from preflight402.api import mcp_server
from preflight402.config import Settings
from preflight402.probe.prober import ProbeResult
from preflight402.probe.tls import TLSInfo

pytestmark = pytest.mark.anyio

GOOD_TLS = TLSInfo(valid=True, expires_at="2027-01-01T00:00:00.000Z", issuer="Let's Encrypt")


def _v2_probe() -> ProbeResult:
    payload = {
        "x402Version": 2,
        "resource": {"url": "https://api.example.com/data"},
        "accepts": [
            {
                "scheme": "exact",
                "network": "eip155:8453",
                "amount": "10000",
                "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                "payTo": "0x" + "ab" * 20,
                "maxTimeoutSeconds": 300,
            }
        ],
    }
    import base64

    return ProbeResult(
        url="https://api.example.com/data",
        ok=True,
        http_status=402,
        headers={"payment-required": base64.b64encode(json.dumps(payload).encode()).decode()},
        body="{}",
        latency_ms=180.0,
        tls=GOOD_TLS,
    )


@pytest.fixture()
def configured(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(
        mcp_server,
        "settings",
        Settings(_env_file=None, db_path=tmp_path / "preflight.db", allow_private_targets=True),
    )
    service.ensure_migrated.cache_clear()


@pytest.fixture()
def stub_probe(monkeypatch):
    results: list[ProbeResult] = []
    calls: list[str] = []

    async def fake(
        url: str, *, timeout_s: float = 10.0, pinned_ip=None, enforce_pin=False
    ) -> ProbeResult:
        calls.append(url)
        return results.pop(0)

    monkeypatch.setattr(service, "probe", fake)
    return results, calls


async def test_preflight_tool_is_advertised(configured) -> None:
    async with create_connected_server_and_client_session(mcp_server.mcp) as session:
        tools = await session.list_tools()
    names = {tool.name for tool in tools.tools}
    assert "preflight" in names
    tool = next(t for t in tools.tools if t.name == "preflight")
    assert "url" in tool.inputSchema["properties"]
    assert "url" in tool.inputSchema.get("required", [])


async def test_preflight_tool_returns_trust_preview(configured, stub_probe) -> None:
    results, calls = stub_probe
    results.append(_v2_probe())
    async with create_connected_server_and_client_session(
        mcp_server.mcp, raise_exceptions=True
    ) as session:
        result = await session.call_tool("preflight", {"url": "https://api.example.com/data"})
    assert result.isError is False
    doc = result.structuredContent
    assert doc["schema"] == "trust-preview.v1"
    assert doc["endpoint"]["protocol"] == "x402-v2"
    assert doc["endpoint"]["price"]["usd_estimate"] == 0.01
    assert doc["verdict"]["recommendation"] == "caution"  # first sighting
    assert calls == ["https://api.example.com/data"]


async def test_preflight_tool_shares_cache_with_rest_pipeline(configured, stub_probe) -> None:
    # The MCP tool and REST share service.get_preflight, so a second call for
    # the same URL is served from cache — the network is probed once.
    results, calls = stub_probe
    results.append(_v2_probe())
    async with create_connected_server_and_client_session(mcp_server.mcp) as session:
        first = await session.call_tool("preflight", {"url": "https://api.example.com/data"})
        second = await session.call_tool("preflight", {"url": "HTTPS://api.EXAMPLE.com:443/data"})
    assert len(calls) == 1
    assert first.structuredContent == second.structuredContent


async def test_preflight_tool_dead_url_is_avoid(configured, stub_probe) -> None:
    results, _calls = stub_probe
    results.append(
        ProbeResult(
            url="https://dead.example/",
            ok=False,
            error="dns",
            latency_ms=40.0,
            tls=TLSInfo(valid=False, error="Name or service not known"),
        )
    )
    async with create_connected_server_and_client_session(mcp_server.mcp) as session:
        result = await session.call_tool("preflight", {"url": "https://dead.example/"})
    doc = result.structuredContent
    assert doc["health"]["status"] == "down"
    assert doc["verdict"]["recommendation"] == "avoid"


async def test_preflight_tool_rejects_invalid_url(configured, stub_probe) -> None:
    _, calls = stub_probe
    async with create_connected_server_and_client_session(mcp_server.mcp) as session:
        result = await session.call_tool("preflight", {"url": "not a url"})
    assert result.isError is True
    text = " ".join(c.text for c in result.content if getattr(c, "type", None) == "text")
    assert "invalid url" in text.lower()
    assert calls == []  # never probed


def test_streamable_http_app_mounts_mcp_route() -> None:
    from starlette.applications import Starlette

    app = mcp_server.streamable_http_app()
    assert isinstance(app, Starlette)
    paths = {getattr(r, "path", None) for r in app.routes}
    assert "/mcp" in paths


def test_http_transport_is_stateless_json() -> None:
    # A trust check holds no per-client state, so the hosted transport is
    # configured stateless with plain JSON responses. Pin it: these toggles
    # have no other test, and flipping them changes the deployment contract.
    assert mcp_server.mcp.settings.stateless_http is True
    assert mcp_server.mcp.settings.json_response is True


def test_main_parses_transport_and_port(monkeypatch) -> None:
    # main() wires --transport/--host/--port onto the server before run();
    # verify parsing without actually starting a server.
    captured = {}
    monkeypatch.setattr(
        mcp_server.mcp, "run", lambda transport: captured.update(transport=transport)
    )
    argv = [
        "preflight402-mcp",
        "--transport",
        "streamable-http",
        "--host",
        "0.0.0.0",
        "--port",
        "9999",
    ]
    monkeypatch.setattr("sys.argv", argv)
    mcp_server.main()
    assert captured["transport"] == "streamable-http"
    assert mcp_server.mcp.settings.host == "0.0.0.0"
    assert mcp_server.mcp.settings.port == 9999
