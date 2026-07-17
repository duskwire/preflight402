import asyncio
import base64
import json
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from preflight402 import service
from preflight402.api import rest
from preflight402.config import Settings
from preflight402.db import connect, queries
from preflight402.probe.prober import ProbeResult
from preflight402.probe.tls import TLSInfo

USDC_BASE = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
GOOD_TLS = TLSInfo(valid=True, expires_at="2027-01-01T00:00:00.000Z", issuer="Let's Encrypt")


def _v2_headers(amount: str = "10000") -> dict[str, str]:
    payload = {
        "x402Version": 2,
        "resource": {"url": "https://api.example.com/data"},
        "accepts": [
            {
                "scheme": "exact",
                "network": "eip155:8453",
                "amount": amount,
                "asset": USDC_BASE,
                "payTo": "0x" + "ab" * 20,
                "maxTimeoutSeconds": 300,
            }
        ],
    }
    return {"payment-required": base64.b64encode(json.dumps(payload).encode()).decode()}


@pytest.fixture()
def client(tmp_path: Path, monkeypatch) -> TestClient:
    # allow_private_targets: these tests use unresolvable example hostnames
    # with a stubbed prober, so skip the real DNS the SSRF guard would do.
    # rate_limit_per_minute=0: pipeline tests aren't rate-limit tests.
    monkeypatch.setattr(
        rest,
        "settings",
        Settings(
            _env_file=None,
            db_path=tmp_path / "preflight.db",
            allow_private_targets=True,
            rate_limit_per_minute=0,
        ),
    )
    service.ensure_migrated.cache_clear()
    return TestClient(rest.app)


@pytest.fixture()
def probe_stub(monkeypatch):
    """Replace the network prober; tests queue ProbeResults and count calls."""

    class Stub:
        def __init__(self) -> None:
            self.results: list[ProbeResult] = []
            self.calls: list[str] = []

        async def __call__(
            self, url: str, *, timeout_s: float = 10.0, pinned_ip=None
        ) -> ProbeResult:
            self.calls.append(url)
            return self.results.pop(0)

    stub = Stub()
    monkeypatch.setattr(service, "probe", stub)
    return stub


def _payment_probe(**overrides) -> ProbeResult:
    defaults = dict(
        url="https://api.example.com/data",
        ok=True,
        http_status=402,
        headers=_v2_headers(),
        body="{}",
        latency_ms=180.0,
        tls=GOOD_TLS,
    )
    defaults.update(overrides)
    return ProbeResult(**defaults)


def test_known_good_endpoint_returns_trust_preview(client, probe_stub) -> None:
    probe_stub.results.append(_payment_probe())
    response = client.get("/preflight", params={"url": "https://api.example.com/data"})
    assert response.status_code == 200
    assert response.headers["x-preflight-cache"] == "miss"
    doc = response.json()
    assert doc["schema"] == "trust-preview.v1"
    endpoint = doc["endpoint"]
    assert endpoint["payment_endpoint"] is True
    assert endpoint["protocol"] == "x402-v2"
    assert endpoint["networks"] == ["eip155:8453"]
    assert endpoint["price"] == {
        "amount": "10000",
        "decimals": 6,
        "usd_estimate": 0.01,
        "network": "eip155:8453",
        "asset": USDC_BASE,
    }
    assert endpoint["pay_to"] == "0x" + "ab" * 20
    assert endpoint["assets"][0]["symbol"] == "USDC"
    health = doc["health"]
    assert health["status"] == "up"
    assert health["ssl"]["valid"] is True
    assert health["handshake"] == {"valid_402": True, "spec_compliant": True, "warnings": []}
    assert health["history"] is None  # paid field
    assert doc["authenticity"]["reseller_probability"] is None  # paid field
    assert doc["reputation"]["erc8004"]["filtered_score"] is None  # paid field
    verdict = doc["verdict"]
    assert verdict["recommendation"] == "caution"  # first sighting: single probe
    assert verdict["confidence"] == "low"
    assert any("single probe" in r for r in verdict["reasons"])


def test_preflight_caches_for_ttl(client, probe_stub) -> None:
    probe_stub.results.append(_payment_probe())
    first = client.get("/preflight", params={"url": "https://api.example.com/data"})
    # Variant spelling of the same URL must hit the same cache entry.
    second = client.get("/preflight", params={"url": "HTTPS://api.EXAMPLE.com:443/data"})
    assert first.headers["x-preflight-cache"] == "miss"
    assert second.headers["x-preflight-cache"] == "hit"
    assert second.json() == first.json()
    assert len(probe_stub.calls) == 1  # the network was probed exactly once


def test_dead_url_is_avoid_and_down(client, probe_stub) -> None:
    probe_stub.results.append(
        ProbeResult(
            url="https://dead.example/",
            ok=False,
            error="dns",
            error_detail="Name or service not known",
            latency_ms=42.0,
            tls=TLSInfo(valid=False, error="Name or service not known"),
        )
    )
    doc = client.get("/preflight", params={"url": "https://dead.example/"}).json()
    assert doc["health"]["status"] == "down"
    assert doc["health"]["error"] == "dns"
    assert doc["endpoint"]["payment_endpoint"] is False
    assert doc["endpoint"]["price"] is None
    assert doc["verdict"]["recommendation"] == "avoid"
    assert any("unreachable" in r for r in doc["verdict"]["reasons"])


def test_non_payment_url_says_so(client, probe_stub) -> None:
    probe_stub.results.append(
        ProbeResult(
            url="https://www.google.com/",
            ok=True,
            http_status=200,
            headers={"content-type": "text/html"},
            body="<!doctype html><html>...</html>",
            latency_ms=90.0,
            tls=GOOD_TLS,
        )
    )
    doc = client.get("/preflight", params={"url": "https://www.google.com/"}).json()
    assert doc["endpoint"]["payment_endpoint"] is False
    assert doc["endpoint"]["protocol"] is None
    assert doc["verdict"]["reasons"][0] == "not a payment endpoint (HTTP 200, no 402 challenge)"


def test_invalid_url_is_400(client, probe_stub) -> None:
    response = client.get("/preflight", params={"url": "not a url"})
    assert response.status_code == 400
    assert probe_stub.calls == []


def test_ssrf_target_is_403_and_never_probed(tmp_path, monkeypatch, probe_stub) -> None:
    # With the guard active (allow_private_targets defaults False), a private
    # target is rejected before the network is touched.
    monkeypatch.setattr(
        rest,
        "settings",
        Settings(_env_file=None, db_path=tmp_path / "p.db", rate_limit_per_minute=0),
    )
    service.ensure_migrated.cache_clear()
    guarded = TestClient(rest.app)
    for url in ("http://127.0.0.1/admin", "http://192.168.50.1/", "http://169.254.169.254/"):
        response = guarded.get("/preflight", params={"url": url})
        assert response.status_code == 403, url
        assert "non-public" in response.json()["detail"]
    assert probe_stub.calls == []  # never reached the prober


def test_payment_endpoints_are_persisted_with_probe_history(client, probe_stub) -> None:
    probe_stub.results.append(_payment_probe())
    client.get("/preflight", params={"url": "https://api.example.com/data"})
    conn = connect(rest.settings.db_path)
    try:
        endpoint = queries.get_endpoint(conn, "https://api.example.com/data")
        assert endpoint is not None
        assert endpoint["sources"] == ["preflight"]
        (probe_row,) = queries.latest_probes(conn, endpoint["id"])
        assert probe_row["is_402"] == 1
        assert probe_row["protocol"] == "x402-v2"
        assert probe_row["spec_compliant"] == 1
        assert probe_row["payment"]["protocol"] == "x402-v2"
        assert probe_row["tls_issuer"] == "Let's Encrypt"
    finally:
        conn.close()


def test_non_payment_urls_are_cached_but_not_persisted(client, probe_stub) -> None:
    # A public endpoint must not let arbitrary junk URLs spam the probe
    # schedule — cache the answer, skip the endpoints table.
    probe_stub.results.append(
        ProbeResult(
            url="https://www.google.com/",
            ok=True,
            http_status=200,
            headers={},
            body="<html></html>",
            latency_ms=90.0,
            tls=GOOD_TLS,
        )
    )
    client.get("/preflight", params={"url": "https://www.google.com/"})
    conn = connect(rest.settings.db_path)
    try:
        assert queries.get_endpoint(conn, "https://www.google.com/") is None
        cached = queries.get_verdict(conn, "https://www.google.com/", "preflight")
        assert cached is not None
    finally:
        conn.close()


@pytest.mark.anyio
async def test_concurrent_cold_requests_probe_once(client, monkeypatch) -> None:
    # Two simultaneous cold requests for the same URL must coalesce onto one
    # probe and one recorded observation, and agree on the verdict.
    calls: list[str] = []

    async def slow_probe(url: str, *, timeout_s: float = 10.0, pinned_ip=None) -> ProbeResult:
        calls.append(url)
        await asyncio.sleep(0.05)
        return _payment_probe()

    monkeypatch.setattr(service, "probe", slow_probe)
    transport = httpx.ASGITransport(app=rest.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as ac:
        responses = await asyncio.gather(
            ac.get("/preflight", params={"url": "https://api.example.com/data"}),
            ac.get("/preflight", params={"url": "https://api.example.com/data"}),
        )
    assert len(calls) == 1  # coalesced onto a single probe
    docs = [r.json() for r in responses]
    assert docs[0]["verdict"] == docs[1]["verdict"]  # no divergent scores
    assert sorted(r.headers["x-preflight-cache"] for r in responses) == ["coalesced", "miss"]
    conn = connect(rest.settings.db_path)
    try:
        endpoint = queries.get_endpoint(conn, "https://api.example.com/data")
        assert len(queries.latest_probes(conn, endpoint["id"], limit=10)) == 1
    finally:
        conn.close()


def test_expired_cache_rows_are_purged_on_miss(client, probe_stub) -> None:
    # Every unique junk URL caches a verdict; expired rows must be reclaimed
    # so an anonymous URL flood can't grow verdict_cache without bound.
    for i in range(3):
        probe_stub.results.append(
            ProbeResult(
                url=f"https://junk{i}.example/",
                ok=True,
                http_status=200,
                headers={},
                body="<html></html>",
                latency_ms=10.0,
                tls=GOOD_TLS,
            )
        )
        client.get("/preflight", params={"url": f"https://junk{i}.example/"})
    conn = connect(rest.settings.db_path)
    try:
        # Force all rows expired, then one more miss triggers the purge.
        conn.execute("UPDATE verdict_cache SET expires_at = '2000-01-01T00:00:00.000Z'")
        before = conn.execute("SELECT COUNT(*) FROM verdict_cache").fetchone()[0]
        assert before == 3
    finally:
        conn.close()
    probe_stub.results.append(
        ProbeResult(
            url="https://junk9.example/", ok=True, http_status=200, headers={},
            body="x", latency_ms=10.0, tls=GOOD_TLS,
        )
    )
    client.get("/preflight", params={"url": "https://junk9.example/"})
    conn = connect(rest.settings.db_path)
    try:
        remaining = conn.execute("SELECT COUNT(*) FROM verdict_cache").fetchone()[0]
        assert remaining == 1  # the 3 expired purged; only the fresh one left
    finally:
        conn.close()


def test_5xx_is_not_classified_as_non_payment_endpoint(client, probe_stub) -> None:
    probe_stub.results.append(
        ProbeResult(
            url="https://api.example.com/data",
            ok=True,
            http_status=503,
            headers={"retry-after": "30"},
            body="service unavailable",
            latency_ms=90.0,
            tls=GOOD_TLS,
        )
    )
    doc = client.get("/preflight", params={"url": "https://api.example.com/data"}).json()
    assert doc["health"]["status"] == "up"  # headers arrived
    assert not any("not a payment endpoint" in r for r in doc["verdict"]["reasons"])
    assert any("HTTP 503" in r for r in doc["verdict"]["reasons"])


def test_second_probe_of_known_endpoint_gains_history_context(client, probe_stub) -> None:
    probe_stub.results.append(_payment_probe())
    first = client.get("/preflight", params={"url": "https://api.example.com/data"}).json()
    # Expire the cache manually, then preflight again: the endpoint row now
    # exists, so the new-provider rule sees a real first_seen_at.
    conn = connect(rest.settings.db_path)
    try:
        queries.purge_expired_verdicts(conn, now="2099-01-01T00:00:00.000Z")
    finally:
        conn.close()
    probe_stub.results.append(_payment_probe())
    second = client.get("/preflight", params={"url": "https://api.example.com/data"}).json()
    assert first["verdict"]["recommendation"] == "caution"
    assert any("new provider" in r for r in second["verdict"]["reasons"])
