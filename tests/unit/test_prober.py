import asyncio
import json
import socket
import ssl

import httpx
import pytest
import respx

from preflight402.probe import prober
from preflight402.probe.prober import BODY_CAP_BYTES, probe
from preflight402.probe.tls import TLSInfo

pytestmark = pytest.mark.anyio

STUB_TLS = TLSInfo(valid=True, expires_at="2027-01-01T00:00:00.000Z", issuer="Let's Encrypt")


@pytest.fixture
def stub_tls(monkeypatch):
    """Replace the real TLS handshake — unit tests must not open sockets."""

    async def fake_inspect_tls(host, port=443, **kwargs):
        return STUB_TLS

    monkeypatch.setattr(prober, "inspect_tls", fake_inspect_tls)


@respx.mock
async def test_probe_records_a_402_response(stub_tls) -> None:
    payload = {"x402Version": 2, "accepts": [{"payTo": "0xABC"}]}
    respx.get("https://api.example.com/data").mock(
        return_value=httpx.Response(
            402, json=payload, headers={"x-served-by": "edge-1"}
        )
    )
    result = await probe("https://api.example.com/data")
    assert result.ok is True
    assert result.error is None
    assert result.http_status == 402
    assert json.loads(result.body) == payload
    assert result.headers["x-served-by"] == "edge-1"
    assert result.body_truncated is False
    assert result.latency_ms > 0
    assert result.tls == STUB_TLS


@respx.mock
async def test_probe_plain_http_has_no_tls() -> None:
    respx.get("http://api.example.com/").mock(return_value=httpx.Response(200, text="hi"))
    result = await probe("http://api.example.com/")
    assert result.ok is True
    assert result.tls is None
    assert result.body == "hi"


@respx.mock
async def test_probe_does_not_follow_redirects() -> None:
    respx.get("http://api.example.com/").mock(
        return_value=httpx.Response(307, headers={"location": "https://elsewhere.example/"})
    )
    result = await probe("http://api.example.com/")
    assert result.http_status == 307
    assert result.headers["location"] == "https://elsewhere.example/"


@respx.mock
async def test_probe_caps_body_size() -> None:
    respx.get("http://api.example.com/big").mock(
        return_value=httpx.Response(200, content=b"x" * (BODY_CAP_BYTES * 3))
    )
    result = await probe("http://api.example.com/big")
    assert result.body_truncated is True
    assert len(result.body.encode()) == BODY_CAP_BYTES


@respx.mock
async def test_probe_body_exactly_at_cap_is_complete() -> None:
    # A body of exactly the cap arrives in full — it must not be flagged
    # truncated (and one byte more must be).
    respx.get("http://api.example.com/exact").mock(
        return_value=httpx.Response(200, content=b"x" * BODY_CAP_BYTES)
    )
    respx.get("http://api.example.com/over").mock(
        return_value=httpx.Response(200, content=b"x" * (BODY_CAP_BYTES + 1))
    )
    exact = await probe("http://api.example.com/exact")
    assert exact.body_truncated is False
    assert len(exact.body.encode()) == BODY_CAP_BYTES
    over = await probe("http://api.example.com/over")
    assert over.body_truncated is True
    assert len(over.body.encode()) == BODY_CAP_BYTES


async def test_probe_never_raises_on_malformed_urls() -> None:
    # Registry-sourced junk must come back classified, not as exceptions.
    for bad in [
        "https://example.com:99999/",  # port out of range
        "https://example.com:banana/",  # non-numeric port
        "https://[::1",  # invalid IPv6 brackets
        "https:///path",  # no host
        "ftp://example.com/x",  # unsupported scheme
        "not a url at all",
    ]:
        result = await probe(bad)
        assert result.ok is False, bad
        assert result.error == "protocol", bad
        assert result.http_status is None, bad
        assert result.tls is None, bad


async def test_probe_survives_tls_inspection_crash(monkeypatch) -> None:
    async def boom(host, port=443, **kwargs):
        raise RuntimeError("inspector exploded")

    monkeypatch.setattr(prober, "inspect_tls", boom)
    with respx.mock:
        respx.get("https://api.example.com/").mock(return_value=httpx.Response(402))
        result = await probe("https://api.example.com/")
    assert result.ok is True
    assert result.http_status == 402
    assert result.tls.valid is False
    assert "inspector exploded" in result.tls.error


async def test_mid_body_failure_keeps_status_and_headers() -> None:
    # Server sends a 402 + headers, then closes short of its declared
    # content-length: the status (the product's core signal) must survive.
    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.write(
            b"HTTP/1.1 402 Payment Required\r\n"
            b"content-type: application/json\r\n"
            b"content-length: 1000\r\n\r\n"
            b'{"x402Version": 2, "accepts": ['
        )
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        result = await probe(f"http://127.0.0.1:{port}/", timeout_s=5)
    finally:
        server.close()
        await server.wait_closed()
    assert result.ok is True
    assert result.http_status == 402
    assert result.headers["content-type"] == "application/json"
    assert result.error == "protocol"  # peer closed before finishing the body
    assert result.body_truncated is True
    assert '"x402Version"' in result.body


@respx.mock
async def test_probe_classifies_timeout() -> None:
    respx.get("http://api.example.com/").mock(side_effect=httpx.ConnectTimeout("timed out"))
    result = await probe("http://api.example.com/")
    assert result.ok is False
    assert result.error == "timeout"
    assert result.http_status is None
    assert result.latency_ms is not None


def test_classify_uses_cause_chain() -> None:
    # respx rewrites __cause__ when re-raising side effects, so the chain
    # walk is tested directly against the classifier.
    dns = httpx.ConnectError("All connection attempts failed")
    dns.__cause__ = socket.gaierror(-2, "Name or service not known")
    assert prober._classify(dns)[0] == "dns"

    refused = httpx.ConnectError("All connection attempts failed")
    refused.__cause__ = ConnectionRefusedError(111, "Connection refused")
    assert prober._classify(refused)[0] == "conn_refused"

    tls_exc = httpx.ConnectError("handshake blew up")
    tls_exc.__cause__ = ssl.SSLError(1, "bad cert")
    assert prober._classify(tls_exc)[0] == "tls"


@respx.mock
async def test_probe_classifies_dns_failure_from_message() -> None:
    respx.get("http://nope.example.com/").mock(
        side_effect=httpx.ConnectError("[Errno -2] Name or service not known")
    )
    result = await probe("http://nope.example.com/")
    assert result.error == "dns"


@respx.mock
async def test_probe_classifies_connection_refused_from_message() -> None:
    respx.get("http://localhost:1/").mock(
        side_effect=httpx.ConnectError("Connection refused")
    )
    result = await probe("http://localhost:1/")
    assert result.error == "conn_refused"


@respx.mock
async def test_probe_classifies_tls_failure(stub_tls) -> None:
    respx.get("https://api.example.com/").mock(
        side_effect=httpx.ConnectError(
            "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed"
        )
    )
    result = await probe("https://api.example.com/")
    assert result.error == "tls"
    assert result.tls == STUB_TLS  # cert details still gathered independently


@respx.mock
async def test_db_fields_map_onto_record_probe(stub_tls) -> None:
    respx.get("https://api.example.com/").mock(return_value=httpx.Response(402))
    result = await probe("https://api.example.com/")
    fields = result.db_fields()
    assert fields == {
        "ok": True,
        "error": None,
        "http_status": 402,
        "latency_ms": result.latency_ms,
        "tls_valid": True,
        "tls_expires_at": "2027-01-01T00:00:00.000Z",
        "tls_issuer": "Let's Encrypt",
    }
    # Exactly the optional kwargs record_probe accepts for transport facts.
    import inspect

    from preflight402.db import queries

    accepted = set(inspect.signature(queries.record_probe).parameters)
    assert set(fields) <= accepted
