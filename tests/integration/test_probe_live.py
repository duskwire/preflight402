"""Live-network acceptance checks for task 1.1 (deselected by default).

Run with: uv run pytest -m slow tests/integration/test_probe_live.py
"""

import pytest

from preflight402.probe.prober import probe

pytestmark = [pytest.mark.anyio, pytest.mark.slow]


async def test_live_https_url() -> None:
    result = await probe("https://example.com/")
    assert result.ok is True
    assert result.http_status == 200
    assert result.latency_ms > 0
    assert result.tls is not None
    assert result.tls.valid is True
    assert result.tls.expires_at is not None


async def test_dead_url() -> None:
    result = await probe("https://preflight402-does-not-exist.invalid/")
    assert result.ok is False
    assert result.error == "dns"
    assert result.tls is not None
    assert result.tls.valid is False


async def test_non_https_url() -> None:
    result = await probe("http://example.com/")
    assert result.ok is True
    assert result.tls is None


async def test_pinned_ip_connects_with_verified_tls() -> None:
    # Resolve, then pin the probe to that exact IP: TLS must still verify
    # against the hostname (the rebinding-safe pin), and it reaches example.com.
    import asyncio
    import socket

    infos = await asyncio.get_running_loop().getaddrinfo(
        "example.com", 443, type=socket.SOCK_STREAM
    )
    ip = infos[0][4][0]
    result = await probe("https://example.com/", pinned_ip=ip)
    assert result.ok is True
    assert result.http_status == 200
    assert result.tls is not None
    assert result.tls.valid is True  # cert verified against the hostname, not the IP
