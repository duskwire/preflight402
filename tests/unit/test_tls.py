import asyncio
import re
import ssl
from pathlib import Path

import pytest
import trustme

from preflight402.probe.tls import inspect_tls

pytestmark = pytest.mark.anyio

CANONICAL_TS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")


@pytest.fixture(scope="module")
def ca() -> trustme.CA:
    return trustme.CA(organization_name="preflight402 test CA")


@pytest.fixture
def ca_file(ca: trustme.CA, tmp_path: Path) -> str:
    path = tmp_path / "ca.pem"
    ca.cert_pem.write_to_path(path)
    return str(path)


@pytest.fixture
async def tls_server(ca: trustme.CA):
    """A local TLS server with a cert for 'localhost'; yields its port."""
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ca.issue_cert("localhost").configure_cert(server_ctx)

    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.close()

    server = await asyncio.start_server(handler, "127.0.0.1", 0, ssl=server_ctx)
    try:
        yield server.sockets[0].getsockname()[1]
    finally:
        server.close()
        await server.wait_closed()


async def test_valid_chain_and_hostname(tls_server: int, ca_file: str) -> None:
    info = await inspect_tls("localhost", tls_server, ca_file=ca_file, timeout_s=5)
    assert info.valid is True
    assert info.error is None
    assert info.issuer == "preflight402 test CA"
    assert CANONICAL_TS.match(info.expires_at)


async def test_untrusted_ca_still_reports_cert_details(tls_server: int) -> None:
    # System trust store doesn't know our test CA — verification must fail,
    # but expiry and issuer must still come back via the unverified retry.
    info = await inspect_tls("localhost", tls_server, timeout_s=5)
    assert info.valid is False
    assert info.error  # e.g. 'unable to get local issuer certificate'
    assert info.issuer == "preflight402 test CA"
    assert CANONICAL_TS.match(info.expires_at)


async def test_hostname_mismatch_fails_with_details(tls_server: int, ca_file: str) -> None:
    # Cert is for 'localhost'; connecting as '127.0.0.1' must fail hostname
    # verification even though the chain is trusted.
    info = await inspect_tls("127.0.0.1", tls_server, ca_file=ca_file, timeout_s=5)
    assert info.valid is False
    assert info.issuer == "preflight402 test CA"
    assert CANONICAL_TS.match(info.expires_at)


async def test_unreachable_port() -> None:
    info = await inspect_tls("127.0.0.1", 1, timeout_s=5)
    assert info.valid is False
    assert info.expires_at is None
    assert info.error


async def test_pinned_ip_connects_and_verifies_against_hostname(
    tls_server: int, ca_file: str
) -> None:
    # The rebinding-safe pin: connect to the IP but verify the cert against
    # the hostname (server_hostname stays the name).
    info = await inspect_tls(
        "localhost", tls_server, ca_file=ca_file, pinned_ip="127.0.0.1", timeout_s=5
    )
    assert info.valid is True
    assert info.issuer == "preflight402 test CA"


async def test_pinned_ip_is_actually_used_for_the_connection(tls_server: int, ca_file: str) -> None:
    # Pin to a loopback IP with no listener: 'localhost' resolves fine to
    # 127.0.0.1 (where the server IS), but the pin must win, so the connection
    # fails — proving the IP, not the hostname, drives the socket.
    info = await inspect_tls(
        "localhost", tls_server, ca_file=ca_file, pinned_ip="127.0.0.2", timeout_s=3
    )
    assert info.valid is False


async def test_never_raises_on_idna_garbage() -> None:
    # getaddrinfo raises UnicodeError (not OSError) on a >63-char label —
    # inspection must classify it, not propagate. Hermetic: fails in IDNA
    # encoding before any network I/O.
    info = await inspect_tls("a" * 64 + ".com", timeout_s=5)
    assert info.valid is False
    assert "label" in info.error or "UnicodeError" in info.error


async def test_unparseable_cert_degrades_to_no_details(monkeypatch) -> None:
    # cryptography rejects some DER that OpenSSL handshakes through; details
    # must degrade gracefully with the handshake verdict preserved.
    from preflight402.probe import tls as tls_mod

    async def fake_fetch(connect_host, server_hostname, port, context, timeout_s):
        return b"not a certificate"

    monkeypatch.setattr(tls_mod, "_fetch_peer_cert_der", fake_fetch)
    info = await tls_mod.inspect_tls("example.com", timeout_s=5)
    assert info.valid is True  # handshake verified; only detail parsing failed
    assert "cert unparseable" in info.error
    assert info.expires_at is None
    assert info.issuer is None
