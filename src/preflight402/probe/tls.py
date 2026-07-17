"""TLS certificate inspection for probed endpoints.

Separate from the HTTP probe on purpose: httpx does not expose the peer
certificate after a response completes, and the verdict rules need cert
details (expiry, issuer) even — especially — when verification fails, which
is exactly when an HTTPS request would have died with a bare error. The
extra handshake per probe is cheap at our scale.
"""

from __future__ import annotations

import asyncio
import contextlib
import ssl
from dataclasses import dataclass
from datetime import UTC

from cryptography import x509
from cryptography.x509.oid import NameOID


@dataclass(slots=True)
class TLSInfo:
    valid: bool
    expires_at: str | None = None  # canonical millisecond-Z UTC, like the DB layer
    issuer: str | None = None
    # Verification/handshake failure detail when not valid. May also be set
    # with valid=True when the handshake verified but the certificate bytes
    # could not be parsed for details.
    error: str | None = None


async def inspect_tls(
    host: str,
    port: int = 443,
    *,
    timeout_s: float = 10.0,
    ca_file: str | None = None,
    pinned_ip: str | None = None,
) -> TLSInfo:
    """Handshake with the host and report certificate validity and details.

    valid=True means the default trust store (or ca_file, used by tests)
    verified the chain and hostname. On verification failure a second,
    unverified handshake fetches the offending certificate so expiry and
    issuer are still populated (best-effort: a rotating or multi-cert host
    may present a different certificate on the retry). Never raises —
    inspection failures come back as TLSInfo(valid=False, error=...).
    ca_file exists for hermetic tests against a local CA; production callers
    leave it None for the system store.
    """
    try:
        return await _inspect_tls(host, port, timeout_s, ca_file, pinned_ip)
    except Exception as exc:
        # Never let inspection kill a probe: getaddrinfo raises UnicodeError
        # on bad IDNA labels, cryptography rejects certs OpenSSL accepts, ...
        detail = str(exc) or ""
        return TLSInfo(valid=False, error=f"{type(exc).__name__}: {detail}".rstrip(": "))


async def _inspect_tls(
    host: str, port: int, timeout_s: float, ca_file: str | None, pinned_ip: str | None = None
) -> TLSInfo:
    # Connect to the pinned IP (if any) but keep server_hostname=host for SNI
    # and cert-hostname verification — same rebinding-safe pin as the GET.
    connect_host = pinned_ip or host
    verified_ctx = ssl.create_default_context(cafile=ca_file)
    try:
        der = await _fetch_peer_cert_der(connect_host, host, port, verified_ctx, timeout_s)
    except ssl.SSLCertVerificationError as exc:
        detail = exc.verify_message or str(exc)
        try:
            der = await _fetch_peer_cert_der(
                connect_host, host, port, _unverified_context(), timeout_s
            )
        except (TimeoutError, OSError) as retry_exc:
            retry_detail = str(retry_exc) or type(retry_exc).__name__
            return TLSInfo(valid=False, error=f"{detail}; cert fetch failed: {retry_detail}")
        details, parse_error = _details_or_error(der)
        return TLSInfo(valid=False, error=_join(detail, parse_error), **details)
    except ssl.SSLError as exc:
        return TLSInfo(valid=False, error=exc.reason or str(exc))
    except (TimeoutError, OSError) as exc:
        return TLSInfo(valid=False, error=str(exc) or type(exc).__name__)
    details, parse_error = _details_or_error(der)
    return TLSInfo(valid=True, error=parse_error, **details)


async def _fetch_peer_cert_der(
    connect_host: str, server_hostname: str, port: int, context: ssl.SSLContext, timeout_s: float
) -> bytes:
    async with asyncio.timeout(timeout_s):
        _, writer = await asyncio.open_connection(
            connect_host, port, ssl=context, server_hostname=server_hostname
        )
    try:
        ssl_object = writer.get_extra_info("ssl_object")
        der = ssl_object.getpeercert(binary_form=True)
        if der is None:  # pragma: no cover - handshake succeeded, cert must exist
            raise ssl.SSLError("no peer certificate")
        return der
    finally:
        # abort(), not close(): a graceful TLS shutdown waits for the peer's
        # close_notify, and asyncio's default SSL_SHUTDOWN_TIMEOUT is 30s —
        # a wedged or hostile server would stall every probe regardless of
        # timeout_s. The cert is already in hand; an RST is fine.
        writer.transport.abort()
        with contextlib.suppress(OSError, ssl.SSLError):
            await writer.wait_closed()


def _unverified_context() -> ssl.SSLContext:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def _details_or_error(der: bytes) -> tuple[dict[str, str | None], str | None]:
    """Parse cert details, degrading to empty details on unparseable DER.

    cryptography's parser is stricter than OpenSSL's, so a certificate that
    completed a handshake can still fail to parse here.
    """
    try:
        return _cert_details(der), None
    except ValueError as exc:
        return {"expires_at": None, "issuer": None}, f"cert unparseable: {exc}"


def _join(first: str, second: str | None) -> str:
    return f"{first}; {second}" if second else first


def _cert_details(der: bytes) -> dict[str, str | None]:
    cert = x509.load_der_x509_certificate(der)
    expires = cert.not_valid_after_utc.astimezone(UTC)
    expires_at = expires.isoformat(timespec="milliseconds").replace("+00:00", "Z")
    issuer = None
    for oid in (NameOID.ORGANIZATION_NAME, NameOID.COMMON_NAME):
        attrs = cert.issuer.get_attributes_for_oid(oid)
        if attrs:
            issuer = str(attrs[0].value)
            break
    return {"expires_at": expires_at, "issuer": issuer}
