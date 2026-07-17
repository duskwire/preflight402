"""Async HTTP prober: one GET, everything captured, nothing interpreted.

Protocol parsing (x402 v1/v2, MPP) happens downstream in probe.parsers —
this module only gathers raw material: status, headers, a size-capped body,
timing, transport-level errors, and TLS certificate details for https URLs.
ProbeResult's db_fields() maps onto db.queries.record_probe's kwargs.
"""

from __future__ import annotations

import asyncio
import socket
import ssl
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx

from preflight402.probe.tls import TLSInfo, inspect_tls

BODY_CAP_BYTES = 64 * 1024  # 402 payloads are small JSON; never slurp a video

# error values match the probes.error taxonomy documented in db/schema.sql
_TIMEOUT = "timeout"
_DNS = "dns"
_TLS = "tls"
_CONN_REFUSED = "conn_refused"
_PROTOCOL = "protocol"
_UNKNOWN = "unknown"

USER_AGENT = "preflight402-probe/0.1 (+https://github.com/chadander/preflight402)"


@dataclass(slots=True)
class ProbeResult:
    url: str
    ok: bool  # status line + headers arrived, whatever the status
    method: str = "GET"  # the method that produced this result (POST on 405 fallback)
    # With ok=False: why no response arrived. With ok=True: a body-read
    # failure after headers arrived (status/headers/partial body retained).
    error: str | None = None  # timeout | dns | tls | conn_refused | protocol | unknown
    error_detail: str | None = None
    http_status: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    body: str | None = None  # decoded, truncated to BODY_CAP_BYTES of raw bytes
    body_truncated: bool = False  # capped, or cut short by a body-read failure
    latency_ms: float | None = None  # request start -> body complete/capped/failed
    tls: TLSInfo | None = None  # None for plain-http URLs

    def db_fields(self) -> dict[str, Any]:
        """Kwargs for db.queries.record_probe (parser-derived fields excluded)."""
        return {
            "ok": self.ok,
            "error": self.error,
            "http_status": self.http_status,
            "latency_ms": self.latency_ms,
            "tls_valid": self.tls.valid if self.tls else None,
            "tls_expires_at": self.tls.expires_at if self.tls else None,
            "tls_issuer": self.tls.issuer if self.tls else None,
        }


async def probe(
    url: str,
    *,
    timeout_s: float = 10.0,
    pinned_ip: str | None = None,
    enforce_pin: bool = False,
) -> ProbeResult:
    """GET the URL (no redirects followed) and capture what happened.

    A meaningful share of live x402 endpoints only answer POST and 405 a GET,
    so a GET that returns 405 is retried once with an empty JSON POST — the
    unpaid request returns the 402 challenge without being processed — and
    that result is kept when it reveals a 402.

    When `pinned_ip` is given, both the GET/POST and the TLS handshake connect
    to exactly that address (with the original host preserved for Host and
    SNI), so a hostname already validated as public cannot be re-resolved to a
    private target between check and connect (DNS rebinding). Callers get the
    IP from guard.resolve_and_validate.

    Never raises for network-level failures — they come back classified in
    ProbeResult.error. TLS inspection runs as its own handshake, concurrent
    with the request, so certificate details survive even when it dies on a
    verification error.
    """
    try:
        # urlsplit/.port raise ValueError on malformed IPv6 brackets and
        # garbage ports — registry URLs contain such junk; classify, don't die.
        parts = urlsplit(url)
        host = parts.hostname
        port = parts.port or 443
    except ValueError as exc:
        return ProbeResult(url=url, ok=False, error=_PROTOCOL, error_detail=str(exc))
    if enforce_pin and pinned_ip is None and host:
        # The guard required a validated pin but could not produce one (the
        # host did not resolve at check time). Re-resolving here would reopen
        # the rebinding window a hostile DNS server could exploit, so report
        # unreachable instead of connecting via an unvalidated lookup.
        return ProbeResult(
            url=url, ok=False, error=_DNS, error_detail="host did not resolve at validation"
        )
    tls_task = None
    if parts.scheme == "https" and host:
        tls_task = asyncio.ensure_future(
            inspect_tls(host, port, timeout_s=timeout_s, pinned_ip=pinned_ip)
        )
    try:
        result = await _request("GET", url, timeout_s, pinned_ip=pinned_ip)
        if result.ok and result.http_status == 405:
            post = await _request("POST", url, timeout_s, json_probe=True, pinned_ip=pinned_ip)
            if post.ok and post.http_status == 402:
                result = post
    finally:
        # The GET can fail fast (e.g. DNS); still collect the TLS side. The
        # task must never propagate out of this finally, whatever it throws.
        tls = None
        if tls_task is not None:
            try:
                tls = await tls_task
            except Exception as exc:
                detail = str(exc) or type(exc).__name__
                tls = TLSInfo(valid=False, error=f"tls inspection failed: {detail}")
    result.tls = tls
    return result


async def _request(
    method: str,
    url: str,
    timeout_s: float,
    *,
    json_probe: bool = False,
    pinned_ip: str | None = None,
) -> ProbeResult:
    started = time.monotonic()
    request_kwargs: dict[str, Any] = {}
    headers: dict[str, str] = {}
    target_url = url
    if pinned_ip is not None:
        # Connect to the validated IP but keep the original host for Host and
        # SNI (httpx verifies the cert against sni_hostname), so no second DNS
        # resolution happens that a rebinding attacker could subvert.
        target_url, host_header = _pin_target(url, pinned_ip)
        headers["host"] = host_header
        request_kwargs["extensions"] = {"sni_hostname": urlsplit(url).hostname}
    if json_probe:
        # Minimal empty JSON body for the POST fallback: the x402 challenge is
        # returned pre-payment, so the request is never actually processed.
        request_kwargs["content"] = b"{}"
        headers["content-type"] = "application/json"
    if headers:
        request_kwargs["headers"] = headers
    try:
        async with httpx.AsyncClient(
            timeout=timeout_s,
            follow_redirects=False,  # a redirecting payment endpoint is a finding, not a hop
            headers={"user-agent": USER_AGENT},
        ) as client:
            # Client construction loads the CA bundle (~30ms); restart the
            # timer so latency_ms measures the endpoint, not this process.
            started = time.monotonic()
            async with client.stream(method, target_url, **request_kwargs) as response:
                raw = bytearray()
                truncated = False
                error = detail = None
                try:
                    async for chunk in response.aiter_bytes():
                        raw.extend(chunk)
                        if len(raw) > BODY_CAP_BYTES:
                            truncated = True
                            del raw[BODY_CAP_BYTES:]
                            break
                except Exception as exc:
                    # Headers already arrived — the status (a 402 is the whole
                    # point) and partial body are still the probe's result.
                    error, detail = _classify(exc)
                    truncated = True
                return ProbeResult(
                    url=url,
                    ok=True,
                    method=method,
                    error=error,
                    error_detail=detail,
                    http_status=response.status_code,
                    headers=dict(response.headers),
                    body=bytes(raw).decode(response.encoding or "utf-8", errors="replace"),
                    body_truncated=truncated,
                    latency_ms=(time.monotonic() - started) * 1000,
                )
    except Exception as exc:  # the prober's job is to classify failures, not crash
        kind, detail = _classify(exc)
        return ProbeResult(
            url=url,
            ok=False,
            method=method,
            error=kind,
            error_detail=detail,
            latency_ms=(time.monotonic() - started) * 1000,
        )


def _pin_target(url: str, pinned_ip: str) -> tuple[str, str]:
    """Rewrite `url` to connect to `pinned_ip`, returning (url, Host header)."""
    parts = urlsplit(url)
    ip_netloc = f"[{pinned_ip}]" if ":" in pinned_ip else pinned_ip
    authority = f"{ip_netloc}:{parts.port}" if parts.port else ip_netloc
    target = urlunsplit((parts.scheme, authority, parts.path or "/", parts.query, ""))
    default_port = 443 if parts.scheme == "https" else 80
    host = parts.hostname or ""
    host_header = f"{host}:{parts.port}" if parts.port and parts.port != default_port else host
    return target, host_header


def _classify(exc: Exception) -> tuple[str, str]:
    detail = str(exc) or type(exc).__name__
    if isinstance(exc, httpx.TimeoutException):
        return _TIMEOUT, detail
    for cause in _cause_chain(exc):
        if isinstance(cause, ssl.SSLError):
            return _TLS, detail
        if isinstance(cause, socket.gaierror):
            return _DNS, detail
        if isinstance(cause, ConnectionRefusedError):
            return _CONN_REFUSED, detail
    if isinstance(exc, httpx.ConnectError):
        # httpx flattens some OS errors into the message only
        lowered = detail.lower()
        if "getaddrinfo" in lowered or "name or service" in lowered or "nodename" in lowered:
            return _DNS, detail
        if "refused" in lowered:
            return _CONN_REFUSED, detail
        if "ssl" in lowered or "certificate" in lowered:
            return _TLS, detail
        return _UNKNOWN, detail
    if isinstance(
        exc, httpx.RemoteProtocolError | httpx.UnsupportedProtocol | httpx.InvalidURL | ValueError
    ):
        return _PROTOCOL, detail
    return _UNKNOWN, detail


def _cause_chain(exc: BaseException) -> list[BaseException]:
    chain: list[BaseException] = []
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        chain.append(current)
        seen.add(id(current))
        current = current.__cause__ or current.__context__
    return chain
