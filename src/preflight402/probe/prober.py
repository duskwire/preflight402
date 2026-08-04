"""Async HTTP prober: a GET (plus a bounded POST retry), nothing interpreted.

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
from collections.abc import Collection
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx

from preflight402.probe.tls import TLSInfo, inspect_tls

BODY_CAP_BYTES = 64 * 1024  # 402 payloads are small JSON; never slurp a video

# A GET answered with one of these is retried once as an empty JSON POST.
#
# Most x402 endpoints are POST endpoints. Retrying only on 405 (the original
# behaviour) misses the common case where a POST-only endpoint answers a GET
# with 404/200/401 instead of a polite 405 — the M3 checkpoint measured ~55%
# of endpoints we classified "zombie" (answered, never a 402) actually serving
# a valid 402 on POST: 404-only 55%, 200-only 78%, 401/403 63%
# (docs/checkpoint-m3.md). Without this we return `avoid` for endpoints that
# work.
#
# Why these statuses and not others: each means "your REQUEST was wrong", so
# re-asking with the method the endpoint actually implements is a reasonable
# reinterpretation. 5xx is excluded — it means the SERVER is broken (the
# checkpoint measured 0/20 recovery) and re-hitting a struggling server is
# unkind. 3xx is excluded because following redirects would break the SSRF
# pin (see the module docstring).
#
# Side-effect posture: this broad set is for endpoints a REGISTRY advertised as
# x402 payment endpoints — for those a POST is the request their publisher
# expects agents to make, we send an empty JSON body and NO payment header, and
# a compliant endpoint answers 402 before doing any work. It must NOT be applied
# to arbitrary caller-supplied URLs: service.py gates it on catalog membership
# so the free /preflight cannot be turned into a relay that POSTs at a victim of
# the caller's choosing (probe_post_retry_statuses_unlisted, default {405},
# covers that path). Operators narrow either set via env; [] disables.
POST_RETRY_STATUSES: frozenset[int] = frozenset({200, 400, 401, 403, 404, 405, 415, 422})

# error values match the probes.error taxonomy documented in db/schema.sql
_TIMEOUT = "timeout"
_DNS = "dns"
_TLS = "tls"
_CONN_REFUSED = "conn_refused"
_PROTOCOL = "protocol"
_UNKNOWN = "unknown"

USER_AGENT = "preflight402-probe/0.1 (+https://github.com/duskwire/preflight402)"


@dataclass(slots=True)
class ProbeResult:
    url: str
    ok: bool  # status line + headers arrived, whatever the status
    method: str = "GET"  # the method that produced this result (POST via the retry)
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
    # Status a POST retry returned when its result was NOT kept (only a 402 is
    # kept). Without this the retry is invisible: a 429 telling us to back off
    # would be silently discarded and the caller would read the GET as fine.
    retry_status: int | None = None

    def db_fields(self) -> dict[str, Any]:
        """Kwargs for db.queries.record_probe (parser-derived fields excluded)."""
        return {
            "ok": self.ok,
            "error": self.error,
            "http_status": self.http_status,
            "latency_ms": self.latency_ms,
            "method": self.method,
            "retry_status": self.retry_status,
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
    post_retry_statuses: Collection[int] | None = None,
) -> ProbeResult:
    """GET the URL (no redirects followed) and capture what happened.

    Most live x402 endpoints only answer POST, so a GET answered with a
    "your request was wrong" status (POST_RETRY_STATUSES, overridable per
    call) is retried once with an empty JSON POST — the unpaid request returns
    the 402 challenge without being processed. The POST result is kept ONLY
    when it reveals a 402, so a speculative retry can never downgrade or lose
    what the GET already established.

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
    retry_statuses = POST_RETRY_STATUSES if post_retry_statuses is None else post_retry_statuses
    try:
        result = await _request("GET", url, timeout_s, pinned_ip=pinned_ip)
        if result.ok and result.http_status in retry_statuses:
            post = await _request("POST", url, timeout_s, json_probe=True, pinned_ip=pinned_ip)
            # Only a 402 supersedes the GET: the POST is speculative, so a
            # worse or merely different answer must not overwrite real
            # evidence (e.g. a healthy 200 GET staying a 200).
            if post.ok and post.http_status == 402:
                result = post
            else:
                # Keep the GET, but never lose what the retry said — a 429 here
                # means the host is asking us to back off, and callers
                # (scheduler politeness, auditing) must be able to see it.
                result.retry_status = post.http_status
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
