"""The shared preflight pipeline: probe -> detect -> evaluate -> trust-preview.v1.

Both the REST endpoint (api/rest.py) and the MCP server (api/mcp_server.py)
call get_preflight(). They MUST share this one path — and its in-flight map
and cache — so a verdict is computed once per process regardless of which
surface a request arrives on.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from functools import cache
from typing import Any

from preflight402.config import Settings
from preflight402.db import connect, migrate, queries
from preflight402.probe.parsers import detect
from preflight402.probe.prober import probe
from preflight402.verdict.rules import evaluate
from preflight402.verdict.schema import build_trust_preview

# One in-flight computation per canonical URL: concurrent cold requests for the
# same URL coalesce onto the first probe instead of each hitting the target and
# racing to cache divergent verdicts.
_inflight: dict[str, asyncio.Future] = {}


@dataclass(slots=True)
class PreflightResult:
    document: dict[str, Any]
    cache_state: str  # "hit" | "miss" | "coalesced"


async def get_preflight(url: str, settings: Settings) -> PreflightResult:
    """Return the trust-preview.v1 document for a URL, cached and coalesced.

    Raises queries.InvalidURLError when the URL is not a plausible http(s)
    endpoint; callers turn that into their surface's error shape.
    """
    canonical = queries.canonicalize_url(url)
    ensure_migrated(str(settings.db_path))

    cached = _cached_document(canonical, settings)
    if cached is not None:
        return PreflightResult(cached, "hit")

    inflight = _inflight.get(canonical)
    if inflight is not None:
        # Another request is already probing this URL; ride its result.
        return PreflightResult(await asyncio.shield(inflight), "coalesced")

    future: asyncio.Future = asyncio.get_running_loop().create_future()
    _inflight[canonical] = future
    try:
        document = await _run_preflight(canonical, settings)
    except BaseException as exc:
        if not future.done():
            future.set_exception(exc)
        raise
    else:
        if not future.done():
            future.set_result(document)
        return PreflightResult(document, "miss")
    finally:
        _inflight.pop(canonical, None)


def _cached_document(canonical: str, settings: Settings) -> dict[str, Any] | None:
    conn = connect(settings.db_path)
    try:
        cached = queries.get_verdict(conn, canonical, "preflight")
        return cached["verdict"] if cached is not None else None
    finally:
        conn.close()


async def _run_preflight(canonical: str, settings: Settings) -> dict[str, Any]:
    result = await probe(canonical, timeout_s=settings.probe_timeout_s)
    detection = detect(result.headers, result.body)
    conn = connect(settings.db_path)
    try:
        # A late arrival that missed both cache and in-flight map re-checks
        # here, so it never re-probes an answer another request just cached.
        existing = queries.get_endpoint(conn, canonical)
        verdict = evaluate(
            result,
            detection,
            first_seen_at=existing["first_seen_at"] if existing else None,
        )
        document = build_trust_preview(canonical, result, detection, verdict)

        # Record real payment endpoints (and refresh known ones) so history
        # accrues organically before the M3 scheduler exists. Arbitrary
        # non-payment URLs are cached but NOT persisted — a public endpoint
        # must not let anyone spam junk rows into the probe schedule.
        if verdict.is_payment_endpoint or existing is not None:
            endpoint_id = queries.upsert_endpoint(conn, canonical, source="preflight")
            queries.record_probe(
                conn,
                endpoint_id,
                **result.db_fields(),
                is_402=result.http_status == 402,
                protocol=detection.protocol if detection.protocol != "none" else None,
                spec_compliant=detection.spec_compliant,
                warnings=detection.warnings or None,
                payment=detection.as_db_payment(),
            )
        # No scheduler owns cache housekeeping yet, so reclaim expired rows
        # here — otherwise a flood of unique junk URLs grows verdict_cache
        # without bound (the index makes this touch only expired rows).
        queries.purge_expired_verdicts(conn)
        queries.put_verdict(
            conn,
            canonical,
            "preflight",
            document,
            ttl_seconds=settings.preflight_cache_ttl_s,
        )
        return document
    finally:
        conn.close()


@cache
def ensure_migrated(db_path: str) -> None:
    """Apply migrations once per database path per process."""
    conn = connect(db_path)
    try:
        migrate(conn)
    finally:
        conn.close()
