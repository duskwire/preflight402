import asyncio
from functools import cache
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse

from preflight402 import __version__
from preflight402.config import get_settings
from preflight402.db import connect, migrate, queries
from preflight402.probe.parsers import detect
from preflight402.probe.prober import probe
from preflight402.verdict.rules import evaluate
from preflight402.verdict.schema import build_trust_preview

# Resolved at import so misconfiguration fails the boot, not the first request.
settings = get_settings()

# One in-flight computation per canonical URL: concurrent cold requests for the
# same URL coalesce onto the first probe instead of each hitting the target and
# racing to cache divergent verdicts.
_inflight: dict[str, asyncio.Future] = {}

app = FastAPI(
    title="preflight402",
    description="One free call before your agent pays.",
    version=__version__,
)


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok", "version": __version__, "environment": settings.environment}


@app.get("/preflight")
async def preflight(url: str) -> JSONResponse:
    """One free call before your agent pays: the trust-preview.v1 verdict.

    Free tier by design: no wallet, no auth, no facilitator calls. Responses
    are cached for settings.preflight_cache_ttl_s per canonical URL.
    """
    try:
        canonical = queries.canonicalize_url(url)
    except queries.InvalidURLError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None

    _ensure_migrated(str(settings.db_path))

    cached = _cached_document(canonical)
    if cached is not None:
        return JSONResponse(cached, headers={"x-preflight-cache": "hit"})

    inflight = _inflight.get(canonical)
    if inflight is not None:
        # Another request is already probing this URL; ride its result.
        document = await asyncio.shield(inflight)
        return JSONResponse(document, headers={"x-preflight-cache": "coalesced"})

    future: asyncio.Future = asyncio.get_running_loop().create_future()
    _inflight[canonical] = future
    try:
        document = await _run_preflight(canonical)
    except BaseException as exc:
        if not future.done():
            future.set_exception(exc)
        raise
    else:
        if not future.done():
            future.set_result(document)
        return JSONResponse(document, headers={"x-preflight-cache": "miss"})
    finally:
        _inflight.pop(canonical, None)


def _cached_document(canonical: str) -> dict[str, Any] | None:
    conn = connect(settings.db_path)
    try:
        cached = queries.get_verdict(conn, canonical, "preflight")
        return cached["verdict"] if cached is not None else None
    finally:
        conn.close()


async def _run_preflight(canonical: str) -> dict[str, Any]:
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
def _ensure_migrated(db_path: str) -> None:
    """Apply migrations once per database path per process."""
    conn = connect(db_path)
    try:
        migrate(conn)
    finally:
        conn.close()
