import asyncio
import time

from fastapi import APIRouter, FastAPI, HTTPException
from fastapi.responses import JSONResponse

from preflight402 import __version__
from preflight402.api.ratelimit import RateLimiter, RateLimitMiddleware
from preflight402.config import get_settings
from preflight402.db import connect, queries
from preflight402.probe.guard import BlockedTargetError
from preflight402.service import ensure_migrated, get_preflight
from preflight402.stats import compute_stats

STATS_CACHE_TTL_S = 60.0

# Resolved at import so misconfiguration fails the boot, not the first request.
settings = get_settings()
# Shared limiter; the combined app (api.app) reuses it so REST and MCP debit
# one bucket. get_rate/get_limiter are read per request so tests can swap them.
_limiter = RateLimiter(max(settings.rate_limit_per_minute, 1.0))

# Routes live on a router so the deployment app (api.app) can serve the same
# REST surface alongside the MCP mount without duplicating definitions.
router = APIRouter()

app = FastAPI(
    title="preflight402",
    description="One free call before your agent pays.",
    version=__version__,
)
app.add_middleware(
    RateLimitMiddleware,
    get_limiter=lambda: _limiter,
    get_rate=lambda: settings.rate_limit_per_minute,
    prefixes=("/preflight", "/stats"),
)

# /stats aggregates over the whole probes table; one computation per
# STATS_CACHE_TTL_S serves everyone. Keyed by db_path so tests with distinct
# databases don't read each other's cached document.
_stats_cache: dict[str, tuple[float, dict]] = {}


@router.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok", "version": __version__, "environment": settings.environment}


@router.get("/stats")
async def stats() -> JSONResponse:
    """The public dashboard: catalog, probing, ecosystem health, usage.

    stats.v0, additive-only; paid/reputation fields are null until M4/M5.
    """
    key = str(settings.db_path)
    cached = _stats_cache.get(key)
    if cached is not None and time.monotonic() - cached[0] < STATS_CACHE_TTL_S:
        return JSONResponse(cached[1], headers={"x-stats-cache": "hit"})
    # compute_stats scans the whole probes/endpoints tables (~0.9s at a 50k
    # catalog), so run it off the event loop with its own connection —
    # sqlite connections are thread-bound. The 60s cache means at most one
    # such computation per minute even under a burst.
    document = await asyncio.to_thread(_compute_stats_in_thread, key)
    _stats_cache[key] = (time.monotonic(), document)
    return JSONResponse(document, headers={"x-stats-cache": "miss"})


def _compute_stats_in_thread(db_path: str) -> dict:
    ensure_migrated(db_path)
    conn = connect(db_path)
    try:
        return compute_stats(conn)
    finally:
        conn.close()


@router.get("/preflight")
async def preflight(url: str) -> JSONResponse:
    """One free call before your agent pays: the trust-preview.v1 verdict.

    Free tier by design: no wallet, no auth, no facilitator calls. Responses
    are cached for settings.preflight_cache_ttl_s per canonical URL.
    """
    try:
        result = await get_preflight(url, settings)
    except BlockedTargetError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from None
    except queries.InvalidURLError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None
    return JSONResponse(result.document, headers={"x-preflight-cache": result.cache_state})


app.include_router(router)
