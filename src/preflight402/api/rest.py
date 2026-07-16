from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse

from preflight402 import __version__
from preflight402.config import get_settings
from preflight402.db import queries
from preflight402.service import get_preflight

# Resolved at import so misconfiguration fails the boot, not the first request.
settings = get_settings()

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
        result = await get_preflight(url, settings)
    except queries.InvalidURLError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None
    return JSONResponse(result.document, headers={"x-preflight-cache": result.cache_state})
