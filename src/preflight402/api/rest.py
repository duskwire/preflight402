from fastapi import APIRouter, FastAPI, HTTPException
from fastapi.responses import JSONResponse

from preflight402 import __version__
from preflight402.config import get_settings
from preflight402.db import queries
from preflight402.probe.guard import BlockedTargetError
from preflight402.service import get_preflight

# Resolved at import so misconfiguration fails the boot, not the first request.
settings = get_settings()

# Routes live on a router so the deployment app (api.app) can serve the same
# REST surface alongside the MCP mount without duplicating definitions.
router = APIRouter()

app = FastAPI(
    title="preflight402",
    description="One free call before your agent pays.",
    version=__version__,
)


@router.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok", "version": __version__, "environment": settings.environment}


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
