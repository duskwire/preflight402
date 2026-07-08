from fastapi import FastAPI

from preflight402 import __version__
from preflight402.config import get_settings

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
