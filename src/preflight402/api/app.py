"""The deployment ASGI app: REST and MCP on one port.

    /healthz, /preflight   REST (api.rest)
    /mcp                   MCP streamable-http (api.mcp_server)

The MCP session manager must be running for /mcp to answer, which is why this
module wires it into the FastAPI lifespan. Serve with:

    uvicorn preflight402.api.app:app --host 0.0.0.0 --port 8402

Note: the MCP session manager can only be started once per FastMCP instance,
so create_app() is meant to be called once per process (module import does
it); tests share one client context.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import AsyncIterator

from fastapi import FastAPI

from preflight402 import __version__
from preflight402.api import rest
from preflight402.api.mcp_server import mcp
from preflight402.api.ratelimit import RateLimitMiddleware
from preflight402.scheduler import run_scheduler


@contextlib.asynccontextmanager
async def _lifespan(_: FastAPI) -> AsyncIterator[None]:
    # The in-app scheduler is opt-in (PREFLIGHT402_SCHEDULER_ENABLED=true):
    # a redeploy must never silently start bulk probing from the home LXC.
    # rest.settings is read at startup, not import, so tests can swap it.
    stop = asyncio.Event()
    scheduler_task = None
    if rest.settings.scheduler_enabled:
        scheduler_task = asyncio.create_task(run_scheduler(rest.settings, stop=stop))
    try:
        async with mcp.session_manager.run():
            yield
    finally:
        if scheduler_task is not None:
            stop.set()
            # The loop exits at the next cycle boundary; a mid-cycle stop
            # would wait out the cycle, so cancel rather than hang shutdown.
            scheduler_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await scheduler_task


def create_app() -> FastAPI:
    application = FastAPI(
        title="preflight402",
        description="One free call before your agent pays.",
        version=__version__,
        lifespan=_lifespan,
    )
    application.include_router(rest.router)
    # Rate-limit BOTH public probe surfaces — /preflight and the mounted /mcp
    # tool — sharing rest's limiter so they debit one bucket. A route-level
    # dependency would miss the mounted MCP sub-app; middleware wraps it.
    application.add_middleware(
        RateLimitMiddleware,
        get_limiter=lambda: rest._limiter,
        get_rate=lambda: rest.settings.rate_limit_per_minute,
        prefixes=("/preflight", "/mcp", "/stats"),
    )
    # Mount the MCP app at /mcp (not "/"), with its internal path at the mount
    # root, so it owns exactly the /mcp subtree. Mounting at "/" would
    # full-match every path and rob the REST routes of FastAPI's 405, trailing-
    # slash redirect, and JSON-404 behavior. The path is baked into the app's
    # routes at build time, so set-build-restore leaves the shared FastMCP
    # settings untouched for the standalone server (which serves at /mcp).
    original_path = mcp.settings.streamable_http_path
    mcp.settings.streamable_http_path = "/"
    try:
        application.mount("/mcp", mcp.streamable_http_app())
    finally:
        mcp.settings.streamable_http_path = original_path
    return application


app = create_app()
