from fastapi import FastAPI

from preflight402 import __version__

app = FastAPI(
    title="preflight402",
    description="One free call before your agent pays.",
    version=__version__,
)


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok", "version": __version__}
