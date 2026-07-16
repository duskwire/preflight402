# Build from the repo root:  docker build -f deploy/Dockerfile -t preflight402 .
FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim AS builder

WORKDIR /app
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy

COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-install-project --no-dev

COPY . .
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev

FROM python:3.12-slim-bookworm

RUN groupadd --system app && useradd --system --gid app app
WORKDIR /app
COPY --from=builder --chown=app:app /app /app
# Create the data dir owned by app IN THE IMAGE so a named volume mounted at
# /data inherits app ownership (Docker seeds a fresh named volume from the
# image path). Without this the volume is root-owned and every /preflight
# 500s on "unable to open database file" while /healthz still passes.
RUN mkdir -p /data && chown app:app /data
ENV PATH="/app/.venv/bin:$PATH" \
    PREFLIGHT402_DB_PATH=/data/preflight402.db
USER app
VOLUME ["/data"]

EXPOSE 8402
CMD ["uvicorn", "preflight402.api.app:app", "--host", "0.0.0.0", "--port", "8402"]
