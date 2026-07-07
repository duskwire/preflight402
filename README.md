# preflight402

*One free call before your agent pays. Health, authenticity, and Sybil-filtered
reputation — one verdict, any chain.*

> Working name — final branding decided at M2. The verdict schema name is fixed:
> **`trust-preview.v1`**.

An endpoint health-checker and trust-preview server for the agent payment
economy (x402 on Base + Solana). Free preflight with no wallet required; paid
depth (historical uptime, reseller detection, Sybil-filtered ERC-8004
reputation) via x402 micropayments.

## Status

M0 — scaffold. Nothing to see here yet.

## Development

Requires [uv](https://docs.astral.sh/uv/).

```sh
uv sync                                        # create venv + install deps
uv run uvicorn preflight402.api.rest:app       # serve on :8000
curl http://localhost:8000/healthz             # {"status":"ok","version":"0.1.0"}

uv run pytest                                  # tests
uv run ruff check .                            # lint
uv run ruff format --check .                   # formatting
```

## Layout

```
src/preflight402/
├── api/          # REST + MCP server + x402 paywall
├── probe/        # async prober, TLS inspection, 402 parsers (x402 v1/v2, MPP)
├── verdict/      # rules -> trust-preview.v1 JSON
├── chains/       # ChainVerifier interface: EVM (Base), SVM (Solana)
├── reputation/   # ERC-8004 subgraph client, endpoint binding, Sybil filter
├── ingest/       # endpoint seed ingesters (Bazaar, x402scan, ...)
├── scheduler/    # probe loop with per-host politeness
└── db/           # SQLite (WAL) schema + queries
tests/            # unit/ + golden/ (captured 402 responses) + integration/ (marked slow)
deploy/           # Dockerfile + deploy notes
docs/             # trust-preview.v1 schema + API docs (M8)
```
