# preflight402

*One free call before your agent pays. Health, authenticity, and Sybil-filtered
reputation — one verdict, any chain.*

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)
![MCP](https://img.shields.io/badge/MCP-preflight-8A2BE2.svg)

An endpoint health-checker and trust-preview server for the agent payment
economy (x402 on Base + Solana). Free preflight with no wallet required; paid
depth (historical uptime, reseller detection, Sybil-filtered ERC-8004
reputation) via x402 micropayments.

> Working name — final branding at M2.4. The verdict schema name is fixed:
> **`trust-preview.v1`**.

## 30-second quickstart

Point any agent at the hosted MCP endpoint — no wallet, no key, no install:

```
https://preflight402.ironshell.io/mcp
```

Or check an endpoint over plain HTTP:

```sh
curl 'https://preflight402.ironshell.io/preflight?url=https://api.example.com/paid'
```

You get back a `trust-preview.v1` verdict — liveness, TLS, the 402 handshake
with protocol detection (x402 v1/v2, MPP), a USD price estimate, and a
**proceed / caution / avoid** recommendation with reasons.

## Status

Live at [preflight402.ironshell.io](https://preflight402.ironshell.io). The
free preflight engine is complete (M1): probe → 402 parse (x402 v1/v2 + MPP
detection) → verdict → `trust-preview.v1`, over REST and MCP. Paid depth
(history, reseller detection, ERC-8004 reputation) is next.

## Use it

### As an MCP tool (no wallet, no key)

The `preflight` tool takes a `url` and returns a `trust-preview.v1` verdict.

Easiest — point any MCP client at the hosted instance, no install:

```
https://preflight402.ironshell.io/mcp   (streamable-http)
```

Or run it yourself. Until the package is published to PyPI (M2.3), run it
from a local checkout.
Claude Code — one line (point `--directory` at your clone):

```sh
claude mcp add preflight402 -- uv run --directory /path/to/preflight402 preflight402-mcp
```

Claude Desktop — add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "preflight402": {
      "command": "uv",
      "args": ["run", "--directory", "/path/to/preflight402", "preflight402-mcp"]
    }
  }
}
```

Once published, that becomes `uvx --from preflight402 preflight402-mcp` (no clone
needed). Either way, run it as a hosted HTTP server with
`preflight402-mcp --transport streamable-http` (serves the same tool at
`http://<host>:8000/mcp`).

### As a REST call

The hosted instance also serves REST:

```sh
curl 'https://preflight402.ironshell.io/preflight?url=https://api.example.com/paid'
```

Or run it yourself (serves REST + MCP on one port):

```sh
uv run uvicorn preflight402.api.app:app --port 8402
curl 'http://localhost:8402/preflight?url=https://api.example.com/paid'
```

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
