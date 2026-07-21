# preflight402

*One free call before your agent pays. Health, authenticity, and Sybil-filtered
reputation — one verdict.*

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)
![MCP](https://img.shields.io/badge/MCP-io.ironshell%2Fpreflight402-8A2BE2.svg)

A free trust/health preflight for the agent payment economy (x402). It probes
an endpoint before your agent pays and returns one `trust-preview.v1` verdict:
liveness, TLS, the 402 handshake (x402 v1/v2 + MPP detection), price sanity,
continuous uptime history, ERC-8004 identity binding, and **Sybil-filtered**
on-chain reputation — rolled into a **proceed / caution / avoid** recommendation
with plain-language reasons. No wallet, no key, no charge.

**Why filtered reputation matters:** one live agent shows a **99.8/100 average
from 996 reviewers — until Sybil filtering collapses those reviewers into 12
independent funding clusters at 89.7.** Raw reputation is trivially farmed;
this is what the verdict actually scores. (Separately, only ~4% of x402 payees
bind to any ERC-8004 identity at all — so most verdicts run on health, price,
and handshake, and say so honestly.)

## 30-second quickstart

Point any agent at the hosted MCP endpoint — no wallet, no key, no install:

```
https://preflight402.ironshell.io/mcp
```

Or check an endpoint over plain HTTP:

```sh
curl 'https://preflight402.ironshell.io/preflight?url=https://api.example.com/paid'
```

## Guard every payment automatically

[`preflight402-guard`](guard/) turns the service into a payment gate for the
[x402 Python SDK](https://github.com/x402-foundation/x402) — safety becomes
default-on instead of something an agent has to remember to call:

```sh
pip install "preflight402-guard[x402]"
```

```python
from preflight402_guard import Guard
from x402 import x402Client

guard = Guard()          # block "avoid", warn on "caution"
client = x402Client()
guard.install(client)    # every payment is preflighted before signing;
                         # a bad verdict raises PaymentAbortedError
```

It also cross-checks that the payee your client selected matches the endpoint
that was preflighted (the 402's resource URL is attacker-controlled), enforces
an optional `max_price_usd` ceiling against the *actual* selected terms, and
fails **open** by default so your commerce never depends on our uptime. There's
a CLI too: `preflight402-guard check <url>`. See [guard/README.md](guard/README.md).

## Status

Live at [preflight402.ironshell.io](https://preflight402.ironshell.io) and in
the [official MCP registry](https://registry.modelcontextprotocol.io) as
`io.ironshell/preflight402`. The free preflight engine (health + 402 parse +
verdict), continuous probing with uptime history, ERC-8004 binding, and the
Sybil filter are all shipped and serving live. The whole service is **free** —
there is no paywall.

## Use it

### As an MCP tool (no wallet, no key)

The `preflight` tool takes a `url` and returns a `trust-preview.v1` verdict.

Easiest — point any MCP client at the hosted instance, no install:

```
https://preflight402.ironshell.io/mcp   (streamable-http)
```

Or run it yourself over stdio. Claude Code — one line:

```sh
claude mcp add preflight402 -- uvx --from preflight402 preflight402-mcp
```

Claude Desktop — add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "preflight402": {
      "command": "uvx",
      "args": ["--from", "preflight402", "preflight402-mcp"]
    }
  }
}
```

Either way, run it as a hosted HTTP server with
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
├── api/          # REST + MCP server
├── probe/        # async prober, TLS inspection, 402 parsers (x402 v1/v2, MPP)
├── verdict/      # rules -> trust-preview.v1 JSON
├── chains/       # ChainVerifier interface: EVM (Base), SVM (Solana)
├── reputation/   # ERC-8004 subgraph client, endpoint binding, Sybil filter
├── ingest/       # endpoint seed ingesters (Bazaar, x402scan, ...)
├── scheduler/    # probe loop with per-host politeness
└── db/           # SQLite (WAL) schema + queries
guard/            # preflight402-guard: client-side auto-preflight for the x402 SDK
tests/            # unit/ + golden/ (captured 402 responses) + integration/ (marked slow)
deploy/           # Dockerfile + deploy notes
docs/             # trust-preview.v1 schema + API docs (M8)
```
