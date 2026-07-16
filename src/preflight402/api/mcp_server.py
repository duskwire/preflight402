"""MCP server exposing the free `preflight` tool.

Runs over stdio (for Claude Desktop / Claude Code local config) and
streamable-http (for a hosted URL). Both transports — and the REST API —
call service.get_preflight(), so the 5-minute cache and single-flight
coalescing span every surface in the process.

Run:
    preflight402-mcp                      # stdio (default)
    preflight402-mcp --transport streamable-http
"""

from __future__ import annotations

import argparse
from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from pydantic import Field
from starlette.applications import Starlette

from preflight402.config import get_settings
from preflight402.db import queries
from preflight402.probe.guard import BlockedTargetError
from preflight402.service import get_preflight

settings = get_settings()

mcp = FastMCP(
    "preflight402",
    instructions=(
        "Trust-preview for x402/MPP payment endpoints. Call `preflight` with a"
        " URL before your agent pays it: one free check of liveness, TLS, the"
        " 402 handshake, price sanity, and a proceed/caution/avoid verdict."
    ),
    # A trust check holds no per-client state, so stateless HTTP scales freely.
    stateless_http=True,
    json_response=True,
    # DNS-rebinding protection guards localhost servers with ambient trust;
    # this is a public API served under arbitrary hosts/domains with no
    # ambient auth, where the default localhost-only allowlist would 421
    # every real deployment request.
    transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
)


@mcp.tool(title="x402 Preflight Trust Check")
async def preflight(
    url: Annotated[
        str,
        Field(description="Absolute https URL of the x402 or MPP payment endpoint to check"),
    ],
) -> dict[str, Any]:
    """One free call before your agent pays.

    Probes the URL (no wallet, payment, or auth) and returns a
    trust-preview.v1 verdict: liveness and latency, TLS validity, the 402
    payment handshake with protocol detection (x402 v1/v2, MPP-capable),
    detected networks/asset/price with a USD estimate, and a
    proceed / caution / avoid recommendation with human-readable reasons.
    Paid-tier fields (uptime history, reseller analysis, ERC-8004 reputation)
    are present but null on the free tier.
    """
    try:
        result = await get_preflight(url, settings)
    except BlockedTargetError as exc:
        raise ValueError(str(exc)) from None
    except queries.InvalidURLError as exc:
        # A bad URL is a caller error, not a server fault — surface the reason.
        raise ValueError(f"invalid url: {exc}") from None
    return result.document


def streamable_http_app() -> Starlette:
    """The MCP streamable-http ASGI app, for mounting under a shared server."""
    return mcp.streamable_http_app()


def main() -> None:
    parser = argparse.ArgumentParser(prog="preflight402-mcp", description=__doc__)
    parser.add_argument(
        "--transport",
        choices=["stdio", "streamable-http"],
        default="stdio",
        help="stdio for local clients (default); streamable-http for a hosted URL",
    )
    parser.add_argument("--host", default=mcp.settings.host, help="streamable-http bind host")
    parser.add_argument(
        "--port", type=int, default=mcp.settings.port, help="streamable-http bind port"
    )
    args = parser.parse_args()
    mcp.settings.host = args.host
    mcp.settings.port = args.port
    mcp.run(transport=args.transport)


if __name__ == "__main__":
    main()
