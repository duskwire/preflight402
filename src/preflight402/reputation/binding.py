"""Binding engine (M5.2/5.3): probed endpoint -> ERC-8004 identity + reputation.

Primary mechanism (a single indexed subgraph query): reverse-match the x402
`payTo` against the on-chain Agent.agentWallet. Confidence rises when the
agent's registration file is active and when one of its advertised endpoints
shares a host with the probed URL.

Scope note: only the Base-mainnet subgraph is wired, so this binds agents
registered on Base. An agent registered on another chain that advertises a
Base payTo (common per Research3) needs that chain's subgraph — a documented
extension (add ids to subgraph.SUBGRAPH_IDS and sweep here).

Confidence rubric (Research3):
  wallet match only ............................. low
  + registration file active .................... medium
  + an advertised endpoint host matches the URL . high
Reputation is RAW (un-Sybil-filtered): manipulable, so it populates the block
and adds an honest reason but does not move the recommendation until M6.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from preflight402.config import Settings
from preflight402.reputation.subgraph import SubgraphClient
from preflight402.reputation.types import UNBOUND, AgentIdentity, Binding

BASE_CHAIN_ID = 8453


async def resolve_binding(
    pay_to: str | None, service_url: str, settings: Settings
) -> Binding | None:
    """Bind a probed endpoint to an ERC-8004 identity.

    Returns None when we did NOT check — the feature is off (no graph_api_key)
    or there is no payTo to bind — so the reputation block stays all-null.
    Returns UNBOUND (bound=False) when we checked but no agent matched, and a
    populated Binding on a hit. Never raises: a subgraph failure degrades to
    UNBOUND, not an error.
    """
    if settings.graph_api_key is None or not pay_to:
        return None
    client = SubgraphClient(
        settings.graph_api_key.get_secret_value(), timeout_s=settings.graph_timeout_s
    )
    candidates = await client.agents_by_wallet(BASE_CHAIN_ID, pay_to)
    if not candidates:
        return UNBOUND

    host = _host(service_url)
    chosen, endpoint_match = _choose(candidates, host)
    method = "agent_wallet+endpoint" if endpoint_match else "agent_wallet"
    confidence = _confidence(chosen, endpoint_match)
    reputation = None
    if chosen.total_feedback > 0:
        reputation = await client.reputation_summary(BASE_CHAIN_ID, chosen.global_id)

    return Binding(
        bound=True,
        agent=chosen,
        method=method,
        confidence=confidence,
        reputation=reputation,
        ambiguous_agent_ids=[c.agent_id for c in candidates] if len(candidates) > 1 else [],
    )


def _choose(candidates: list[AgentIdentity], host: str | None) -> tuple[AgentIdentity, bool]:
    """Pick the agent to bind and whether its endpoints match the probed host.

    When several agents share a wallet (ambiguous), prefer one whose endpoint
    host matches, else the most-reviewed — but the ambiguity is still recorded.
    """
    endpoint_matches = [c for c in candidates if host and _endpoint_host_match(c, host)]
    if endpoint_matches:
        return max(endpoint_matches, key=lambda c: c.total_feedback), True
    return max(candidates, key=lambda c: c.total_feedback), False


def _confidence(agent: AgentIdentity, endpoint_match: bool) -> str:
    if endpoint_match:
        return "high"
    if agent.active:
        return "medium"
    return "low"


def _endpoint_host_match(agent: AgentIdentity, host: str) -> bool:
    return any(_host(endpoint) == host for endpoint in agent.endpoints)


def _host(url: str | None) -> str | None:
    if not url:
        return None
    try:
        return (urlsplit(url).hostname or "").lower() or None
    except ValueError:
        return None
