"""ERC-8004 subgraph client (M5.1): read agents + feedback from Agent0.

Queries the Agent0 ERC-8004 subgraphs on The Graph's decentralized gateway
(gateway.thegraph.com/api/<KEY>/subgraphs/id/<ID>). The Base-mainnet subgraph
id is verified live (Research3); per-chain ids let the binding engine sweep
other chains for a wallet advertised cross-chain.

Never raises for network/GraphQL failures: a reputation read that fails must
degrade the preflight to an unpopulated reputation block, not error it. All
public methods return None (or empty) on any failure.
"""

from __future__ import annotations

import contextlib
import logging

import httpx

from preflight402.reputation.types import AgentIdentity, ReputationSummary

logger = logging.getLogger(__name__)

GATEWAY = "https://gateway.thegraph.com/api"

# Agent0 ERC-8004 subgraph ids by chain id (Research3; SDK per-chain map).
# Base first — it is the primary target; the others let us catch an agent
# registered off-Base that advertises a Base payTo (the common multi-chain case).
SUBGRAPH_IDS: dict[int, str] = {
    8453: "43s9hQRurMGjuYnC1r2ZwS6xSQktbFyXMPMqGKUFJojb",  # Base mainnet
}

# Cap feedback fetched per agent for the raw summary. The subgraph caps `first`
# at 1000 anyway; an agent past that under-counts reviewers/scores (raw_feedback
# _count reflects the fetched rows, while AgentIdentity.total_feedback carries
# the true on-chain count). Fine pre-M6 — the Sybil filter is what makes these
# numbers meaningful, and near-zero agents have that much feedback.
FEEDBACK_PAGE = 1000

_AGENT_FIELDS = """
    id chainId agentId owner agentWallet totalFeedback
    registrationFile {
        name active x402Support
        mcpEndpoint a2aEndpoint webEndpoint oasfEndpoint emailEndpoint
    }
"""


class SubgraphClient:
    """Read-only client over the Agent0 ERC-8004 subgraphs."""

    def __init__(self, api_key: str, *, timeout_s: float = 8.0) -> None:
        self._api_key = api_key
        self._timeout_s = timeout_s

    def _url(self, chain_id: int) -> str | None:
        subgraph_id = SUBGRAPH_IDS.get(chain_id)
        if subgraph_id is None:
            return None
        return f"{GATEWAY}/{self._api_key}/subgraphs/id/{subgraph_id}"

    async def _query(self, chain_id: int, query: str, variables: dict) -> dict | None:
        url = self._url(chain_id)
        if url is None:
            return None
        try:
            async with httpx.AsyncClient(timeout=self._timeout_s) as client:
                response = await client.post(url, json={"query": query, "variables": variables})
                response.raise_for_status()
                payload = response.json()
        except Exception as exc:  # never-raises: a reputation read must not
            # break the free preflight. httpx.InvalidURL (malformed key) is not
            # an HTTPError, and json()/decoding can surface odd types — swallow
            # everything, degrade to an unpopulated block. CancelledError is a
            # BaseException and still propagates. httpx exception strings embed
            # the request URL — and the API key is IN the gateway URL, so it
            # must never reach the logs verbatim.
            redacted = str(exc).replace(self._api_key, "<key>")
            logger.warning("subgraph query failed (chain %s): %s", chain_id, redacted)
            return None
        if not isinstance(payload, dict) or payload.get("errors"):
            logger.warning("subgraph returned errors (chain %s): %s", chain_id, payload)
            return None
        data = payload.get("data")
        return data if isinstance(data, dict) else None

    async def agents_by_wallet(self, chain_id: int, wallet: str) -> list[AgentIdentity] | None:
        """Agents whose on-chain agentWallet equals `wallet` (lowercased).

        Returns None when the query FAILED (network/GraphQL/rate-limit error) —
        the caller must NOT treat that as "no agent". An empty list means the
        query succeeded and genuinely matched nothing.
        """
        query = f"""
            query ByWallet($wallet: Bytes!) {{
                agents(where: {{ agentWallet: $wallet }}, first: 20) {{ {_AGENT_FIELDS} }}
            }}
        """
        data = await self._query(chain_id, query, {"wallet": wallet.lower()})
        if data is None:
            return None
        return [_parse_agent(row) for row in data.get("agents", []) if isinstance(row, dict)]

    async def reputation_summary(self, chain_id: int, global_id: str) -> ReputationSummary | None:
        """Aggregate non-revoked feedback for one agent into a raw summary."""
        query = """
            query Feedback($agent: String!, $first: Int!) {
                feedbacks(
                    where: { agent: $agent, isRevoked: false }
                    first: $first
                    orderBy: createdAt
                    orderDirection: desc
                ) { value tag1 tag2 clientAddress }
            }
        """
        data = await self._query(chain_id, query, {"agent": global_id, "first": FEEDBACK_PAGE})
        if data is None:
            return None
        rows = [r for r in data.get("feedbacks", []) if isinstance(r, dict)]
        return _summarize_feedback(rows)


def _parse_agent(row: dict) -> AgentIdentity:
    reg = row.get("registrationFile") or {}
    endpoints = [
        reg[key]
        for key in ("mcpEndpoint", "a2aEndpoint", "webEndpoint", "oasfEndpoint", "emailEndpoint")
        if isinstance(reg.get(key), str) and reg[key]
    ]
    wallet = row.get("agentWallet")
    return AgentIdentity(
        global_id=row.get("id", ""),
        chain_id=int(row["chainId"]) if row.get("chainId") is not None else 0,
        agent_id=str(row.get("agentId", "")),
        owner=row.get("owner"),
        agent_wallet=wallet.lower() if isinstance(wallet, str) else None,
        total_feedback=int(row["totalFeedback"]) if row.get("totalFeedback") else 0,
        name=reg.get("name") if isinstance(reg.get("name"), str) else None,
        active=reg.get("active") if isinstance(reg.get("active"), bool) else None,
        x402_support=reg.get("x402Support") if isinstance(reg.get("x402Support"), bool) else None,
        endpoints=endpoints,
    )


def _summarize_feedback(rows: list[dict]) -> ReputationSummary:
    # `value` is the subgraph's already-normalized BigDecimal score (0-100 range
    # observed live). On-chain the score is fixed-point (value:int128 /
    # 10^valueDecimals) — if this ever reads raw RPC instead of the subgraph, it
    # MUST divide by valueDecimals per entry (Research4-M6-sybil.md §2).
    reviewer_scores: dict[str, list[float]] = {}
    scores: list[float] = []
    tag_counts: dict[str, int] = {}
    for row in rows:
        value: float | None = None
        with contextlib.suppress(TypeError, ValueError, KeyError):
            value = float(row["value"])
        if value is not None:
            scores.append(value)
        client = row.get("clientAddress")
        if isinstance(client, str) and client:
            per_reviewer = reviewer_scores.setdefault(client.lower(), [])
            if value is not None:
                per_reviewer.append(value)
        for tag in (row.get("tag1"), row.get("tag2")):
            if isinstance(tag, str) and tag:
                tag_counts[tag] = tag_counts.get(tag, 0) + 1
    top_tags = [tag for tag, _ in sorted(tag_counts.items(), key=lambda kv: -kv[1])[:5]]
    return ReputationSummary(
        raw_feedback_count=len(rows),
        distinct_reviewers=len(reviewer_scores),
        average_score=round(sum(scores) / len(scores), 1) if scores else None,
        top_tags=top_tags,
        reviewer_scores=reviewer_scores,
    )
