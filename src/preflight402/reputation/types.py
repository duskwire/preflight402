"""Shared shapes for ERC-8004 binding + reputation (M5).

See ~/A2A/Research3-M5-erc8004.md for the schema these mirror. The Agent0
Base subgraph indexes on-chain agent identities (Agent.agentWallet is the
payment address set on-chain) and parsed off-chain registration files
(x402Support, endpoints, active); reputation is a Feedback entity per agent
(value 0-100, tags, reviewer clientAddress, isRevoked).
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class AgentIdentity:
    """One ERC-8004 agent as indexed by the subgraph."""

    global_id: str  # "<chainId>:<agentId>", the subgraph entity id
    chain_id: int
    agent_id: str  # the ERC-721 tokenId, as a decimal string
    owner: str | None
    agent_wallet: str | None  # lowercased payment address, or None
    total_feedback: int
    # registration-file fields (None when no resolvable file):
    name: str | None = None
    active: bool | None = None
    x402_support: bool | None = None
    endpoints: list[str] = field(default_factory=list)  # advertised endpoint URLs


@dataclass(slots=True)
class ReputationSummary:
    """Raw (un-Sybil-filtered) feedback aggregate for one agent.

    Raw only: the M6 Sybil filter fills sybil_filtered_count/filtered_score.
    'value' scores are 0-100; revoked feedback is excluded from counts.
    """

    raw_feedback_count: int
    distinct_reviewers: int
    average_score: float | None  # mean of non-revoked values, or None if none
    top_tags: list[str] = field(default_factory=list)


@dataclass(slots=True)
class Binding:
    """The result of binding a probed endpoint to an ERC-8004 identity.

    `status` is the honest signal (never conflates failure with no-match):
      "bound"   — a matching agent was found (bound=True).
      "unbound" — the subgraph was queried and returned no agent (bound=False).
      "error"   — the subgraph call FAILED, so we could not determine binding
                  (bound=False, but the API must surface this as unknown, not
                  a real "no such agent").
    resolve_binding() returns None (not a Binding) when it did not check at all
    (feature off / no payTo).
    """

    bound: bool
    status: str = "unbound"  # bound | unbound | error
    agent: AgentIdentity | None = None
    # "agent_wallet" (payTo reverse-match) | "endpoint" (service-URL match) |
    # "agent_wallet+endpoint" (both) — None when unbound.
    method: str | None = None
    confidence: str | None = None  # low | medium | high
    reputation: ReputationSummary | None = None
    # >1 agent claimed the same wallet: ambiguous, all candidates listed.
    ambiguous_agent_ids: list[str] = field(default_factory=list)


UNBOUND = Binding(bound=False, status="unbound")
# The subgraph could not be reached/queried — binding is UNKNOWN, not "no agent".
BINDING_ERROR = Binding(bound=False, status="error")
