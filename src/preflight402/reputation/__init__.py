"""ERC-8004 reputation layer (M5): subgraph client + endpoint binding.

resolve_binding() reverse-matches an x402 payTo against on-chain agent
identities on the Agent0 Base subgraph and reads raw feedback. Feature-gated
on PREFLIGHT402_GRAPH_API_KEY; the M6 Sybil filter cleans the raw signal.
"""

from preflight402.reputation.binding import resolve_binding
from preflight402.reputation.types import UNBOUND, AgentIdentity, Binding, ReputationSummary

__all__ = ["UNBOUND", "AgentIdentity", "Binding", "ReputationSummary", "resolve_binding"]
