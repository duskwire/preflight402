"""Sybil filter (M6): first-funder clustering over a bound agent's reviewers.

Replicates Xiong et al. (arXiv:2606.26028) lazily, per bound agent
(Research4-M6-sybil.md §2, §5): each reviewer's first funder is the earliest
inbound external native transfer (Alchemy, cached permanently in
reviewer_funding); qualifying funders are EOAs/delegated EOAs only; funder
ANCESTRY is explored to a bounded depth (sybil_ancestry_depth generations,
each fact cached permanently) so reviewers are union-found into clusters by
shared funding ROOT, not just direct funder — a one-hop intermediary wallet
per Sybil must not defeat the filter. One vote per cluster.

Hub exclusion: funders in the vendored eth-labels set (CEX/bridge/mixer/
bundler wallets — labels.py) never become cluster edges, because they fund
unrelated users and would collapse everyone who onboarded through them into
one false ring. The cross-agent fan-out heuristic (funder_agent_spread) is
OFF by default (sybil_hub_min_agents=0): reviewer_agents is derived from
attacker-writable feedback, so a farm could whitewash its own funder into a
"hub" by having a few funded wallets review sock agents. Labels are curated
externally and cannot be gamed that way.

Honesty rule: filtered numbers are emitted only at FULL coverage of the
reviewer set and its explored ancestry. A pass still warming the cache
(per-pass lookup budget, RPC failures, deadline) reports status "pending"
with null fields — a partially computed score would silently misrepresent
exactly the agents big enough to matter. When the feedback window itself is
truncated (the subgraph page cap), full coverage of the WINDOW reports
"complete_truncated", never plain "complete".

Never raises: any failure — RPC, sqlite, a corrupt vendored label file —
degrades to "pending" (retried on a later pass); a Sybil failure must never
break the free preflight. (CancelledError still propagates: client
disconnects must cancel the pass.)

Known accepted limitations (documented, not defects): a funder that is a
contract yields independent singletons (the paper's EOA-only rule — a
disperse-contract funding pattern evades clustering); a permanently cached
'none' could in principle capture Alchemy transfer-index lag for a wallet
funded seconds before its first lookup; the RPC concurrency cap is per pass,
not process-global.
"""

from __future__ import annotations

import asyncio
import logging
import sqlite3

from preflight402.config import Settings
from preflight402.db import queries
from preflight402.reputation.alchemy import ALCHEMY_NETWORKS, AlchemyClient
from preflight402.reputation.labels import hub_addresses
from preflight402.reputation.types import SybilResult

logger = logging.getLogger(__name__)


async def sybil_filter(
    conn: sqlite3.Connection,
    chain_id: int,
    agent_global_id: str,
    reviewer_scores: dict[str, list[float]],
    settings: Settings,
    *,
    max_lookups: int | None = None,
    feedback_truncated: bool = False,
) -> SybilResult | None:
    """Run one Sybil-filter pass; returns None when the filter cannot run at
    all (feature off, unsupported chain, or an empty reviewer set).

    max_lookups overrides settings.sybil_max_lookups_per_pass (0 = unlimited)
    — the CLI backfill uses it to crawl a big agent in one go.
    feedback_truncated marks that reviewer_scores came from a page-capped
    feedback read, so a covered pass reports complete_truncated.
    """
    if settings.alchemy_api_key is None or chain_id not in ALCHEMY_NETWORKS:
        return None
    reviewers = {address.lower(): scores for address, scores in reviewer_scores.items()}
    if not reviewers:
        return None
    try:
        return await _run_pass(
            conn, chain_id, agent_global_id, reviewers, settings, max_lookups, feedback_truncated
        )
    except Exception as exc:  # never-raises boundary: sqlite errors, a corrupt
        # vendored label file, anything — the free preflight must still serve.
        # CancelledError is a BaseException and still propagates.
        logger.warning("sybil pass failed (agent %s): %s", agent_global_id, exc)
        return SybilResult(status="pending", reviewers=len(reviewers), resolved=0)


async def _run_pass(
    conn: sqlite3.Connection,
    chain_id: int,
    agent_global_id: str,
    reviewers: dict[str, list[float]],
    settings: Settings,
    max_lookups: int | None,
    feedback_truncated: bool,
) -> SybilResult:
    # The association rows feed the (opt-in) fan-out heuristic across agents.
    queries.record_reviewer_agents(conn, chain_id, list(reviewers), agent_global_id)

    # The 37k-entry hub set gunzips in ~300ms on first use — do that off the
    # event loop; afterwards the functools.cache makes this call free.
    hubs_labeled = await asyncio.to_thread(hub_addresses)

    budget = settings.sybil_max_lookups_per_pass if max_lookups is None else max_lookups
    remaining = budget if budget > 0 else None
    if max_lookups is None and settings.sybil_daily_lookup_cap > 0:
        # Service-path passes share a daily RPC ceiling so a caller forcing
        # cache misses cannot drain the CU budget; operator backfills (an
        # explicit max_lookups) bypass it. At the cap the pass is honestly
        # pending and the cache resumes warming tomorrow.
        today = queries.utcnow_iso()[:10]
        spent_today = sum(queries.counters_since(conn, today).get("sybil_lookups", {}).values())
        headroom = max(0, settings.sybil_daily_lookup_cap - spent_today)
        remaining = headroom if remaining is None else min(remaining, headroom)
    facts: dict[str, dict] = {}
    excluded_hubs: set[str] = set()

    def _pending() -> SybilResult:
        # resolved counts every fact held (reviewers + explored ancestry), so
        # it increases monotonically across passes while any work remains —
        # the CLI backfill uses that to distinguish progress from a stall.
        return SybilResult(status="pending", reviewers=len(reviewers), resolved=len(facts))

    async def resolve_level(addresses: list[str]) -> bool:
        """Fill `facts` for addresses (cache first, then RPC within budget).
        Returns False when any address stays unresolved this pass."""
        nonlocal remaining
        cached = queries.get_reviewer_funding(conn, chain_id, addresses)
        facts.update(cached)
        missing = [address for address in addresses if address not in facts]
        if missing:
            spend = missing if remaining is None else missing[: max(0, remaining)]
            if spend:
                if remaining is not None:
                    remaining -= len(spend)
                queries.bump_counter(conn, "sybil_lookups", by=len(spend))
                facts.update(await _resolve_funding(conn, chain_id, spend, settings))
        return all(address in facts for address in addresses)

    def edge_targets(addresses: set[str]) -> set[str]:
        """Qualifying funder edges out of `addresses`: EOA/delegated-EOA
        funders that are not labeled hubs (and not fan-out hubs, if enabled)."""
        candidates: set[str] = set()
        for address in addresses:
            row = facts.get(address)
            if row and row["status"] == "ok" and row["funder"] and not row["funder_is_contract"]:
                candidates.add(row["funder"])
        hubs = {funder for funder in candidates if funder in hubs_labeled}
        if settings.sybil_hub_min_agents > 0:
            spread = queries.funder_agent_spread(conn, chain_id, list(candidates - hubs))
            hubs |= {
                funder
                for funder, agents in spread.items()
                if agents >= settings.sybil_hub_min_agents
            }
        excluded_hubs.update(hubs)
        return candidates - hubs

    # Generation 1: the reviewers' own funding facts.
    if not await resolve_level(list(reviewers)):
        return _pending()

    # Generations 2..depth: walk funder ancestry so clusters form by shared
    # ROOT, not just direct funder. Every fact is permanent cache, so this
    # converges to "already cached" almost immediately in practice.
    explored: set[str] = set(reviewers)
    frontier = edge_targets(explored) - explored
    generation = 1
    while frontier and generation < settings.sybil_ancestry_depth:
        if not await resolve_level(sorted(frontier)):
            return _pending()
        explored |= frontier
        frontier = edge_targets(frontier) - explored
        generation += 1

    clusters = _cluster(reviewers, facts, explored, excluded_hubs)
    filtered_score, scored_clusters = _score(clusters, reviewers)
    queries.bump_counter(conn, "sybil_passes_complete")
    return SybilResult(
        status="complete_truncated" if feedback_truncated else "complete",
        reviewers=len(reviewers),
        resolved=len(facts),
        filtered_count=len(clusters),
        filtered_score=filtered_score,
        scored_clusters=scored_clusters,
        excluded_hub_funders=len(excluded_hubs),
    )


async def _resolve_funding(
    conn: sqlite3.Connection, chain_id: int, addresses: list[str], settings: Settings
) -> dict[str, dict]:
    """Look up + permanently cache funding facts for `addresses`.

    Returns only the addresses that resolved; failures are simply absent and
    retry on a later pass. A fact is cached only when COMPLETE (funder AND
    its EOA-vs-contract status), so every cached row is fully usable.
    """
    resolved: dict[str, dict] = {}
    # In-pass memo of funder code checks; primed from other reviewers' cached
    # rows so a shared funder costs one eth_getCode ever.
    code_status: dict[str, bool] = {}

    async def resolve_one(client: AlchemyClient, address: str) -> None:
        funding = await client.first_funder(address)
        if funding is None:
            return
        if funding.funder is None:
            queries.put_reviewer_funding(conn, chain_id, address, status="none")
            resolved[address] = {"status": "none", "funder": None, "funder_is_contract": None}
            return
        is_contract = code_status.get(funding.funder)
        if is_contract is None:
            is_contract = queries.funder_code_status(conn, chain_id, funding.funder)
        if is_contract is None:
            is_contract = await client.is_contract(funding.funder)
        if is_contract is None:
            return  # code check failed: retry the whole fact next pass
        code_status[funding.funder] = is_contract
        queries.put_reviewer_funding(
            conn,
            chain_id,
            address,
            status="ok",
            funder=funding.funder,
            funder_is_contract=is_contract,
            tx_hash=funding.tx_hash,
            block_num=funding.block_num,
        )
        resolved[address] = {
            "status": "ok",
            "funder": funding.funder,
            "funder_is_contract": int(is_contract),
        }

    try:
        async with AlchemyClient(
            settings.alchemy_api_key.get_secret_value(),
            chain_id=chain_id,
            timeout_s=settings.alchemy_timeout_s,
            concurrency=settings.sybil_concurrency,
        ) as client:
            # return_exceptions: one child's sqlite hiccup must neither abort
            # its siblings nor orphan them past the client/connection close.
            gather = asyncio.gather(
                *(resolve_one(client, address) for address in addresses),
                return_exceptions=True,
            )
            if settings.sybil_pass_timeout_s > 0:
                async with asyncio.timeout(settings.sybil_pass_timeout_s):
                    await gather
            else:
                await gather
    except TimeoutError:
        logger.info(
            "sybil pass deadline (%ss): %d/%d resolved, rest next pass",
            settings.sybil_pass_timeout_s,
            len(resolved),
            len(addresses),
        )
    return resolved


def _cluster(
    reviewers: dict[str, list[float]],
    facts: dict[str, dict],
    explored: set[str],
    hubs: set[str],
) -> list[list[str]]:
    """Union-find through every qualifying funder edge -> reviewer clusters.

    A reviewer with no qualifying edge (no external funding, contract funder,
    or hub funder) stands as its own singleton — independent by default.
    """
    parent: dict[str, str] = {}

    def find(node: str) -> str:
        parent.setdefault(node, node)
        while parent[node] != node:
            parent[node] = parent[parent[node]]  # path halving
            node = parent[node]
        return node

    for address in explored:
        row = facts.get(address)
        if not row or row["status"] != "ok":
            continue
        funder = row["funder"]
        if funder and not row["funder_is_contract"] and funder not in hubs:
            parent[find(address)] = find(funder)

    groups: dict[str, list[str]] = {}
    for address in reviewers:
        groups.setdefault(find(address), []).append(address)
    return list(groups.values())


def _score(
    clusters: list[list[str]], reviewers: dict[str, list[float]]
) -> tuple[float | None, int]:
    """(mean of per-cluster scores, number of clusters that scored).

    One vote per cluster; a cluster's score is the mean of its member
    reviewers' mean scores (so a member spamming many feedbacks does not
    dominate its own cluster). Clusters whose members carry no parseable
    value are counted in filtered_count but not here — the scored count is
    reported separately because the verdict gates must not treat tag-only
    padding clusters as scoring evidence. Score is (None, 0) when nothing is
    scoreable.
    """
    cluster_scores: list[float] = []
    for members in clusters:
        member_means = [
            sum(scores) / len(scores) for scores in (reviewers[m] for m in members) if scores
        ]
        if member_means:
            cluster_scores.append(sum(member_means) / len(member_means))
    if not cluster_scores:
        return None, 0
    return round(sum(cluster_scores) / len(cluster_scores), 1), len(cluster_scores)
