"""Sybil-filter backfill/inspect CLI (M6).

    python -m preflight402.reputation --agent 8453:1380 [--batch 100] [--once]

Fetches the agent's feedback from the subgraph, then runs budgeted
sybil_filter passes against the local DB until the funding cache covers the
whole reviewer set, printing progress per pass. Ends with the same filtered
numbers a preflight would serve, as JSON on stdout — use it to warm the cache
for agents too big to resolve inside one request's budget (Captain Dackie:
~1000 reviewers ≈ 2000 RPC calls ≈ minutes).

Needs PREFLIGHT402_GRAPH_API_KEY (feedback read) and
PREFLIGHT402_ALCHEMY_API_KEY (funding lookups); respects PREFLIGHT402_DB_PATH.
"""

from __future__ import annotations

import argparse
import asyncio
import dataclasses
import json
import sys

from preflight402.config import get_settings
from preflight402.db import connect, migrate
from preflight402.reputation.subgraph import FEEDBACK_PAGE, SubgraphClient
from preflight402.reputation.sybil import sybil_filter


async def run(agent_global_id: str, batch: int, once: bool) -> int:
    settings = get_settings()
    if settings.graph_api_key is None:
        print("PREFLIGHT402_GRAPH_API_KEY is not set (needed to read feedback)", file=sys.stderr)
        return 2
    if settings.alchemy_api_key is None:
        print("PREFLIGHT402_ALCHEMY_API_KEY is not set (the Sybil filter is off)", file=sys.stderr)
        return 2
    try:
        chain_id = int(agent_global_id.split(":", 1)[0])
    except ValueError:
        print(f"--agent must be '<chainId>:<agentId>', got {agent_global_id!r}", file=sys.stderr)
        return 2

    client = SubgraphClient(
        settings.graph_api_key.get_secret_value(), timeout_s=settings.graph_timeout_s
    )
    summary = await client.reputation_summary(chain_id, agent_global_id)
    if summary is None:
        print("subgraph feedback query failed", file=sys.stderr)
        return 1
    print(
        f"agent {agent_global_id}: {summary.raw_feedback_count} feedback rows, "
        f"{summary.distinct_reviewers} distinct reviewers, raw avg {summary.average_score}",
        file=sys.stderr,
    )

    # The interactive pass budget/deadline exist to protect a live request;
    # a deliberate backfill wants steady batches with no wall-clock ceiling.
    settings = settings.model_copy(update={"sybil_pass_timeout_s": 0.0})

    conn = connect(settings.db_path)
    try:
        migrate(conn)
        truncated = summary.raw_feedback_count >= FEEDBACK_PAGE
        previous_resolved = -1
        while True:
            result = await sybil_filter(
                conn,
                chain_id,
                agent_global_id,
                summary.reviewer_scores,
                settings,
                max_lookups=batch,
                feedback_truncated=truncated,
            )
            if result is None:
                print("nothing to filter (no reviewers)", file=sys.stderr)
                return 1
            print(
                f"  pass: {result.resolved} facts held ({result.reviewers} reviewers)",
                file=sys.stderr,
            )
            if result.status.startswith("complete") or once:
                break
            if result.resolved == previous_resolved:
                print("no progress (RPC failing persistently?) — aborting", file=sys.stderr)
                break
            previous_resolved = result.resolved
    finally:
        conn.close()

    document = dataclasses.asdict(result)
    document["agent"] = agent_global_id
    document["raw_feedback_count"] = summary.raw_feedback_count
    document["raw_average_score"] = summary.average_score
    print(json.dumps(document, indent=2))
    return 0 if result.status.startswith("complete") else 1


def main() -> None:
    parser = argparse.ArgumentParser(prog="python -m preflight402.reputation", description=__doc__)
    parser.add_argument("--agent", required=True, help="agent global id, e.g. 8453:1380")
    parser.add_argument(
        "--batch", type=int, default=100, help="funding lookups per pass (default 100)"
    )
    parser.add_argument(
        "--once", action="store_true", help="run a single pass instead of looping to completion"
    )
    args = parser.parse_args()
    raise SystemExit(asyncio.run(run(args.agent, args.batch, args.once)))


if __name__ == "__main__":
    main()
