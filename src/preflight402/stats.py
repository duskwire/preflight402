"""The weekly dashboard (build-plan M3): one stats document from the DB.

Served as GET /stats (api/rest.py, briefly cached) and printable via
`python -m preflight402.stats` on a box with the database. The shape is
stats.v0 and additive-only: paid-tier and reputation fields ship as nulls
until M4/M5 fill them, so consumers can rely on the keys today.

Definitions:
- dead_now / zombie_now: endpoints whose latest 3 probes within the 7d
  window are all transport failures (dead) or all answered-but-not-402
  (zombie) — the same streak thresholds the verdict heuristics use.
- serving_402_pct: of endpoints probed in the last 7d, the share whose
  most recent probe returned a 402.
- Latency percentiles: nearest-rank over ok-probe latencies in the window.
"""

from __future__ import annotations

import math
import sqlite3
from typing import Any

from preflight402.db import queries
from preflight402.db.rollups import PERIODS
from preflight402.verdict.rules import DEAD_CONSECUTIVE_FAILS, ZOMBIE_CONSECUTIVE_NON402

SCHEMA = "stats.v0"


def compute_stats(conn: sqlite3.Connection, *, now: str | None = None) -> dict[str, Any]:
    """Assemble the dashboard document. Read-only; one pass per section."""
    now = now or queries.utcnow_iso()
    cutoff_24h = queries.iso_add_seconds(now, -PERIODS["24h"])
    cutoff_7d = queries.iso_add_seconds(now, -PERIODS["7d"])

    catalog = _catalog(conn, cutoff_7d)
    probing = _probing(conn, cutoff_24h, cutoff_7d, catalog["enabled"])
    health = _health(conn, cutoff_7d, probing["endpoints_probed_7d"])
    usage = _usage(conn, cutoff_7d)

    return {
        "schema": SCHEMA,
        "generated_at": now,
        "catalog": catalog,
        "probing": probing,
        "health": health,
        "usage": usage,
        # M4 fills these from settlement records; M5 fills reputation.
        "paid": {"settlements_7d": None, "unique_payers_7d": None, "revenue_usd_7d": None},
        "reputation": {"erc8004_bound_pct": None},
    }


def _catalog(conn: sqlite3.Connection, cutoff_7d: str) -> dict[str, Any]:
    row = conn.execute(
        "SELECT COUNT(*) AS total,"
        " SUM(enabled) AS enabled,"
        " COUNT(DISTINCT host) AS hosts,"
        " SUM(CASE WHEN first_seen_at >= ? THEN 1 ELSE 0 END) AS new_7d"
        " FROM endpoints",
        (cutoff_7d,),
    ).fetchone()
    by_source: dict[str, int] = {}
    for source_row in conn.execute("SELECT sources FROM endpoints"):
        for source in queries._to_dict(source_row)["sources"]:
            by_source[source] = by_source.get(source, 0) + 1
    return {
        "endpoints": row["total"],
        "enabled": row["enabled"] or 0,
        "hosts": row["hosts"],
        "new_7d": row["new_7d"] or 0,
        "by_source": dict(sorted(by_source.items(), key=lambda kv: -kv[1])),
    }


def _probing(
    conn: sqlite3.Connection, cutoff_24h: str, cutoff_7d: str, enabled: int
) -> dict[str, Any]:
    row = conn.execute(
        "SELECT COUNT(*) AS probes_7d,"
        " SUM(CASE WHEN probed_at >= ? THEN 1 ELSE 0 END) AS probes_24h,"
        " COUNT(DISTINCT endpoint_id) AS endpoints_probed_7d,"
        " SUM(CASE WHEN is_402 = 1 THEN 1 ELSE 0 END) AS answered_402,"
        " SUM(CASE WHEN ok = 1 AND is_402 = 0 THEN 1 ELSE 0 END) AS answered_other,"
        " SUM(CASE WHEN ok = 0 AND error = 'blocked' THEN 1 ELSE 0 END) AS blocked,"
        " SUM(CASE WHEN ok = 0 AND error != 'blocked' THEN 1 ELSE 0 END) AS transport_error"
        " FROM probes WHERE probed_at >= ?",
        (cutoff_24h, cutoff_7d),
    ).fetchone()
    latencies = sorted(
        value
        for (value,) in conn.execute(
            "SELECT latency_ms FROM probes"
            " WHERE probed_at >= ? AND ok = 1 AND latency_ms IS NOT NULL",
            (cutoff_7d,),
        )
    )

    def rank(p: float) -> float | None:
        if not latencies:
            return None
        return round(latencies[min(math.ceil(p / 100 * len(latencies)), len(latencies)) - 1], 1)

    probed = row["endpoints_probed_7d"]
    return {
        "probes_24h": row["probes_24h"] or 0,
        "probes_7d": row["probes_7d"],
        "endpoints_probed_7d": probed,
        "coverage_7d_pct": round(100.0 * probed / enabled, 2) if enabled else None,
        "outcomes_7d": {
            "answered_402": row["answered_402"] or 0,
            "answered_other": row["answered_other"] or 0,
            "transport_error": row["transport_error"] or 0,
            "blocked": row["blocked"] or 0,
        },
        "latency_ms_7d": {"p50": rank(50), "p90": rank(90)},
    }


def _health(conn: sqlite3.Connection, cutoff_7d: str, probed_7d: int) -> dict[str, Any]:
    # Latest-N streaks per endpoint over the 7d window, in one window scan —
    # the same thresholds as the verdict heuristics (rules.py).
    streak_n = max(DEAD_CONSECUTIVE_FAILS, ZOMBIE_CONSECUTIVE_NON402)
    row = conn.execute(
        """
        WITH recent AS (
            SELECT endpoint_id, ok, http_status, is_402,
                   ROW_NUMBER() OVER (
                       PARTITION BY endpoint_id ORDER BY probed_at DESC, id DESC
                   ) AS rn
            FROM probes WHERE probed_at >= ?
        ),
        latest AS (
            SELECT endpoint_id,
                   MAX(CASE WHEN rn = 1 THEN is_402 END) AS latest_is_402
            FROM recent GROUP BY endpoint_id
        ),
        streaks AS (
            SELECT endpoint_id,
                   COUNT(*) AS n,
                   SUM(ok) AS oks,
                   SUM(CASE WHEN ok = 1 AND http_status IS NOT NULL
                            AND http_status != 402 THEN 1 ELSE 0 END) AS non402
            FROM recent WHERE rn <= ? GROUP BY endpoint_id
        )
        SELECT
            (SELECT SUM(latest_is_402) FROM latest) AS serving_402,
            SUM(CASE WHEN n >= ? AND oks = 0 THEN 1 ELSE 0 END) AS dead_now,
            SUM(CASE WHEN n >= ? AND non402 = n THEN 1 ELSE 0 END) AS zombie_now
        FROM streaks
        """,
        (cutoff_7d, streak_n, DEAD_CONSECUTIVE_FAILS, ZOMBIE_CONSECUTIVE_NON402),
    ).fetchone()
    serving = row["serving_402"] or 0
    return {
        "serving_402_pct": round(100.0 * serving / probed_7d, 2) if probed_7d else None,
        "dead_now": row["dead_now"] or 0,
        "zombie_now": row["zombie_now"] or 0,
    }


def _usage(conn: sqlite3.Connection, cutoff_7d: str) -> dict[str, Any]:
    by_day = queries.counters_since(conn, cutoff_7d[:10])
    calls = by_day.get("preflight_calls", {})
    hits = by_day.get("preflight_cache_hits", {})
    return {
        "preflight_calls_7d": sum(calls.values()),
        "preflight_cache_hits_7d": sum(hits.values()),
        "preflight_calls_by_day": calls,
        # M6: how much the Sybil filter is actually running (RPC lookups are
        # the Alchemy budget; complete passes are filtered verdicts served).
        "sybil_lookups_7d": sum(by_day.get("sybil_lookups", {}).values()),
        "sybil_passes_complete_7d": sum(by_day.get("sybil_passes_complete", {}).values()),
    }


def render_text(document: dict[str, Any]) -> str:
    """Human-readable rendering for the CLI."""
    catalog = document["catalog"]
    probing = document["probing"]
    health = document["health"]
    usage = document["usage"]
    sources = ", ".join(f"{k}: {v}" for k, v in catalog["by_source"].items()) or "none"
    lines = [
        f"preflight402 dashboard — {document['generated_at']}",
        "",
        f"catalog    {catalog['endpoints']} endpoints ({catalog['enabled']} enabled)"
        f" on {catalog['hosts']} hosts, {catalog['new_7d']} new in 7d",
        f"           by source: {sources}",
        f"probing    {probing['probes_24h']} probes/24h, {probing['probes_7d']}/7d"
        f" over {probing['endpoints_probed_7d']} endpoints"
        f" ({probing['coverage_7d_pct']}% of catalog)"
        if probing["coverage_7d_pct"] is not None
        else f"probing    {probing['probes_24h']} probes/24h, {probing['probes_7d']}/7d",
        f"           outcomes 7d: {probing['outcomes_7d']}",
        f"           latency 7d: p50={probing['latency_ms_7d']['p50']}ms"
        f" p90={probing['latency_ms_7d']['p90']}ms",
        f"health     serving-402: {health['serving_402_pct']}%"
        f" | dead now: {health['dead_now']} | zombie now: {health['zombie_now']}",
        f"usage      {usage['preflight_calls_7d']} preflight calls/7d"
        f" ({usage['preflight_cache_hits_7d']} cache hits)",
        "paid       (M4) settlements/payers/revenue: not yet",
        "reputation (M5) erc8004 bound: not yet",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    import argparse
    import json

    from preflight402.config import get_settings
    from preflight402.db import connect, migrate

    parser = argparse.ArgumentParser(prog="preflight402.stats", description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit the raw stats.v0 JSON")
    args = parser.parse_args(argv)

    conn = connect(get_settings().db_path)
    try:
        migrate(conn)
        document = compute_stats(conn)
    finally:
        conn.close()
    print(json.dumps(document, indent=2) if args.json else render_text(document))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
