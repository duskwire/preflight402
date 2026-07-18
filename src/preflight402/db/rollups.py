"""Probe-history aggregation (M3.3): rollup rows + live verdict HistoryStats.

Definitions (pinned by the fixture tests):
- uptime_pct: 100 * (ok=1 AND http_status < 500) / all probes in the window.
  A 402/2xx/404 all mean "the service answered" (a 404 is zombie signal,
  not downtime); 5xx and transport failures are downtime. ok=1 implies
  http_status is present. SSRF-blocked rows (error='blocked') count as
  downtime — an endpoint we refuse to reach is not usable.
- latency percentiles: nearest-rank (the ceil(p/100*n)-th of the sorted
  values) over latency_ms of ok=1 probes whatever their status — latency
  measures responsiveness, uptime measures usability.
- status_counts: HTTP statuses of ok=1 probes plus error labels of ok=0
  probes — one flat JSON object telling the window's whole story.

history_stats() is computed live from probes at verdict time — always
fresh, cheap for a single endpoint. The rollups table is a materialized
snapshot for deep_report/leaderboard reads, refreshed each scheduler cycle
for the endpoints that cycle probed; computed_at dates any staleness (rows
age until their endpoint is probed again — acceptable for paid reads,
never consulted by the verdict path).
"""

from __future__ import annotations

import math
import sqlite3
from collections import Counter
from datetime import datetime
from typing import Any

from preflight402.db import queries
from preflight402.verdict.rules import HistoryStats

PERIODS: dict[str, float] = {"24h": 86400.0, "7d": 7 * 86400.0, "30d": 30 * 86400.0}


def window_rollup(probes: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate one window of probe rows into rollup fields."""
    count = len(probes)
    if count == 0:
        return {
            "probe_count": 0,
            "uptime_pct": None,
            "p50_ms": None,
            "p90_ms": None,
            "p99_ms": None,
            "status_counts": None,
        }
    up = 0
    latencies: list[float] = []
    counts: Counter[str] = Counter()
    for probe in probes:
        if probe["ok"]:
            status = probe["http_status"]
            if status is not None:
                counts[str(status)] += 1
                if status < 500:
                    up += 1
            else:
                # record_probe permits ok=1 with NULL status even though no
                # current writer produces it; keep the key space to HTTP
                # statuses + error labels, and count the row as downtime.
                counts["no-status"] += 1
            if probe["latency_ms"] is not None:
                latencies.append(probe["latency_ms"])
        else:
            counts[probe["error"] or "unknown"] += 1
    latencies.sort()

    def rank(p: float) -> float | None:
        if not latencies:
            return None
        return latencies[min(math.ceil(p / 100 * len(latencies)), len(latencies)) - 1]

    return {
        "probe_count": count,
        "uptime_pct": round(100.0 * up / count, 2),
        "p50_ms": rank(50),
        "p90_ms": rank(90),
        "p99_ms": rank(99),
        "status_counts": dict(counts),
    }


def refresh_rollups(
    conn: sqlite3.Connection, endpoint_ids: list[int], *, now: str | None = None
) -> int:
    """Recompute 24h/7d/30d rollups for the given endpoints; return rows written."""
    now = now or queries.utcnow_iso()
    written = 0
    for endpoint_id in endpoint_ids:
        since_30d = queries.iso_add_seconds(now, -PERIODS["30d"])
        probes = queries.probes_since(conn, endpoint_id, since_30d)
        for period, seconds in PERIODS.items():
            cutoff = queries.iso_add_seconds(now, -seconds)
            fields = window_rollup([p for p in probes if p["probed_at"] >= cutoff])
            queries.upsert_rollup(conn, endpoint_id, period, computed_at=now, **fields)
            written += 1
    return written


def history_stats(
    conn: sqlite3.Connection, endpoint_id: int, *, now: str | None = None
) -> HistoryStats | None:
    """Live HistoryStats for the verdict engine; None below 2 total probes.

    probe_count and observed_days span the FULL probe history (they feed
    rules.py's confidence thresholds); uptime and percentiles come from the
    7d window.
    """
    now = now or queries.utcnow_iso()
    row = conn.execute(
        "SELECT COUNT(*) AS n, MIN(probed_at) AS first FROM probes WHERE endpoint_id = ?",
        (endpoint_id,),
    ).fetchone()
    if row is None or row["n"] < 2:
        return None
    first_dt = datetime.fromisoformat(row["first"])
    now_dt = datetime.fromisoformat(now)
    observed_days = max((now_dt - first_dt).total_seconds() / 86400.0, 0.0)
    since_7d = queries.iso_add_seconds(now, -PERIODS["7d"])
    window = window_rollup(queries.probes_since(conn, endpoint_id, since_7d))
    return HistoryStats(
        probe_count=row["n"],
        observed_days=observed_days,
        uptime_7d=window["uptime_pct"],
        p50_ms=window["p50_ms"],
        p99_ms=window["p99_ms"],
    )
