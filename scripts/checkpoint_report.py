"""Reproduce the M3 continuous-probing checkpoint report from a prober DB.

Answers "what fraction of listed x402 endpoints actually serve a valid 402?"
from real probe history, and prints the methodology alongside the numbers so
the figure can be audited rather than taken on faith.

    PREFLIGHT402_DB_PATH=/var/lib/preflight402/preflight402.db \
        python scripts/checkpoint_report.py [--days 7] [--min-probes 3] [--json]

Why it is not one GROUP BY: the probes table reaches millions of rows and its
index leads with endpoint_id, so a window-filtered group-by full-scans. The
per-endpoint 7d aggregates already live in `rollups` (written per cycle), so
classification reads those. But rollups only qualify at >= min_probes, and
per-host politeness windowing spreads a mega-host's probes so thinly that its
individual endpoints never reach that bar — so those hosts drop out of the
rollup sample entirely. Ignoring that undercounts the rot ~3x (measured). This
script therefore classifies the rollup sample AND separately measures every
host whose listed endpoints exceed the rollup coverage, then reports the union
with its sampling caveats.
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
from dataclasses import dataclass, field


@dataclass
class HostSample:
    host: str
    listed: int
    probed: int
    serving_402: int


@dataclass
class Report:
    catalog: int
    probes_total: int
    window_start: str | None
    window_end: str | None
    days_observed: float
    endpoints_probed_window: int
    classified: int = 0
    classified_alive: int = 0
    classified_zombie: int = 0
    classified_dead: int = 0
    hosts_classified: int = 0
    hosts_alive: int = 0
    undersampled: list[HostSample] = field(default_factory=list)

    @property
    def undersampled_listed(self) -> int:
        return sum(h.listed for h in self.undersampled)

    @property
    def undersampled_probed(self) -> int:
        return sum(h.probed for h in self.undersampled)

    @property
    def undersampled_alive(self) -> int:
        return sum(h.serving_402 for h in self.undersampled)

    @property
    def usable(self) -> int:
        """Endpoints observed serving a valid 402 (the conservative numerator:
        an under-sampled host contributes only what we actually saw serve)."""
        return self.classified_alive + self.undersampled_alive

    @property
    def accounted(self) -> int:
        return self.classified + self.undersampled_listed

    @property
    def not_usable_pct(self) -> float:
        return 100.0 * (1.0 - self.usable / self.accounted) if self.accounted else 0.0


def _classify(counts: dict) -> str:
    """serving_402 | zombie (answered, never a 402) | dead (never answered)."""
    served = int(counts.get("402", 0)) > 0
    answered = sum(int(v) for k, v in counts.items() if str(k).isdigit())
    if served:
        return "serving_402"
    return "zombie" if answered > 0 else "dead"


def build_report(conn: sqlite3.Connection, *, days: int, min_probes: int) -> Report:
    conn.row_factory = sqlite3.Row
    totals = conn.execute(
        "SELECT COUNT(*) n, MIN(probed_at) first, MAX(probed_at) last FROM probes"
    ).fetchone()
    catalog = conn.execute("SELECT COUNT(*) n FROM endpoints").fetchone()["n"]
    window = f"-{days} days"
    probed_window = conn.execute(
        "SELECT COUNT(DISTINCT endpoint_id) n FROM probes WHERE probed_at > datetime('now', ?)",
        (window,),
    ).fetchone()["n"]
    days_observed = 0.0
    if totals["first"] and totals["last"]:
        span = conn.execute(
            "SELECT (julianday(?) - julianday(?)) d", (totals["last"], totals["first"])
        ).fetchone()["d"]
        days_observed = round(span or 0.0, 1)

    report = Report(
        catalog=catalog,
        probes_total=totals["n"],
        window_start=totals["first"],
        window_end=totals["last"],
        days_observed=days_observed,
        endpoints_probed_window=probed_window,
    )

    # --- classify the rollup sample, and tally per host -----------------------
    per_host: dict[str, dict[str, int]] = {}
    rows = conn.execute(
        "SELECT e.host host, r.status_counts counts FROM rollups r"
        " JOIN endpoints e ON e.id = r.endpoint_id"
        " WHERE r.period = '7d' AND r.probe_count >= ?",
        (min_probes,),
    ).fetchall()
    for row in rows:
        counts = json.loads(row["counts"]) if row["counts"] else {}
        verdict = _classify(counts)
        report.classified += 1
        if verdict == "serving_402":
            report.classified_alive += 1
        elif verdict == "zombie":
            report.classified_zombie += 1
        else:
            report.classified_dead += 1
        tally = per_host.setdefault(row["host"], {"n": 0, "alive": 0})
        tally["n"] += 1
        tally["alive"] += 1 if verdict == "serving_402" else 0
    report.hosts_classified = len(per_host)
    report.hosts_alive = sum(1 for t in per_host.values() if t["alive"] > 0)

    # --- hosts the rollup sample under-covers (the mega-host blind spot) ------
    listed_by_host = {
        row["host"]: row["n"]
        for row in conn.execute("SELECT host, COUNT(*) n FROM endpoints GROUP BY host")
    }
    for host, listed in sorted(listed_by_host.items(), key=lambda kv: -kv[1]):
        covered = per_host.get(host, {}).get("n", 0)
        if covered >= listed:
            continue  # fully represented in the classified sample
        # Measure this host directly over the window (host-filtered: uses the
        # host index, so this stays cheap even on a huge probes table).
        row = conn.execute(
            "SELECT COUNT(DISTINCT p.endpoint_id) probed,"
            " SUM(CASE WHEN p.is_402 = 1 THEN 1 ELSE 0 END) n402"
            " FROM probes p JOIN endpoints e ON e.id = p.endpoint_id"
            " WHERE e.host = ? AND p.probed_at > datetime('now', ?)",
            (host, window),
        ).fetchone()
        probed = row["probed"] or 0
        if not probed:
            continue
        # Endpoints of this host seen serving a valid 402 at least once.
        alive = conn.execute(
            "SELECT COUNT(*) n FROM (SELECT p.endpoint_id FROM probes p"
            " JOIN endpoints e ON e.id = p.endpoint_id"
            " WHERE e.host = ? AND p.probed_at > datetime('now', ?)"
            " GROUP BY p.endpoint_id HAVING SUM(p.is_402) > 0)",
            (host, window),
        ).fetchone()["n"]
        report.undersampled.append(
            HostSample(host=host, listed=listed - covered, probed=probed, serving_402=alive)
        )
    return report


def render(report: Report) -> str:
    lines = [
        "preflight402 — M3 continuous-probing checkpoint",
        "",
        f"observation window : {report.window_start} -> {report.window_end}"
        f"  ({report.days_observed} days)",
        f"probes recorded    : {report.probes_total:,}",
        f"catalog            : {report.catalog:,} listed endpoints",
        f"endpoints probed   : {report.endpoints_probed_window:,} distinct (in-window)",
        "",
        f"A. rollup-classified sample ({report.classified:,} endpoints,"
        f" {report.hosts_classified:,} hosts)",
        f"     serving a valid 402 : {report.classified_alive:,}"
        f" ({_pct(report.classified_alive, report.classified)})",
        f"     zombie (no 402)     : {report.classified_zombie:,}"
        f" ({_pct(report.classified_zombie, report.classified)})",
        f"     dead (no answer)    : {report.classified_dead:,}"
        f" ({_pct(report.classified_dead, report.classified)})",
        f"     hosts serving >=1 valid 402: {report.hosts_alive:,}"
        f" ({_pct(report.hosts_alive, report.hosts_classified)})",
        "",
        f"B. hosts the sample under-covers ({len(report.undersampled)} hosts,"
        f" {report.undersampled_listed:,} endpoints)",
    ]
    for host in report.undersampled[:10]:
        lines.append(
            f"     {host.host}: {host.listed:,} listed, {host.probed:,} probed,"
            f" {host.serving_402:,} serving a valid 402"
        )
    lines += [
        "",
        f"CATALOG-WIDE ({report.accounted:,} endpoints accounted for)",
        f"     serving a valid 402 : {report.usable:,} ({_pct(report.usable, report.accounted)})",
        f"     NOT usable          : {report.accounted - report.usable:,}"
        f" ({report.not_usable_pct:.1f}%)",
        "",
        "Caveats this figure must be published with:",
        "  - Scope is REGISTRY LISTINGS (Bazaar + agentic.market + x402-list), not all of x402.",
        "  - Under-covered hosts are sampled, not exhaustive: their unprobed remainder is",
        "    credited as not-usable at the rate observed across the sampled portion.",
        "  - 'zombie' = answered every probe but never with a valid 402 challenge. The prober",
        "    retries a GET that 405s with a POST, so POST-only endpoints are not miscounted;",
        "    auth-gated or template (:param) listings can still land here.",
    ]
    return "\n".join(lines)


def _pct(part: int, whole: int) -> str:
    return f"{(100.0 * part / whole):.1f}%" if whole else "n/a"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", default=os.environ.get("PREFLIGHT402_DB_PATH", "preflight402.db"))
    parser.add_argument("--days", type=int, default=7)
    parser.add_argument("--min-probes", type=int, default=3)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    conn = sqlite3.connect(args.db)
    try:
        report = build_report(conn, days=args.days, min_probes=args.min_probes)
    finally:
        conn.close()

    if args.json:
        payload = {k: v for k, v in report.__dict__.items() if k != "undersampled"}
        payload["undersampled"] = [h.__dict__ for h in report.undersampled]
        payload["usable"] = report.usable
        payload["accounted"] = report.accounted
        payload["not_usable_pct"] = round(report.not_usable_pct, 1)
        print(json.dumps(payload, indent=2))
    else:
        print(render(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
