"""Rollups + HistoryStats: aggregation math pinned by hand-computed fixtures."""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from preflight402.db import connect, migrate, queries, rollups
from preflight402.probe.prober import ProbeResult
from preflight402.probe.tls import TLSInfo

NOW = "2026-07-17T12:00:00.000Z"

GOOD_TLS = TLSInfo(valid=True, expires_at="2027-01-01T00:00:00.000Z", issuer="Let's Encrypt")
USDC_BASE = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"


def _payment_probe(url: str) -> ProbeResult:
    payload = {
        "x402Version": 2,
        "resource": {"url": url},
        "accepts": [
            {
                "scheme": "exact",
                "network": "eip155:8453",
                "amount": "10000",
                "asset": USDC_BASE,
                "payTo": "0x" + "ab" * 20,
                "maxTimeoutSeconds": 300,
            }
        ],
    }
    headers = {"payment-required": base64.b64encode(json.dumps(payload).encode()).decode()}
    return ProbeResult(
        url=url,
        ok=True,
        http_status=402,
        headers=headers,
        body="{}",
        latency_ms=180.0,
        tls=GOOD_TLS,
    )


@pytest.fixture()
def db(tmp_path: Path):
    conn = connect(tmp_path / "rollups.db")
    migrate(conn)
    yield conn
    conn.close()


def hours_ago(hours: float) -> str:
    return queries.iso_add_seconds(NOW, -hours * 3600)


def seed_fixture(db) -> int:
    """The hand-computed window from the M3.3 design note.

    10 probes going back from NOW:
    - 8 ok 402s with latencies 100..800ms, 36h..120h ago (well inside 7d,
      clear of the 24h boundary — probes_since cutoffs are inclusive)
    - 1 ok 500 with latency 900ms, 12h ago (down for uptime, counted for latency)
    - 1 transport timeout, 6h ago (down, no latency)
    Hand-computed (7d window = all 10):
      uptime = 8/10 = 80.0
      latencies sorted = [100..900] (9 values)
      p50 = ceil(0.5*9)=5th = 500; p90 = ceil(0.9*9)=9th = 900; p99 = 9th = 900
      status_counts = {"402": 8, "500": 1, "timeout": 1}
    """
    endpoint_id = queries.upsert_endpoint(db, "https://fix.example/pay")
    for i in range(8):
        queries.record_probe(
            db,
            endpoint_id,
            ok=True,
            http_status=402,
            latency_ms=100.0 * (i + 1),
            is_402=True,
            now=hours_ago(12 * (i + 3)),
        )
    queries.record_probe(
        db, endpoint_id, ok=True, http_status=500, latency_ms=900.0, now=hours_ago(12)
    )
    queries.record_probe(db, endpoint_id, ok=False, error="timeout", now=hours_ago(6))
    return endpoint_id


def test_window_rollup_matches_hand_computed_fixture(db) -> None:
    endpoint_id = seed_fixture(db)
    fields = rollups.window_rollup(queries.probes_since(db, endpoint_id, hours_ago(7 * 24)))
    assert fields == {
        "probe_count": 10,
        "uptime_pct": 80.0,
        "p50_ms": 500.0,
        "p90_ms": 900.0,
        "p99_ms": 900.0,
        "status_counts": {"402": 8, "500": 1, "timeout": 1},
    }


def test_window_rollup_empty_window(db) -> None:
    fields = rollups.window_rollup([])
    assert fields["probe_count"] == 0
    assert fields["uptime_pct"] is None
    assert fields["p50_ms"] is None
    assert fields["status_counts"] is None


def test_window_rollup_blocked_counts_as_downtime(db) -> None:
    endpoint_id = queries.upsert_endpoint(db, "https://blocked.example/x")
    queries.record_probe(db, endpoint_id, ok=False, error="blocked", now=hours_ago(1))
    queries.record_probe(
        db, endpoint_id, ok=True, http_status=402, latency_ms=100.0, now=hours_ago(2)
    )
    fields = rollups.window_rollup(queries.probes_since(db, endpoint_id, hours_ago(24)))
    assert fields["uptime_pct"] == 50.0
    assert fields["status_counts"] == {"402": 1, "blocked": 1}


def test_refresh_rollups_writes_all_periods(db) -> None:
    endpoint_id = seed_fixture(db)
    written = rollups.refresh_rollups(db, [endpoint_id], now=NOW)
    assert written == 3
    rows = queries.get_rollups(db, endpoint_id)
    assert set(rows) == {"24h", "7d", "30d"}
    # 24h window holds only the 500 (12h ago) and the timeout (6h ago)
    assert rows["24h"]["probe_count"] == 2
    assert rows["24h"]["uptime_pct"] == 0.0
    assert rows["24h"]["status_counts"] == {"500": 1, "timeout": 1}
    assert rows["7d"]["probe_count"] == 10
    assert rows["7d"]["uptime_pct"] == 80.0
    assert rows["7d"]["p50_ms"] == 500.0
    assert rows["30d"]["probe_count"] == 10
    assert rows["24h"]["computed_at"] == NOW


def test_history_stats_none_below_two_probes(db) -> None:
    endpoint_id = queries.upsert_endpoint(db, "https://single.example/x")
    assert rollups.history_stats(db, endpoint_id, now=NOW) is None
    queries.record_probe(db, endpoint_id, ok=True, http_status=402, now=hours_ago(1))
    assert rollups.history_stats(db, endpoint_id, now=NOW) is None
    # exactly two probes crosses the threshold — history begins here
    queries.record_probe(db, endpoint_id, ok=True, http_status=402, now=hours_ago(2))
    stats = rollups.history_stats(db, endpoint_id, now=NOW)
    assert stats is not None
    assert stats.probe_count == 2


def test_history_stats_7d_window_boundary(db) -> None:
    """A probe ~6.5 days old is inside the 7d window; ~7.5 days is outside."""
    endpoint_id = queries.upsert_endpoint(db, "https://boundary.example/x")
    queries.record_probe(db, endpoint_id, ok=True, http_status=402, now=hours_ago(1))
    queries.record_probe(db, endpoint_id, ok=False, error="timeout", now=hours_ago(6.5 * 24))
    queries.record_probe(db, endpoint_id, ok=False, error="timeout", now=hours_ago(7.5 * 24))
    stats = rollups.history_stats(db, endpoint_id, now=NOW)
    # window holds the fresh ok + the 6.5d failure; the 7.5d one is excluded
    assert stats.uptime_7d == 50.0
    assert stats.probe_count == 3  # full history still counts everything


def test_window_rollup_null_status_ok_row_labeled_no_status(db) -> None:
    endpoint_id = queries.upsert_endpoint(db, "https://nullstatus.example/x")
    queries.record_probe(db, endpoint_id, ok=True, http_status=402, now=hours_ago(2))
    queries.record_probe(db, endpoint_id, ok=True, latency_ms=50.0, now=hours_ago(1))
    fields = rollups.window_rollup(queries.probes_since(db, endpoint_id, hours_ago(24)))
    # the anomalous ok-without-status row is downtime with an explicit label,
    # never a literal "None" key in the paid deep_report's JSON
    assert fields["uptime_pct"] == 50.0
    assert fields["status_counts"] == {"402": 1, "no-status": 1}


def test_history_stats_spans_full_history_windows_7d(db) -> None:
    endpoint_id = seed_fixture(db)
    # an old probe outside the 7d window widens observed_days but not uptime
    queries.record_probe(db, endpoint_id, ok=False, error="timeout", now=hours_ago(20 * 24))
    stats = rollups.history_stats(db, endpoint_id, now=NOW)
    assert stats is not None
    assert stats.probe_count == 11  # full history
    assert round(stats.observed_days, 1) == 20.0
    assert stats.uptime_7d == 80.0  # the old failure is outside the window
    assert stats.p50_ms == 500.0
    assert stats.p99_ms == 900.0


def test_history_upgrades_verdict_through_the_service(db, tmp_path, monkeypatch) -> None:
    """The M3 payoff: a well-observed healthy endpoint escapes caution/low."""
    from fastapi.testclient import TestClient

    from preflight402 import service
    from preflight402.api import rest
    from preflight402.config import Settings

    db_path = tmp_path / "svc-history.db"
    monkeypatch.setattr(
        rest,
        "settings",
        Settings(
            _env_file=None,
            db_path=db_path,
            allow_private_targets=True,
            rate_limit_per_minute=0,
        ),
    )
    service.ensure_migrated.cache_clear()

    async def stubbed_probe(url, *, timeout_s=10.0, pinned_ip=None, enforce_pin=False):
        return _payment_probe(url)

    monkeypatch.setattr(service, "probe", stubbed_probe)

    # 19 healthy 402 probes over 9.5 days of history (as the scheduler
    # accrues). 19 is deliberate: HIGH_CONFIDENCE_PROBES is 20, so the
    # 'high' assertion below holds only if the verdict's history includes
    # the current request's just-recorded observation (records-then-
    # evaluates ordering) — reverting that ordering fails this test.
    conn = connect(db_path)
    migrate(conn)
    url = "https://api.example.com/data"
    endpoint_id = queries.upsert_endpoint(
        conn, url, source="bazaar", now=queries.iso_add_seconds(queries.utcnow_iso(), -10 * 86400)
    )
    for i in range(19):
        queries.record_probe(
            conn,
            endpoint_id,
            ok=True,
            http_status=402,
            latency_ms=150.0,
            is_402=True,
            now=queries.iso_add_seconds(queries.utcnow_iso(), -(i + 1) * 12 * 3600),
        )
    conn.close()

    client = TestClient(rest.app)
    doc = client.get("/preflight", params={"url": url}).json()
    verdict = doc["verdict"]
    # 20 probes (19 seeded + this one) over 9.5 days of a valid handshake
    assert verdict["recommendation"] == "proceed"
    assert verdict["confidence"] == "high"
    assert verdict["score"] >= 85
    assert any("uptime" in reason for reason in verdict["reasons"])
    assert not any("single probe" in reason for reason in verdict["reasons"])


def test_first_sight_endpoint_still_cautions(db, tmp_path, monkeypatch) -> None:
    """No history -> unchanged single-probe caution/low behavior."""
    from fastapi.testclient import TestClient

    from preflight402 import service
    from preflight402.api import rest
    from preflight402.config import Settings

    monkeypatch.setattr(
        rest,
        "settings",
        Settings(
            _env_file=None,
            db_path=tmp_path / "svc-fresh.db",
            allow_private_targets=True,
            rate_limit_per_minute=0,
        ),
    )
    service.ensure_migrated.cache_clear()

    async def stubbed_probe(url, *, timeout_s=10.0, pinned_ip=None, enforce_pin=False):
        return _payment_probe(url)

    monkeypatch.setattr(service, "probe", stubbed_probe)
    client = TestClient(rest.app)
    doc = client.get("/preflight", params={"url": "https://api.example.com/data"}).json()
    assert doc["verdict"]["recommendation"] == "caution"
    assert doc["verdict"]["confidence"] == "low"
    assert any("single probe" in r for r in doc["verdict"]["reasons"])


# --- M3.4: trailing streaks for the dead/zombie heuristics -------------------


def test_history_stats_trailing_failure_streak(db) -> None:
    endpoint_id = queries.upsert_endpoint(db, "https://dying.example/x")
    queries.record_probe(db, endpoint_id, ok=True, http_status=402, now=hours_ago(5))
    for h in (3, 2, 1):
        queries.record_probe(db, endpoint_id, ok=False, error="timeout", now=hours_ago(h))
    stats = rollups.history_stats(db, endpoint_id, now=NOW)
    assert stats.consecutive_failures == 3  # the old success ends the streak
    assert stats.consecutive_non402 == 0


def test_history_stats_trailing_non402_streak(db) -> None:
    endpoint_id = queries.upsert_endpoint(db, "https://zombie.example/x")
    queries.record_probe(db, endpoint_id, ok=True, http_status=402, now=hours_ago(5))
    for h, status in ((3, 404), (2, 404), (1, 200)):
        queries.record_probe(db, endpoint_id, ok=True, http_status=status, now=hours_ago(h))
    stats = rollups.history_stats(db, endpoint_id, now=NOW)
    assert stats.consecutive_non402 == 3
    assert stats.consecutive_failures == 0


def test_history_stats_streaks_reset_by_current_success(db) -> None:
    endpoint_id = queries.upsert_endpoint(db, "https://recovered.example/x")
    for h in (4, 3, 2):
        queries.record_probe(db, endpoint_id, ok=False, error="timeout", now=hours_ago(h))
    queries.record_probe(db, endpoint_id, ok=True, http_status=402, now=hours_ago(1))
    stats = rollups.history_stats(db, endpoint_id, now=NOW)
    assert stats.consecutive_failures == 0
    assert stats.consecutive_non402 == 0


def test_dead_endpoint_flag_surfaces_through_the_service(db, tmp_path, monkeypatch) -> None:
    from fastapi.testclient import TestClient

    from preflight402 import service
    from preflight402.api import rest
    from preflight402.config import Settings

    db_path = tmp_path / "svc-dead.db"
    monkeypatch.setattr(
        rest,
        "settings",
        Settings(
            _env_file=None,
            db_path=db_path,
            allow_private_targets=True,
            rate_limit_per_minute=0,
        ),
    )
    service.ensure_migrated.cache_clear()

    async def failing_probe(url, *, timeout_s=10.0, pinned_ip=None, enforce_pin=False):
        return ProbeResult(url=url, ok=False, error="timeout")

    monkeypatch.setattr(service, "probe", failing_probe)

    conn = connect(db_path)
    migrate(conn)
    url = "https://dead.example/pay"
    endpoint_id = queries.upsert_endpoint(
        conn, url, source="bazaar", now=queries.iso_add_seconds(queries.utcnow_iso(), -30 * 86400)
    )
    for i in range(2):  # two prior failures; the live one makes three
        queries.record_probe(
            conn,
            endpoint_id,
            ok=False,
            error="timeout",
            now=queries.iso_add_seconds(queries.utcnow_iso(), -(i + 1) * 3600),
        )
    conn.close()

    client = TestClient(rest.app)
    doc = client.get("/preflight", params={"url": url}).json()
    assert doc["verdict"]["recommendation"] == "avoid"
    assert doc["authenticity"]["flags"] == ["dead"]
    assert any("dead endpoint (3 consecutive" in r for r in doc["verdict"]["reasons"])
