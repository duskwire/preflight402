"""Dashboard stats: counters, aggregation math, REST endpoint, CLI."""

from __future__ import annotations

from pathlib import Path

import pytest

from preflight402 import stats
from preflight402.db import connect, migrate, queries

NOW = "2026-07-17T12:00:00.000Z"


@pytest.fixture()
def db(tmp_path: Path):
    conn = connect(tmp_path / "stats.db")
    migrate(conn)
    yield conn
    conn.close()


def hours_ago(hours: float) -> str:
    return queries.iso_add_seconds(NOW, -hours * 3600)


def seed_world(db) -> None:
    """Three endpoints with hand-computable stats at NOW.

    - healthy.example/pay: 402@30h(100ms), 402@40h(200ms) -> serving 402,
      outside the 24h window
    - dead.example/pay: 3 consecutive timeouts (1h,2h,3h) after a 402@50h
      -> dead_now
    - zombie.example/pay: 3 consecutive 404s (1h,2h,3h; 50ms each) -> zombie_now
    - old.example/pay: one 402 probe 10 days ago -> outside every 7d window
    Probing 7d: 9 probes (2+4+3); 24h: 6 (the timeouts + 404s). Outcomes 7d:
    answered_402=3, answered_other=3 (404s), transport_error=3, blocked=0.
    Latencies (ok probes 7d) sorted: [50,50,50,90,100,200], n=6 ->
    p50 = 3rd = 50, p90 = ceil(5.4)=6th = 200.
    serving_402_pct: 1 of 3 endpoints probed in 7d whose latest probe is a
    402 -> 33.33.
    """
    healthy = queries.upsert_endpoint(db, "https://healthy.example/pay", source="bazaar")
    dead = queries.upsert_endpoint(db, "https://dead.example/pay", source="bazaar")
    zombie = queries.upsert_endpoint(db, "https://zombie.example/pay", source="x402-list")
    old = queries.upsert_endpoint(db, "https://old.example/pay", source="preflight")

    for h, latency in ((30, 100.0), (40, 200.0)):
        queries.record_probe(
            db,
            healthy,
            ok=True,
            http_status=402,
            latency_ms=latency,
            is_402=True,
            now=hours_ago(h),
        )
    queries.record_probe(
        db, dead, ok=True, http_status=402, latency_ms=90.0, is_402=True, now=hours_ago(50)
    )
    for h in (1, 2, 3):
        queries.record_probe(db, dead, ok=False, error="timeout", now=hours_ago(h))
    for h in (1, 2, 3):
        queries.record_probe(
            db, zombie, ok=True, http_status=404, latency_ms=50.0, now=hours_ago(h)
        )
    queries.record_probe(
        db,
        old,
        ok=True,
        http_status=402,
        latency_ms=10.0,
        is_402=True,
        now=hours_ago(10 * 24),
    )


def test_compute_stats_matches_hand_computed_fixture(db) -> None:
    seed_world(db)
    queries.bump_counter(db, "preflight_calls", by=7, now=NOW)
    queries.bump_counter(db, "preflight_cache_hits", by=2, now=NOW)
    queries.bump_counter(db, "preflight_calls", by=1, now="2026-06-01T00:00:00.000Z")  # old

    document = stats.compute_stats(db, now=NOW)
    assert document["schema"] == "stats.v0"

    assert document["catalog"] == {
        "endpoints": 4,
        "enabled": 4,
        "hosts": 4,
        "new_7d": 4,
        "by_source": {"bazaar": 2, "preflight": 1, "x402-list": 1},
    }

    probing = document["probing"]
    assert probing["probes_7d"] == 9
    assert probing["probes_24h"] == 6
    assert probing["endpoints_probed_7d"] == 3
    assert probing["coverage_7d_pct"] == 75.0
    assert probing["outcomes_7d"] == {
        "answered_402": 3,
        "answered_other": 3,
        "transport_error": 3,
        "blocked": 0,
    }
    assert probing["latency_ms_7d"] == {"p50": 50.0, "p90": 200.0}

    health = document["health"]
    assert health["dead_now"] == 1
    assert health["zombie_now"] == 1
    assert health["serving_402_pct"] == 33.33

    usage = document["usage"]
    assert usage["preflight_calls_7d"] == 7  # the June bump is outside the window
    assert usage["preflight_cache_hits_7d"] == 2
    assert usage["preflight_calls_by_day"] == {"2026-07-17": 7}

    assert document["paid"] == {
        "settlements_7d": None,
        "unique_payers_7d": None,
        "revenue_usd_7d": None,
    }
    assert document["reputation"] == {"erc8004_bound_pct": None}


def test_compute_stats_empty_db(db) -> None:
    document = stats.compute_stats(db, now=NOW)
    assert document["catalog"]["endpoints"] == 0
    assert document["probing"]["probes_7d"] == 0
    assert document["probing"]["coverage_7d_pct"] is None
    assert document["probing"]["latency_ms_7d"] == {"p50": None, "p90": None}
    assert document["health"]["serving_402_pct"] is None
    assert document["health"]["dead_now"] == 0
    assert document["usage"]["preflight_calls_7d"] == 0


def test_dead_needs_full_streak_not_just_failures(db) -> None:
    endpoint = queries.upsert_endpoint(db, "https://flaky.example/pay")
    # fail, ok, fail — interrupted streak must not read as dead
    queries.record_probe(db, endpoint, ok=False, error="timeout", now=hours_ago(3))
    queries.record_probe(db, endpoint, ok=True, http_status=402, is_402=True, now=hours_ago(2))
    queries.record_probe(db, endpoint, ok=False, error="timeout", now=hours_ago(1))
    document = stats.compute_stats(db, now=NOW)
    assert document["health"]["dead_now"] == 0
    assert document["health"]["zombie_now"] == 0


def test_counters_bump_and_daily_rollover(db) -> None:
    queries.bump_counter(db, "preflight_calls", now="2026-07-17T23:59:59.000Z")
    queries.bump_counter(db, "preflight_calls", now="2026-07-18T00:00:01.000Z")
    queries.bump_counter(db, "preflight_calls", now="2026-07-18T05:00:00.000Z")
    counters = queries.counters_since(db, "2026-07-17")
    assert counters["preflight_calls"] == {"2026-07-17": 1, "2026-07-18": 2}
    assert queries.counters_since(db, "2026-07-18") == {"preflight_calls": {"2026-07-18": 2}}


def test_preflight_calls_are_metered(tmp_path, monkeypatch) -> None:
    from fastapi.testclient import TestClient

    from preflight402 import service
    from preflight402.api import rest
    from preflight402.config import Settings

    db_path = tmp_path / "metered.db"
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

    from preflight402.probe.prober import ProbeResult

    async def stub_probe(url, *, timeout_s=10.0, pinned_ip=None, enforce_pin=False):
        return ProbeResult(url=url, ok=True, http_status=200, body="hi")

    monkeypatch.setattr(service, "probe", stub_probe)
    client = TestClient(rest.app)
    client.get("/preflight", params={"url": "http://a.example/x"})
    client.get("/preflight", params={"url": "http://a.example/x"})  # cache hit

    conn = connect(db_path)
    try:
        counters = queries.counters_since(conn, "2000-01-01")
    finally:
        conn.close()
    assert sum(counters["preflight_calls"].values()) == 2
    assert sum(counters["preflight_cache_hits"].values()) == 1


def test_stats_endpoint_serves_and_caches(tmp_path, monkeypatch) -> None:
    from fastapi.testclient import TestClient

    from preflight402 import service
    from preflight402.api import rest
    from preflight402.config import Settings

    monkeypatch.setattr(
        rest,
        "settings",
        Settings(_env_file=None, db_path=tmp_path / "rest-stats.db", rate_limit_per_minute=0),
    )
    service.ensure_migrated.cache_clear()
    rest._stats_cache.clear()

    client = TestClient(rest.app)
    first = client.get("/stats")
    assert first.status_code == 200
    assert first.headers["x-stats-cache"] == "miss"
    document = first.json()
    assert document["schema"] == "stats.v0"
    assert document["catalog"]["endpoints"] == 0

    second = client.get("/stats")
    assert second.headers["x-stats-cache"] == "hit"
    assert second.json() == document


def test_cli_renders_text_and_json(db, tmp_path, monkeypatch, capsys) -> None:
    from preflight402.config import get_settings

    seed_world(db)
    monkeypatch.setenv("PREFLIGHT402_DB_PATH", str(tmp_path / "stats.db"))
    get_settings.cache_clear()
    try:
        assert stats.main([]) == 0
        text = capsys.readouterr().out
        assert "preflight402 dashboard" in text
        assert "4 endpoints" in text
        assert "dead now: 1" in text

        assert stats.main(["--json"]) == 0
        import json

        document = json.loads(capsys.readouterr().out)
        assert document["schema"] == "stats.v0"
        assert document["health"]["zombie_now"] == 1
    finally:
        get_settings.cache_clear()
