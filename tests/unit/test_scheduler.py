"""Scheduler: cycle mechanics, per-host politeness, backoff, guard wiring."""

from __future__ import annotations

import asyncio
import contextlib

import httpx
import pytest
import respx

from preflight402.config import Settings
from preflight402.db import connect, queries
from preflight402.probe.guard import BlockedTargetError
from preflight402.scheduler import CycleStats, Scheduler, run_scheduler
from preflight402.scheduler import loop as loop_module

pytestmark = pytest.mark.anyio


@pytest.fixture
def settings(tmp_path) -> Settings:
    # allow_private_targets=True keeps unit tests off the real resolver (the
    # guard returns None immediately and the prober skips pinning); the guard
    # path itself is tested via an explicit monkeypatched raise.
    return Settings(
        db_path=tmp_path / "sched-test.db",
        allow_private_targets=True,
        per_host_min_interval_s=60.0,
        scheduler_cycle_s=900.0,
    )


@pytest.fixture
def sleeps(monkeypatch) -> list[float]:
    """Record politeness sleeps instead of serving them."""
    recorded: list[float] = []

    async def instant(delay: float) -> None:
        recorded.append(delay)

    monkeypatch.setattr(loop_module, "_sleep", instant)
    return recorded


@pytest.fixture
def calm(monkeypatch) -> None:
    """Deterministic politeness: no stagger, no jitter."""
    monkeypatch.setattr(Scheduler, "_stagger", lambda self: 0.0)
    monkeypatch.setattr(Scheduler, "_jitter", lambda self: 1.0)


def seed(settings: Settings, urls: list[str]) -> None:
    conn = connect(settings.db_path)
    try:
        from preflight402.db import migrate

        migrate(conn)
        for url in urls:
            queries.upsert_endpoint(conn, url, source="test")
    finally:
        conn.close()


def all_probes(settings: Settings) -> list[dict]:
    conn = connect(settings.db_path)
    try:
        return [dict(row) for row in conn.execute("SELECT * FROM probes ORDER BY id")]
    finally:
        conn.close()


@respx.mock
async def test_cycle_probes_due_records_and_rotates(settings, sleeps, calm) -> None:
    seed(settings, ["http://h1.example/pay", "http://h2.example/pay"])
    respx.get("http://h1.example/pay").mock(
        return_value=httpx.Response(402, json={"x402Version": 1, "accepts": []})
    )
    respx.get("http://h2.example/pay").mock(return_value=httpx.Response(200, text="hi"))

    scheduler = Scheduler(settings)
    stats = await scheduler.run_cycle()
    assert stats.due == 2
    assert stats.probed == 2
    assert stats.ok == 2
    assert stats.errors == 0

    probes = all_probes(settings)
    assert len(probes) == 2
    by_status = {p["http_status"] for p in probes}
    assert by_status == {402, 200}
    assert all(p["ok"] == 1 for p in probes)
    is_402_flags = {p["http_status"]: p["is_402"] for p in probes}
    assert is_402_flags[402] == 1
    assert is_402_flags[200] == 0

    # Rotation: everything was just probed, so nothing is due next cycle.
    second = await scheduler.run_cycle()
    assert second.due == 0
    assert second.probed == 0


@respx.mock
async def test_same_host_probes_are_spaced(settings, sleeps, calm) -> None:
    seed(
        settings,
        ["http://one.example/a", "http://one.example/b", "http://one.example/c"],
    )
    respx.get(url__startswith="http://one.example/").mock(return_value=httpx.Response(200))
    stats = await Scheduler(settings).run_cycle()
    assert stats.probed == 3
    # one stagger (0.0) plus two spacing sleeps at the politeness interval
    assert sleeps.count(60.0) == 2


@respx.mock
async def test_429_backs_off_host_and_abandons_group(settings, sleeps, calm) -> None:
    seed(
        settings,
        ["http://rl.example/a", "http://rl.example/b", "http://rl.example/c"],
    )
    route = respx.get(url__startswith="http://rl.example/").mock(return_value=httpx.Response(429))
    scheduler = Scheduler(settings)
    stats = await scheduler.run_cycle()
    assert stats.probed == 1  # first 429 abandons the rest of the group
    assert stats.rate_limited == 1
    assert stats.skipped_backoff == 2
    assert route.call_count == 1

    state = scheduler._hosts["rl.example"]
    assert state.backoff_level == 1
    assert state.blocked_until > 0

    # While backing off, the host's still-due endpoints are skipped untouched.
    second = await scheduler.run_cycle()
    assert second.due == 2
    assert second.probed == 0
    assert second.skipped_backoff == 2
    assert route.call_count == 1

    # Once the backoff expires, probing resumes and success resets the state.
    state.blocked_until = 0.0
    route.mock(return_value=httpx.Response(200))
    third = await scheduler.run_cycle()
    assert third.probed == 2
    assert third.ok == 2
    assert state.backoff_level == 0


@respx.mock
async def test_blocked_target_is_recorded_without_connecting(
    settings, sleeps, calm, monkeypatch
) -> None:
    seed(settings, ["http://internal.example/x", "http://public.example/y"])
    route = respx.get("http://public.example/y").mock(return_value=httpx.Response(200))
    unreached = respx.get("http://internal.example/x").mock(return_value=httpx.Response(200))

    async def guard(host, port, *, allow_private=False):
        if host == "internal.example":
            raise BlockedTargetError(f"refusing to probe {host!r}")
        return None

    monkeypatch.setattr(loop_module, "resolve_and_validate", guard)
    stats = await Scheduler(settings).run_cycle()
    assert stats.blocked == 1
    assert stats.ok == 1
    assert not unreached.called  # the guard refusal never opened a connection
    assert route.called

    blocked_rows = [p for p in all_probes(settings) if p["error"] == "blocked"]
    assert len(blocked_rows) == 1
    assert blocked_rows[0]["ok"] == 0
    assert blocked_rows[0]["http_status"] is None


@respx.mock
async def test_max_endpoints_caps_the_cycle(settings, sleeps, calm) -> None:
    seed(settings, [f"http://h{i}.example/p" for i in range(5)])
    respx.get(url__regex=r"http://h\d\.example/p").mock(return_value=httpx.Response(200))
    stats = await Scheduler(settings).run_cycle(max_endpoints=2)
    assert stats.due == 2
    assert stats.probed == 2


@respx.mock
async def test_per_host_share_is_capped_per_cycle(settings, sleeps, calm) -> None:
    # cycle 120s / interval 60s -> at most 2 probes per host per cycle
    settings = settings.model_copy(
        update={"scheduler_cycle_s": 120.0, "per_host_min_interval_s": 60.0}
    )
    seed(settings, [f"http://big.example/e{i}" for i in range(4)])
    respx.get(url__startswith="http://big.example/").mock(return_value=httpx.Response(200))
    scheduler = Scheduler(settings)
    assert scheduler.per_host_limit() == 2
    stats = await scheduler.run_cycle()
    assert stats.due == 2
    assert stats.probed == 2
    # the other two rotate into the next cycle (oldest first)
    second = await scheduler.run_cycle()
    assert second.due == 2
    conn = connect(settings.db_path)
    try:
        unprobed = conn.execute(
            "SELECT COUNT(*) FROM endpoints WHERE last_probed_at IS NULL"
        ).fetchone()[0]
    finally:
        conn.close()
    assert unprobed == 0  # all four covered across the two cycles


@respx.mock
async def test_one_endpoints_crash_does_not_burn_the_cycle(
    settings, sleeps, calm, monkeypatch
) -> None:
    seed(settings, ["http://boom.example/x", "http://fine.example/y"])
    respx.get("http://boom.example/x").mock(return_value=httpx.Response(200))
    respx.get("http://fine.example/y").mock(return_value=httpx.Response(200))

    real_record = loop_module.record_probe_result

    def record(conn, endpoint_id, result, detection):
        if "boom" in result.url:
            raise RuntimeError("db hiccup")
        return real_record(conn, endpoint_id, result, detection)

    monkeypatch.setattr(loop_module, "record_probe_result", record)
    stats = await Scheduler(settings).run_cycle()
    # the crash is contained: counted as an error, the other host still probed
    assert stats.errors == 1
    assert stats.ok == 1
    assert len(all_probes(settings)) == 1


@respx.mock
def test_cli_once_runs_a_cycle(monkeypatch, tmp_path, capsys) -> None:
    from preflight402.config import get_settings
    from preflight402.scheduler import __main__ as cli

    monkeypatch.setenv("PREFLIGHT402_DB_PATH", str(tmp_path / "cli-sched.db"))
    monkeypatch.setenv("PREFLIGHT402_ALLOW_PRIVATE_TARGETS", "true")
    get_settings.cache_clear()
    try:
        exit_code = cli.main(["--once", "--max-endpoints", "5"])
    finally:
        get_settings.cache_clear()
    assert exit_code == 0
    assert "due=0 probed=0" in capsys.readouterr().out


async def test_run_scheduler_survives_crashes_and_stops(settings, monkeypatch) -> None:
    calls = 0
    stop = asyncio.Event()

    async def flaky_cycle(self, *, max_endpoints=None):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("cycle exploded")
        if calls >= 3:
            stop.set()
        return CycleStats()

    monkeypatch.setattr(Scheduler, "run_cycle", flaky_cycle)
    fast = settings.model_copy(update={"scheduler_cycle_s": 0.01})
    await asyncio.wait_for(run_scheduler(fast, stop=stop), timeout=5)
    assert calls >= 3  # crashed once, kept cycling, honored stop


async def test_lifespan_starts_and_stops_scheduler_only_when_enabled(settings, monkeypatch) -> None:
    from types import SimpleNamespace

    from preflight402.api import app as app_module
    from preflight402.api import rest

    events: list[str] = []

    async def fake_run_scheduler(passed_settings, *, stop):
        events.append("started")
        try:
            await stop.wait()
        except asyncio.CancelledError:
            events.append("cancelled")
            raise

    @contextlib.asynccontextmanager
    async def fake_session_manager_run():
        yield

    monkeypatch.setattr(app_module, "run_scheduler", fake_run_scheduler)
    monkeypatch.setattr(
        app_module,
        "mcp",
        SimpleNamespace(session_manager=SimpleNamespace(run=fake_session_manager_run)),
    )

    disabled = settings.model_copy(update={"scheduler_enabled": False})
    monkeypatch.setattr(rest, "settings", disabled)
    async with app_module._lifespan(None):
        pass
    assert events == []

    enabled = settings.model_copy(update={"scheduler_enabled": True})
    monkeypatch.setattr(rest, "settings", enabled)
    async with app_module._lifespan(None):
        await asyncio.sleep(0)  # let the scheduler task start
    assert events == ["started", "cancelled"]
