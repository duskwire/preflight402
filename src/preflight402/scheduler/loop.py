"""Continuous probing scheduler (M3.2).

Each cycle pulls due endpoints (host-windowed: the catalog is so skewed
that one host holds ~40% of it), groups them by host, and probes every
group concurrently while inside a group probes run sequentially with
politeness spacing. A shared semaphore bounds simultaneous probes.

Politeness model, per host:
- at most floor(cycle_s / per_host_min_interval_s) probes per cycle
  (endpoints_due_by_host enforces the same cap at selection time);
- probes within a group are spaced per_host_min_interval_s apart, with a
  small multiplicative jitter, and each group starts at a random stagger so
  cycles do not open with a thundering herd;
- an HTTP 429 abandons the rest of the host's group and puts the host in
  exponential backoff (min_interval * 2^level, capped at 1h); any non-429
  response from the host resets it.

Every probe is SSRF-guarded exactly like the public /preflight: the target
must resolve public, and the connection pins to the validated IP. A guard
refusal is recorded as a probe row with error='blocked' — a registry entry
pointing at private space is signal, not noise — and costs no connection.

The loop is deploy-safe OFF (settings.scheduler_enabled defaults False);
the standalone CLI (python -m preflight402.scheduler) always runs
explicitly. A cycle that crashes is logged and the loop continues; cycles
never stack (the next starts only after the previous finishes).
"""

from __future__ import annotations

import asyncio
import logging
import random
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from preflight402.config import Settings
from preflight402.db import connect, queries, rollups
from preflight402.probe.guard import BlockedTargetError, resolve_and_validate
from preflight402.probe.parsers import detect
from preflight402.probe.prober import probe
from preflight402.service import ensure_migrated, record_probe_result

logger = logging.getLogger(__name__)

BACKOFF_CAP_S = 3600.0

# Indirection so tests can record politeness sleeps instead of serving them.
_sleep = asyncio.sleep


def _refresh_rollups_in_thread(db_path, endpoint_ids: list[int]) -> int:
    """refresh_rollups on a worker thread: sqlite connections are bound to
    their creating thread, so open a dedicated one here (cheap under WAL)."""
    conn = connect(db_path)
    try:
        return rollups.refresh_rollups(conn, endpoint_ids)
    finally:
        conn.close()


@dataclass(slots=True)
class HostState:
    backoff_level: int = 0
    blocked_until: float = 0.0  # monotonic clock deadline


@dataclass(slots=True)
class CycleStats:
    due: int = 0
    probed: int = 0
    ok: int = 0  # response arrived and was not a 429
    rate_limited: int = 0  # 429 responses (each also triggers host backoff)
    blocked: int = 0  # SSRF-guard refusals (recorded, never connected)
    errors: int = 0  # transport-level failures (probes.ok = 0)
    skipped_backoff: int = 0  # endpoints skipped because their host is backing off
    hosts: int = 0
    rollup_rows: int = 0  # rollup rows refreshed for this cycle's probed endpoints

    def as_line(self) -> str:
        return (
            f"due={self.due} probed={self.probed} ok={self.ok}"
            f" errors={self.errors} blocked={self.blocked}"
            f" rate_limited={self.rate_limited} skipped_backoff={self.skipped_backoff}"
            f" hosts={self.hosts} rollup_rows={self.rollup_rows}"
        )


@dataclass
class Scheduler:
    """Cycle runner with per-host politeness state that persists across cycles."""

    settings: Settings
    _hosts: dict[str, HostState] = field(default_factory=dict)

    def _now(self) -> float:
        return asyncio.get_running_loop().time()

    def _jitter(self) -> float:
        """Multiplier applied to same-host spacing (monkeypatch target)."""
        return random.uniform(1.0, 1.1)

    def _stagger(self) -> float:
        """Initial delay before a host group starts (monkeypatch target)."""
        return random.uniform(0.0, min(self.settings.per_host_min_interval_s, 15.0))

    def per_host_limit(self) -> int:
        interval = max(self.settings.per_host_min_interval_s, 1.0)
        return max(1, int(self.settings.scheduler_cycle_s // interval))

    async def run_cycle(self, *, max_endpoints: int | None = None) -> CycleStats:
        settings = self.settings
        ensure_migrated(str(settings.db_path))
        conn = connect(settings.db_path)
        stats = CycleStats()
        try:
            before = queries.iso_add_seconds(queries.utcnow_iso(), -settings.scheduler_cycle_s)
            limit = max_endpoints if max_endpoints and max_endpoints > 0 else 1_000_000
            due = queries.endpoints_due_by_host(
                conn,
                before=before,
                per_host_limit=self.per_host_limit(),
                limit=limit,
            )
            stats.due = len(due)
            groups: dict[str, list[dict]] = {}
            for endpoint in due:
                groups.setdefault(endpoint["host"], []).append(endpoint)
            stats.hosts = len(groups)
            semaphore = asyncio.Semaphore(settings.probe_concurrency)
            probed_ids: list[int] = []
            async with asyncio.TaskGroup() as tasks:
                for host, endpoints in groups.items():
                    tasks.create_task(
                        self._probe_host_group(conn, host, endpoints, semaphore, stats, probed_ids)
                    )
            # M3.3: materialize rollups for what this cycle touched, so the
            # paid deep_report reads fresh windows without recomputing. In a
            # worker thread with its own connection: measured ~48ms of
            # synchronous work per endpoint at 30d history depth, which would
            # stall the shared event loop for seconds per cycle when the
            # scheduler is embedded in the API app (sqlite connections are
            # thread-bound, hence the fresh one).
            stats.rollup_rows = await asyncio.to_thread(
                _refresh_rollups_in_thread, settings.db_path, probed_ids
            )
            return stats
        finally:
            conn.close()

    async def _probe_host_group(
        self,
        conn,
        host: str,
        endpoints: list[dict],
        semaphore: asyncio.Semaphore,
        stats: CycleStats,
        probed_ids: list[int],
    ) -> None:
        state = self._hosts.setdefault(host, HostState())
        await _sleep(self._stagger())
        for index, endpoint in enumerate(endpoints):
            if state.blocked_until > self._now():
                stats.skipped_backoff += len(endpoints) - index
                return
            if index:
                await _sleep(self.settings.per_host_min_interval_s * self._jitter())
            try:
                async with semaphore:
                    outcome = await self._probe_one(conn, endpoint)
            except Exception:
                # One endpoint's unexpected failure (db hiccup, parser edge)
                # must not TaskGroup-cancel every other host group and burn
                # the whole cycle.
                logger.exception("probe of %s failed unexpectedly", endpoint["url"])
                stats.errors += 1
                continue
            stats.probed += 1
            probed_ids.append(endpoint["id"])  # every non-crash outcome wrote a row
            if outcome == "rate_limited":
                stats.rate_limited += 1
                state.backoff_level = min(state.backoff_level + 1, 12)
                delay = min(
                    self.settings.per_host_min_interval_s * 2**state.backoff_level,
                    BACKOFF_CAP_S,
                )
                state.blocked_until = self._now() + delay
                remaining = len(endpoints) - index - 1
                stats.skipped_backoff += remaining
                logger.info(
                    "host %s rate-limited; backing off %.0fs (%d endpoints deferred)",
                    host,
                    delay,
                    remaining,
                )
                return
            if outcome == "ok":
                state.backoff_level = 0
                state.blocked_until = 0.0
                stats.ok += 1
            elif outcome == "blocked":
                stats.blocked += 1
            else:
                stats.errors += 1

    async def _probe_one(self, conn, endpoint: dict) -> str:
        """Probe one endpoint and record the row; classify the outcome."""
        settings = self.settings
        url = endpoint["url"]
        parts = urlsplit(url)
        default_port = 443 if parts.scheme == "https" else 80
        try:
            pinned_ip = await resolve_and_validate(
                parts.hostname or "",
                parts.port or default_port,
                allow_private=settings.allow_private_targets,
            )
        except BlockedTargetError:
            queries.record_probe(conn, endpoint["id"], ok=False, error="blocked")
            return "blocked"
        result = await probe(
            url,
            timeout_s=settings.probe_timeout_s,
            pinned_ip=pinned_ip,
            enforce_pin=not settings.allow_private_targets,
        )
        detection = detect(result.headers, result.body)
        record_probe_result(conn, endpoint["id"], result, detection)
        if result.http_status == 429:
            return "rate_limited"
        return "ok" if result.ok else "error"


async def run_scheduler(settings: Settings, *, stop: asyncio.Event) -> None:
    """Run cycles forever until `stop` is set; crashes are logged, not fatal."""
    scheduler = Scheduler(settings)
    loop = asyncio.get_running_loop()
    while not stop.is_set():
        started = loop.time()
        try:
            max_per_cycle = settings.scheduler_max_per_cycle or None
            stats = await scheduler.run_cycle(max_endpoints=max_per_cycle)
            logger.info("scheduler cycle: %s", stats.as_line())
        except Exception:
            logger.exception("scheduler cycle failed; continuing")
        elapsed = loop.time() - started
        remaining = max(0.0, settings.scheduler_cycle_s - elapsed)
        try:
            await asyncio.wait_for(stop.wait(), timeout=remaining)
        except TimeoutError:
            continue
