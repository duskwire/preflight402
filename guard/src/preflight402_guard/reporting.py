"""Delivery-outcome reporting (Phase A of the crowdsourced delivery verifier).

After a payment settles, the x402 SDK fires an on_payment_response hook whose
context tells us whether the paid request actually succeeded. We turn that into
a small, privacy-minimal report and POST it to the preflight402 service —
crowdsourcing "did paying this endpoint actually deliver?" from real purchases.

Two tiers (Guard controls which):
  - anonymous (default ON): endpoint URL + delivered bool + a coarse failure
    category. No tx, no payer, no client identity, no response bodies.
  - verified (opt-in): additionally the settlement tx hash, payer, network,
    amount — on-chain-anchored so a positive report can be verified and a
    Sybil farm of payers collapses to one vote (server side).

Discipline: reporting is FIRE-AND-FORGET and must never add latency to, or
raise into, the payment path. A running event loop gets a detached task; a
sync context gets a daemon thread; a blocking send exists only for the CLI.
Every failure is swallowed. An env kill switch (PREFLIGHT402_GUARD_NO_TELEMETRY)
overrides code — a user or ops team can force telemetry off process-wide.
"""

from __future__ import annotations

import asyncio
import logging
import os
import threading
from typing import Any

import httpx

logger = logging.getLogger(__name__)

NO_TELEMETRY_ENV = "PREFLIGHT402_GUARD_NO_TELEMETRY"
_TRUTHY = {"1", "true", "yes", "on"}


def telemetry_disabled_by_env() -> bool:
    """True when the env kill switch forces all reporting off."""
    return os.environ.get(NO_TELEMETRY_ENV, "").strip().lower() in _TRUTHY


class DeliveryReporter:
    """Best-effort sender for delivery-outcome reports.

    enabled=False (or the env kill switch) makes every method a no-op.
    """

    def __init__(self, service_url: str, *, enabled: bool = True, timeout_s: float = 4.0) -> None:
        self._url = f"{service_url.rstrip('/')}/delivery-reports"
        self._enabled = enabled and not telemetry_disabled_by_env()
        self._timeout_s = timeout_s

    @property
    def enabled(self) -> bool:
        return self._enabled

    def report_async(self, payload: dict[str, Any]) -> None:
        """Fire-and-forget from an async context. Falls back to a thread if no
        loop is running (e.g. called from sync code). NEVER raises — dispatch
        itself (create_task under a broken loop) is swallowed, because this is
        called from the payment path and a telemetry glitch must not break a
        settled payment."""
        if not self._enabled:
            return
        try:
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                self.report_thread(payload)
                return
            # Detached: a telemetry send must never join the payment path. The
            # reference is dropped intentionally — best-effort by design.
            task = loop.create_task(self._send_async(payload))
            task.add_done_callback(lambda t: t.exception())  # swallow, don't warn
        except Exception as exc:  # e.g. loop shutting down
            logger.debug("delivery report dispatch failed: %s", exc)

    def report_thread(self, payload: dict[str, Any]) -> None:
        """Fire-and-forget from a sync context (daemon thread). NEVER raises —
        Thread.start() can throw RuntimeError under thread exhaustion, and that
        must not surface in the payment path."""
        if not self._enabled:
            return
        try:
            threading.Thread(target=self._send_sync, args=(payload,), daemon=True).start()
        except Exception as exc:
            logger.debug("delivery report dispatch failed: %s", exc)

    def send_blocking(self, payload: dict[str, Any]) -> bool:
        """Synchronous, inline send that waits for the result. For the CLI,
        where a daemon thread would be killed at process exit. Returns success;
        never raises."""
        if not self._enabled:
            return False
        return self._send_sync(payload)

    async def _send_async(self, payload: dict[str, Any]) -> None:
        try:
            async with httpx.AsyncClient(timeout=self._timeout_s) as client:
                await client.post(self._url, json={"reports": [payload]})
        except Exception as exc:  # telemetry is best-effort; never propagate
            logger.debug("delivery report failed: %s", exc)

    def _send_sync(self, payload: dict[str, Any]) -> bool:
        try:
            with httpx.Client(timeout=self._timeout_s) as client:
                response = client.post(self._url, json={"reports": [payload]})
            return response.status_code < 400
        except Exception as exc:
            logger.debug("delivery report failed: %s", exc)
            return False
