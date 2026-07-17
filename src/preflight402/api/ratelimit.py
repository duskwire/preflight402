"""Per-client-IP rate limiting for the public endpoints.

`/preflight` makes an outbound probe per (uncached) call, so an unauthenticated
public endpoint is an amplification and abuse vector. A token bucket per client
IP caps the sustained rate while allowing short bursts.

In-memory and per-process — the deployment is a single uvicorn worker. Behind
the Cloudflare tunnel the real client IP arrives in CF-Connecting-IP (the
socket peer is always the tunnel), and the service is not otherwise exposed, so
that header is trusted; the socket peer is the fallback.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from starlette.requests import Request

# Above this many tracked IPs, sweep idle (full) buckets so a spray of
# distinct client IPs can't grow the map without bound.
_SWEEP_THRESHOLD = 10_000


@dataclass(slots=True)
class _Bucket:
    tokens: float
    updated: float


class RateLimiter:
    """Token bucket per key: `capacity` burst, refills `rate` tokens/second."""

    def __init__(self, per_minute: float, burst: float | None = None) -> None:
        self.rate = per_minute / 60.0
        self.capacity = burst if burst is not None else max(per_minute, 1.0)
        self._buckets: dict[str, _Bucket] = {}

    def allow(self, key: str, *, now: float | None = None) -> bool:
        """Consume one token for `key`; True if allowed, False if limited.

        No await between read and write, so this is atomic under the single
        asyncio thread.
        """
        now = time.monotonic() if now is None else now
        bucket = self._buckets.get(key)
        if bucket is None:
            bucket = _Bucket(tokens=self.capacity, updated=now)
            self._buckets[key] = bucket
            if len(self._buckets) > _SWEEP_THRESHOLD:
                self._sweep(now)
        else:
            bucket.tokens = min(self.capacity, bucket.tokens + (now - bucket.updated) * self.rate)
            bucket.updated = now
        if bucket.tokens >= 1.0:
            bucket.tokens -= 1.0
            return True
        return False

    def _sweep(self, now: float) -> None:
        # A bucket refilled to capacity carries no state worth keeping — the
        # IP would get a fresh full bucket next time anyway. Drop those.
        for key in [
            k
            for k, b in self._buckets.items()
            if min(self.capacity, b.tokens + (now - b.updated) * self.rate) >= self.capacity
        ]:
            del self._buckets[key]

    def reset(self) -> None:
        self._buckets.clear()


def client_ip(request: Request) -> str:
    """The caller's IP: CF-Connecting-IP behind the tunnel, else the peer."""
    cf = request.headers.get("cf-connecting-ip")
    if cf:
        return cf.split(",")[0].strip()
    return request.client.host if request.client else "unknown"
