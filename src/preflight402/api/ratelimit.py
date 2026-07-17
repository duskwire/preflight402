"""Per-client-IP rate limiting for the public endpoints.

Both `/preflight` (REST) and `/mcp` (the MCP tool) make an outbound probe per
(uncached) call, so the unauthenticated public surface is an amplification and
abuse vector. A token bucket per client IP caps the sustained rate while
allowing short bursts. Enforced as ASGI middleware (RateLimitMiddleware) so it
covers the mounted MCP sub-app too — a route-level dependency cannot — and runs
on the event loop, where allow()'s read-modify-write is genuinely atomic.

In-memory and per-process — the deployment is a single uvicorn worker. Behind
the Cloudflare tunnel the real client IP arrives in CF-Connecting-IP (the
socket peer is always the tunnel), and the service is not otherwise exposed, so
that header is trusted; the socket peer is the fallback.
"""

from __future__ import annotations

import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

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

        Called only from the async middleware, on the event loop: there is no
        await between read and write, so it is atomic (no lock needed).
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
        # Snapshot items first: never mutate the dict while iterating it.
        for key, b in list(self._buckets.items()):
            if min(self.capacity, b.tokens + (now - b.updated) * self.rate) >= self.capacity:
                del self._buckets[key]

    def reset(self) -> None:
        self._buckets.clear()


def client_ip(request: Request) -> str:
    """The caller's IP: CF-Connecting-IP behind the tunnel, else the peer."""
    cf = request.headers.get("cf-connecting-ip")
    if cf:
        return cf.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _path_matches(path: str, prefixes: tuple[str, ...]) -> bool:
    return any(path == p or path.startswith(p + "/") for p in prefixes)


class RateLimitMiddleware:
    """Token-bucket rate limit on HTTP requests to `prefixes`.

    `get_limiter` and `get_rate` are read per request (not captured), so tests
    can swap the limiter/rate at runtime and one app can front several
    surfaces. A rate <= 0 disables it. Runs on the event loop, so the limiter
    stays lock-free.
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        get_limiter: Callable[[], RateLimiter | None],
        get_rate: Callable[[], float],
        prefixes: tuple[str, ...],
    ) -> None:
        self.app = app
        self._get_limiter = get_limiter
        self._get_rate = get_rate
        self._prefixes = prefixes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if (
            scope["type"] == "http"
            and self._get_rate() > 0
            and _path_matches(scope["path"], self._prefixes)
        ):
            limiter = self._get_limiter()
            if limiter is not None and not limiter.allow(client_ip(Request(scope))):
                response: Callable[..., Awaitable[None]] = JSONResponse(
                    {"detail": "rate limit exceeded"},
                    status_code=429,
                    headers={"retry-after": "60"},
                )
                await response(scope, receive, send)
                return
        await self.app(scope, receive, send)
