"""Auto-preflight guard: validate an x402 payment endpoint before paying.

The guard asks a preflight402 service (default: the public instance at
https://preflight402.ironshell.io) for a trust-preview.v1 verdict and applies
a local policy BEFORE any payment is signed:

    from preflight402_guard import Guard

    guard = Guard()                       # blocks "avoid", warns on "caution"
    await guard.assert_allowed(url)       # raises PaymentBlocked on a bad verdict

    # or wire it into the x402 SDK so every payment is checked automatically:
    from x402 import x402Client
    client = x402Client()
    guard.install(client)                 # AbortResult -> PaymentAbortedError

Design choices worth knowing:
  - FAIL-OPEN by default: if the preflight service is unreachable, payments
    proceed (with a warning decision) — your commerce must not depend on our
    uptime. Set fail_open=False for strict environments.
  - max_price_usd is enforced against the payment terms YOUR client selected
    (the ground truth of what would be signed), not only against the price
    the preflight service observed — an endpoint that shows one price to a
    scanner and another to payers is caught.
  - Decisions are cached briefly per URL (cache_ttl_s) so hot request loops
    don't re-preflight every call; the service itself caches verdicts ~5 min.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import httpx

logger = logging.getLogger(__name__)

DEFAULT_SERVICE_URL = "https://preflight402.ironshell.io"

# (network, asset) -> decimals for USD-stable assets, mirroring the service's
# verdict table — used to price the LOCALLY selected payment terms.
_KNOWN_USD_ASSETS: dict[tuple[str, str], int] = {}
for _networks, _asset, _decimals in [
    (("eip155:8453", "base"), "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913", 6),
    (("eip155:137", "polygon"), "0x3c499c542cef5e3811e1192ce70d8cc03d5c3359", 6),
    (
        ("solana:5eykt4usfv8p8njdtrepy1vzqkqzkvdp", "solana"),
        "epjfwdd5aufqssqem2qn1xzybapc8g4wegGkzwytdt1v".lower(),
        6,
    ),
]:
    for _network in _networks:
        _KNOWN_USD_ASSETS[(_network, _asset)] = _decimals


@dataclass(frozen=True)
class GuardDecision:
    """The outcome of one guard evaluation for one URL."""

    url: str
    allowed: bool
    action: str  # "allow" | "warn" | "block"
    recommendation: str | None  # proceed | caution | avoid; None = no verdict
    reasons: list[str] = field(default_factory=list)
    document: dict[str, Any] | None = None  # full trust-preview.v1, when fetched


class PaymentBlocked(Exception):
    """Raised by assert_allowed()/the x402 hook path when policy blocks a payment."""

    def __init__(self, decision: GuardDecision) -> None:
        self.decision = decision
        reasons = "; ".join(decision.reasons) or "blocked by policy"
        super().__init__(f"preflight blocked payment to {decision.url}: {reasons}")


class Guard:
    """Policy + preflight client. One instance is safe to share across calls.

    Args:
        service_url: preflight402 service base URL.
        block: recommendations that block payment (default: avoid).
        warn: recommendations that allow with a warning (default: caution).
        max_price_usd: hard ceiling on the price actually being paid; enforced
            against the locally selected terms when known-USD, else against
            the verdict's observed price. None disables.
        require_bound_identity: block unless the payee binds to an ERC-8004
            identity (reputation.erc8004.bound is true).
        min_filtered_score: block when a Sybil-filtered reputation score IS
            available (sybil complete) and falls below this. Endpoints with
            no filtered score are unaffected — most aren't bound at all.
        verify_payee: block when the locally selected payment recipient is
            not the payee the preflighted endpoint advertises. The 402's
            resource URL is ATTACKER-CONTROLLED; without this check a
            malicious endpoint could point it at someone else's clean
            endpoint and inherit their verdict.
        fail_open: allow (with warning) when the preflight service cannot be
            reached or returns garbage. False = block instead.
        timeout_s: per-request timeout to the preflight service.
        cache_ttl_s: per-URL decision cache; 0 disables.
        on_decision: optional callback invoked with every GuardDecision.
    """

    def __init__(
        self,
        service_url: str = DEFAULT_SERVICE_URL,
        *,
        block: tuple[str, ...] = ("avoid",),
        warn: tuple[str, ...] = ("caution",),
        max_price_usd: float | None = None,
        require_bound_identity: bool = False,
        min_filtered_score: float | None = None,
        verify_payee: bool = True,
        fail_open: bool = True,
        timeout_s: float = 8.0,
        cache_ttl_s: float = 60.0,
        on_decision: Callable[[GuardDecision], None] | None = None,
    ) -> None:
        self._service_url = service_url.rstrip("/")
        self._block = tuple(block)
        self._warn = tuple(warn)
        self._max_price_usd = max_price_usd
        self._require_bound = require_bound_identity
        self._min_filtered_score = min_filtered_score
        self._verify_payee = verify_payee
        self._fail_open = fail_open
        self._timeout_s = timeout_s
        self._cache_ttl_s = cache_ttl_s
        self._on_decision = on_decision
        self._cache: dict[tuple, tuple[float, GuardDecision]] = {}

    # ------------------------------------------------------------------ core

    async def check(
        self,
        url: str,
        *,
        local_price_usd: float | None = None,
        local_pay_to: str | None = None,
    ) -> GuardDecision:
        """Fetch a verdict for `url` and evaluate policy. Never raises for
        service failures — those become an allow-or-block per fail_open.
        local_price_usd/local_pay_to are the terms YOUR client selected; the
        hook path fills them so scanner-vs-payer games are caught."""
        key = (url, local_price_usd, local_pay_to)
        cached = self._cached(key)
        if cached is not None:
            return cached
        document, failure, refused = await self._fetch(url)
        return self._decide(key, document, failure, refused, local_price_usd, local_pay_to)

    def check_sync(
        self,
        url: str,
        *,
        local_price_usd: float | None = None,
        local_pay_to: str | None = None,
    ) -> GuardDecision:
        """Synchronous check() for non-async code (blocking HTTP call)."""
        key = (url, local_price_usd, local_pay_to)
        cached = self._cached(key)
        if cached is not None:
            return cached
        document, failure, refused = self._fetch_sync(url)
        return self._decide(key, document, failure, refused, local_price_usd, local_pay_to)

    async def assert_allowed(self, url: str) -> GuardDecision:
        """check() that raises PaymentBlocked when policy blocks."""
        decision = await self.check(url)
        if not decision.allowed:
            raise PaymentBlocked(decision)
        return decision

    def assert_allowed_sync(self, url: str) -> GuardDecision:
        decision = self.check_sync(url)
        if not decision.allowed:
            raise PaymentBlocked(decision)
        return decision

    # ---------------------------------------------------- x402 SDK integration

    async def hook(self, ctx: Any) -> Any:
        """x402 BeforePaymentCreationHook (async): preflight the resource and
        return AbortResult to block — the SDK raises PaymentAbortedError."""
        url = _resource_url(ctx)
        if url is None:
            return self._abort_for(self._no_url_decision())
        decision = await self.check(
            url, local_price_usd=_selected_price_usd(ctx), local_pay_to=_selected_pay_to(ctx)
        )
        return self._abort_for(decision)

    def hook_sync(self, ctx: Any) -> Any:
        """x402 SyncBeforePaymentCreationHook — same policy, blocking I/O."""
        url = _resource_url(ctx)
        if url is None:
            return self._abort_for(self._no_url_decision())
        decision = self.check_sync(
            url, local_price_usd=_selected_price_usd(ctx), local_pay_to=_selected_pay_to(ctx)
        )
        return self._abort_for(decision)

    def install(self, x402_client: Any) -> Any:
        """Register this guard on an x402Client/x402ClientSync; returns the
        client for chaining. Async clients get the async hook (a blocking
        hook would stall the event loop); sync clients get the sync hook."""
        register = getattr(x402_client, "on_before_payment_creation", None)
        if register is None:
            raise TypeError(
                "expected an x402 client with on_before_payment_creation "
                f"(got {type(x402_client).__name__}); pip install preflight402-guard[x402]"
            )
        is_sync = type(x402_client).__name__ == "x402ClientSync"
        register(self.hook_sync if is_sync else self.hook)
        return x402_client

    def _abort_for(self, decision: GuardDecision) -> Any:
        if decision.allowed:
            return None
        try:
            from x402.schemas.hooks import AbortResult
        except ImportError as exc:  # pragma: no cover - install() guards this
            raise PaymentBlocked(decision) from exc
        reasons = "; ".join(decision.reasons) or "blocked by preflight policy"
        return AbortResult(reason=f"preflight402: {reasons}")

    # -------------------------------------------------------------- internals

    def _cached(self, key: tuple) -> GuardDecision | None:
        if self._cache_ttl_s <= 0:
            return None
        entry = self._cache.get(key)
        if entry is None:
            return None
        expires, decision = entry
        if time.monotonic() >= expires:
            self._cache.pop(key, None)
            return None
        return decision

    async def _fetch(self, url: str) -> tuple[dict[str, Any] | None, str | None, bool]:
        try:
            async with httpx.AsyncClient(timeout=self._timeout_s) as client:
                response = await client.get(f"{self._service_url}/preflight", params={"url": url})
            return self._parse(response)
        except Exception as exc:
            return None, f"preflight service unreachable ({type(exc).__name__})", False

    def _fetch_sync(self, url: str) -> tuple[dict[str, Any] | None, str | None, bool]:
        try:
            with httpx.Client(timeout=self._timeout_s) as client:
                response = client.get(f"{self._service_url}/preflight", params={"url": url})
            return self._parse(response)
        except Exception as exc:
            return None, f"preflight service unreachable ({type(exc).__name__})", False

    @staticmethod
    def _parse(response: httpx.Response) -> tuple[dict[str, Any] | None, str | None, bool]:
        """(document, problem, refused). `refused` marks a service JUDGMENT
        (4xx: invalid URL, SSRF-blocked target) rather than a service failure
        — an endpoint whose resource URL our service refuses to probe must
        NOT slip through fail-open (attackers would point resource.url at a
        private address precisely to launder past the check). 429 and 5xx
        are genuine availability problems and stay on the fail-open path."""
        status = response.status_code
        if status != 200:
            refused = 400 <= status < 500 and status != 429
            label = "refused the URL" if refused else "returned"
            return None, f"preflight service {label} (HTTP {status})", refused
        try:
            document = response.json()
        except ValueError:
            return None, "preflight service returned invalid JSON", False
        if not isinstance(document, dict) or "verdict" not in document:
            return None, "preflight service returned an unexpected document", False
        return document, None, False

    def _decide(
        self,
        key: tuple,
        document: dict[str, Any] | None,
        failure: str | None,
        refused: bool,
        local_price_usd: float | None,
        local_pay_to: str | None,
    ) -> GuardDecision:
        url = key[0]
        if document is None:
            allowed = self._fail_open and not refused
            decision = GuardDecision(
                url=url,
                allowed=allowed,
                action="warn" if allowed else "block",
                recommendation=None,
                reasons=[failure or "no verdict available"],
            )
            return self._finish(key, decision)

        verdict = document.get("verdict") or {}
        recommendation = verdict.get("recommendation")
        verdict_reasons = [r for r in (verdict.get("reasons") or []) if isinstance(r, str)]
        blocked: list[str] = []

        if recommendation in self._block:
            blocked.append(f"verdict is '{recommendation}'")

        price = local_price_usd
        if price is None:
            endpoint_price = (document.get("endpoint") or {}).get("price") or {}
            observed = endpoint_price.get("usd_estimate")
            price = float(observed) if isinstance(observed, (int, float)) else None
        if self._max_price_usd is not None and price is not None and price > self._max_price_usd:
            blocked.append(f"price ${price:.6g} exceeds your ${self._max_price_usd:.6g} ceiling")

        if self._verify_payee and local_pay_to:
            observed = (document.get("endpoint") or {}).get("pay_to")
            if isinstance(observed, str) and observed and observed.lower() != local_pay_to.lower():
                blocked.append(
                    "selected payment recipient differs from the payee the preflighted"
                    f" endpoint advertises ({local_pay_to} vs {observed}) — possible"
                    " resource-URL spoof"
                )

        erc = (document.get("reputation") or {}).get("erc8004") or {}
        if self._require_bound and erc.get("bound") is not True:
            blocked.append("payee has no bound ERC-8004 identity")
        filtered = erc.get("filtered_score")
        if (
            self._min_filtered_score is not None
            and isinstance(filtered, (int, float))
            and filtered < self._min_filtered_score
        ):
            blocked.append(
                f"sybil-filtered reputation {filtered} is below your"
                f" {self._min_filtered_score} floor"
            )

        if blocked:
            decision = GuardDecision(
                url=url,
                allowed=False,
                action="block",
                recommendation=recommendation,
                reasons=blocked + verdict_reasons,
                document=document,
            )
        elif recommendation in self._warn:
            decision = GuardDecision(
                url=url,
                allowed=True,
                action="warn",
                recommendation=recommendation,
                reasons=verdict_reasons,
                document=document,
            )
        else:
            decision = GuardDecision(
                url=url,
                allowed=True,
                action="allow",
                recommendation=recommendation,
                reasons=verdict_reasons,
                document=document,
            )
        return self._finish(key, decision)

    def _no_url_decision(self) -> GuardDecision:
        action = "warn" if self._fail_open else "block"
        return GuardDecision(
            url="<unknown>",
            allowed=self._fail_open,
            action=action,
            recommendation=None,
            reasons=["402 response carried no resource URL to preflight"],
        )

    def _finish(self, key: tuple, decision: GuardDecision) -> GuardDecision:
        url = key[0]
        if self._cache_ttl_s > 0 and url != "<unknown>":
            self._cache[key] = (time.monotonic() + self._cache_ttl_s, decision)
        if decision.action == "warn":
            logger.warning(
                "preflight402 warning for %s: %s", url, "; ".join(decision.reasons) or "caution"
            )
        if self._on_decision is not None:
            try:
                self._on_decision(decision)
            except Exception:  # a broken callback must not affect the payment path
                logger.exception("on_decision callback failed")
        return decision


def _resource_url(ctx: Any) -> str | None:
    """Best-effort extraction of the endpoint URL from an x402 hook context.

    V2: payment_required.resource.url. V1: each accepts entry carries its own
    resource string — take the selected requirement's."""
    resource = getattr(getattr(ctx, "payment_required", None), "resource", None)
    url = getattr(resource, "url", None)
    if isinstance(url, str) and url:
        return url
    selected = getattr(ctx, "selected_requirements", None)
    v1_resource = getattr(selected, "resource", None)
    if isinstance(v1_resource, str) and v1_resource:
        return v1_resource
    return None


def _selected_pay_to(ctx: Any) -> str | None:
    """The recipient address of the requirements the client selected."""
    pay_to = getattr(getattr(ctx, "selected_requirements", None), "pay_to", None)
    return pay_to if isinstance(pay_to, str) and pay_to else None


def _selected_price_usd(ctx: Any) -> float | None:
    """USD price of the requirements the client actually selected, when the
    asset is a known USD stablecoin. This is what would really be signed."""
    selected = getattr(ctx, "selected_requirements", None)
    if selected is None:
        return None
    network = str(getattr(selected, "network", "") or "").lower()
    asset = str(getattr(selected, "asset", "") or "").lower()
    decimals = _KNOWN_USD_ASSETS.get((network, asset))
    if decimals is None:
        return None
    get_amount = getattr(selected, "get_amount", None)
    amount = get_amount() if callable(get_amount) else getattr(selected, "amount", None)
    if not isinstance(amount, str) or not amount.isdigit():
        return None
    try:
        return int(amount) / 10**decimals
    except OverflowError:
        return None
