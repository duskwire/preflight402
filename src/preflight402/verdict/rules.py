"""Verdict engine v0 — the rules table from build-plan §2, implementable day one.

- avoid:   unreachable/dead, expired or invalid TLS, malformed or missing 402,
           price > $5. (Known-decoy patterns arrive with M3.4's heuristics.)
- caution: single probe only, new provider (<7d observed), p99 > 5000ms or a
           single probe > 5s, price outside $0.0001-$1, TLS expiring <14d,
           valid 402 with non-spec-compliant fields (x402 or MPP side),
           plain-HTTP endpoint, price not in a recognized USD asset,
           body-read failure, an above-cap offer beside a cheaper one,
           TLS details unavailable (inspection-side transient).
- proceed: valid handshake + healthy latency + sane price.
- confidence: low = 1 probe; medium = 2-19; high = >=20 probes over >=7 days.

M6.3 reputation gates: only the Sybil-FILTERED reputation of a BOUND ERC-8004
identity moves a verdict — raw feedback is manipulable and never does. With
at least REPUTATION_MIN_CLUSTERS independent reviewer clusters:
  - a poor filtered score adds a caution (can demote proceed, never forces
    avoid on its own — a hostile review campaign must not be able to kill an
    agent through us);
  - a strong filtered score vouches for the OPERATOR: it waives only the
    thin-observation cautions (single probe / new provider) into a
    proceed/medium, because independent reviewers supply the evidence our
    own probe history hasn't accrued yet. It never waives operational
    problems (TLS, price, spec deviations, latency).

All USD estimates are v0: a small table of known USD stablecoins at 1:1 plus
MPP's 'usd' currency (base units = cents). Anything else is honest about
being unpriceable rather than guessed.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import UTC, datetime

from preflight402.probe.parsers import Detection
from preflight402.probe.parsers.types import ATOMIC_AMOUNT
from preflight402.probe.prober import ProbeResult
from preflight402.reputation.types import Binding

PRICE_AVOID_ABOVE_USD = 5.0
PRICE_TYPICAL_USD = (0.0001, 1.0)
SLOW_MS = 5000.0
TLS_EXPIRING_SOON_DAYS = 14
NEW_PROVIDER_DAYS = 7
HIGH_CONFIDENCE_PROBES = 20
HIGH_CONFIDENCE_DAYS = 7
# M3.4 heuristics (flag names track x402station's categories):
DEAD_CONSECUTIVE_FAILS = 3  # trailing transport failures -> flag `dead`
ZOMBIE_CONSECUTIVE_NON402 = 3  # trailing answered-but-no-402 -> flag `zombie`
DECOY_PRICE_EXTREME_USD = 50.0  # 10x the avoid cap -> flag `decoy_price_extreme`
# M6.3 reputation gates. The cluster floor keeps a single (possibly hostile,
# possibly self-serving) reviewer cluster from moving a verdict in either
# direction; between the two score bands reputation is deliberately neutral.
REPUTATION_MIN_CLUSTERS = 3
REPUTATION_GOOD_SCORE = 80.0
REPUTATION_BAD_SCORE = 40.0

USDC_BASE = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"
USDC_POLYGON = "0x3c499c542cef5e3811e1192ce70d8cc03d5c3359"
USDC_SOLANA = "epjfwdd5aufqssqem2qn1xzybapc8g4wegGkzwytdt1v".lower()

# (network id, asset id) -> decimals, both lowercased; USD stablecoins at 1:1.
# v1 slug networks alias their CAIP-2 ids.
KNOWN_USD_ASSETS: dict[tuple[str, str], int] = {}
for _networks, _asset, _decimals in [
    (("eip155:8453", "base"), USDC_BASE, 6),
    (("eip155:137", "polygon"), USDC_POLYGON, 6),
    (("solana:5eykt4usfv8p8njdtrepy1vzqkqzkvdp", "solana"), USDC_SOLANA, 6),
]:
    for _network in _networks:
        KNOWN_USD_ASSETS[(_network, _asset)] = _decimals


@dataclass(slots=True)
class HistoryStats:
    """Aggregates from M3.3 rollups; single-probe callers pass None.

    The trailing runs are newest-first streaks over the most recent probes
    (INCLUDING the just-recorded current one — both the service and the
    scheduler record before evaluating): consecutive_failures counts ok=0
    probes, consecutive_non402 counts answered-but-not-402 probes. At most
    one of them is non-zero.
    """

    probe_count: int
    observed_days: float
    uptime_7d: float | None = None
    p50_ms: float | None = None
    p99_ms: float | None = None
    consecutive_failures: int = 0
    consecutive_non402: int = 0


@dataclass(slots=True)
class Verdict:
    recommendation: str  # proceed | caution | avoid
    confidence: str  # low | medium | high
    score: int  # 0-100
    reasons: list[str]
    is_payment_endpoint: bool
    price_usd: float | None  # cheapest priceable offer, for endpoint.price
    flags: list[str] = field(default_factory=list)  # M3.4: dead | zombie |
    # decoy_price_extreme | new_provider — surfaced as authenticity.flags


def is_payment_shaped(probe: ProbeResult, detection: Detection) -> bool:
    """A live 402 carrying parseable payment terms.

    The single source of truth for 'is this a payment endpoint' — evaluate()
    derives its verdict field from it, and service persistence decides with
    it which URLs may create endpoint rows. Keep them the same predicate or
    the probe schedule and the verdicts drift apart.
    """
    return bool(probe.ok and probe.http_status == 402 and detection.is_payment_endpoint)


def evaluate(
    probe: ProbeResult,
    detection: Detection,
    *,
    history: HistoryStats | None = None,
    first_seen_at: str | None = None,
    binding: Binding | None = None,
    now: str | None = None,
) -> Verdict:
    """Apply the v0 rules table. Worst triggered tier wins.

    `now` (canonical ISO string) is injectable for tests; wall clock
    otherwise. `first_seen_at` comes from the endpoints row when known.
    `binding` (M5/M6) contributes only its Sybil-filtered reputation, per the
    module docstring's reputation gates.
    """
    now_dt = _parse_ts(now) or datetime.now(UTC)
    avoid: list[str] = []
    caution: list[str] = []
    positive: list[str] = []
    flags: list[str] = []

    is_payment = is_payment_shaped(probe, detection)

    # --- history-backed heuristics (M3.4): dead / zombie ---
    # The trailing runs include the current probe, so these de-flake the
    # single-probe judgements: one bad probe stays a per-probe reason, a
    # streak becomes a named condition.
    if history is not None:
        if history.consecutive_failures >= DEAD_CONSECUTIVE_FAILS:
            avoid.append(
                f"dead endpoint ({history.consecutive_failures} consecutive failed probes)"
            )
            flags.append("dead")
        elif history.consecutive_non402 >= ZOMBIE_CONSECUTIVE_NON402:
            avoid.append(
                "zombie: registered but serving no 402"
                f" ({history.consecutive_non402} consecutive non-402 responses)"
            )
            flags.append("zombie")

    # --- reachability + handshake ---
    if not probe.ok:
        avoid.append(f"unreachable ({probe.error})")
    elif probe.http_status != 402:
        avoid.append(f"no 402 payment challenge (HTTP {probe.http_status})")
    elif not detection.is_payment_endpoint:
        avoid.append("malformed 402: no parseable payment terms")
    else:
        if detection.payment is not None:
            # A 402 whose x402 side carries zero usable offers (e.g. an
            # undecodable PAYMENT-REQUIRED header over a junk body) is a
            # malformed 402, not merely non-compliant — a decoy must not
            # upgrade itself from avoid to caution by serving garbage.
            if not detection.payment.accepts and not detection.mpp.mpp_capable:
                avoid.append("malformed 402: no usable payment terms")
            if detection.spec_compliant is False:
                caution.append(
                    _deviation_reason("non-spec-compliant 402", detection.payment.warnings)
                )
            elif detection.payment.accepts:
                label = {"x402-v2": "x402 v2", "x402-v1": "x402 v1"}[detection.protocol]
                positive.append(f"valid {label} handshake")
        elif detection.mpp.warnings:
            # spec_compliant reflects only the x402 payload; pure-MPP
            # endpoints are judged on their own challenge deviations.
            caution.append(
                _deviation_reason("non-spec-compliant MPP challenge", detection.mpp.warnings)
            )
        else:
            positive.append("valid MPP handshake")
        if detection.payment is not None and detection.mpp_capable:
            if detection.mpp.warnings:
                caution.append(
                    _deviation_reason("MPP challenge has deviations", detection.mpp.warnings)
                )
            else:
                positive.append("MPP-capable (accepts Payment challenges)")
        if probe.error:
            caution.append(f"response body read failed ({probe.error})")

    # --- TLS ---
    if probe.tls is not None:
        expires_dt = _parse_ts(probe.tls.expires_at)
        has_cert_evidence = expires_dt is not None or probe.tls.issuer is not None
        if not probe.tls.valid:
            if (expires_dt is not None and expires_dt <= now_dt) or (
                "expired" in (probe.tls.error or "")
            ):
                avoid.append("TLS certificate expired")
            elif has_cert_evidence:
                avoid.append(f"TLS verification failed ({probe.tls.error})")
            elif probe.ok:
                # A successful https GET means httpx already verified the
                # chain end-to-end; a cert-less failure of the separate
                # inspection handshake (RST, rate limit on the second
                # connection) is transient noise, not a TLS judgement.
                caution.append(f"TLS details unavailable (inspection failed: {probe.tls.error})")
            # else: no certificate was ever seen and the GET already failed —
            # that's the same network failure, not a TLS judgement.
        elif expires_dt is not None:
            days_left = (expires_dt - now_dt).total_seconds() / 86400
            if days_left < TLS_EXPIRING_SOON_DAYS:
                # floor(), not round(): a cert 13.7 days out must not read
                # "expires in 14 days" beside a rule that fired at <14.
                caution.append(f"TLS certificate expires in {math.floor(max(days_left, 0))} days")
    elif probe.ok:
        caution.append("plain-HTTP endpoint (no TLS)")

    # --- price sanity ---
    candidates = _usd_candidates(detection)
    price_usd = min(candidates) if candidates else None
    if is_payment:
        if price_usd is None:
            caution.append("price not in a recognized USD asset (cannot sanity-check)")
        elif price_usd > PRICE_AVOID_ABOVE_USD:
            avoid.append(
                f"price ${_fmt_usd(price_usd)} exceeds the ${PRICE_AVOID_ABOVE_USD:.0f} cap"
            )
            if price_usd > DECOY_PRICE_EXTREME_USD:
                # 10x past the cap is not a pricing decision, it's bait for
                # agents that skip sanity checks.
                flags.append("decoy_price_extreme")
        else:
            # min() is "the price" an agent would pay, but an above-cap offer
            # on another network must not be silently blessed — an agent that
            # only speaks that chain pays it.
            highest = max(candidates)
            over_cap = highest > PRICE_AVOID_ABOVE_USD
            if over_cap:
                caution.append(
                    f"an offer costs ${_fmt_usd(highest)}, above the"
                    f" ${PRICE_AVOID_ABOVE_USD:.0f} cap (cheapest is ${_fmt_usd(price_usd)})"
                )
            if not (PRICE_TYPICAL_USD[0] <= price_usd <= PRICE_TYPICAL_USD[1]):
                caution.append(
                    f"price ${_fmt_usd(price_usd)} outside the typical"
                    f" ${PRICE_TYPICAL_USD[0]}-${PRICE_TYPICAL_USD[1]:.0f} range"
                )
            elif not over_cap:
                positive.append(f"price ${_fmt_usd(price_usd)} within category norms")

    # --- latency ---
    if history is not None and history.p99_ms is not None:
        if history.p99_ms > SLOW_MS:
            caution.append(f"p99 latency {history.p99_ms:.0f}ms exceeds {SLOW_MS:.0f}ms")
        else:
            positive.append(f"healthy latency (p99 {history.p99_ms:.0f}ms)")
    elif probe.ok and probe.latency_ms is not None:
        if probe.latency_ms > SLOW_MS:
            caution.append(f"slow response ({probe.latency_ms:.0f}ms)")
        else:
            positive.append(f"responded in {probe.latency_ms:.0f}ms")

    # --- history depth + provider age ---
    # These two cautions say "WE haven't observed enough yet", not "something
    # is wrong" — they are the only cautions strong filtered reputation may
    # waive below.
    thin_observation: list[str] = []
    probe_count = history.probe_count if history is not None else 1
    observed_days = history.observed_days if history is not None else 0.0
    if probe_count <= 1:
        thin_observation.append("single probe only (no history)")
    elif history is not None and history.uptime_7d is not None:
        positive.append(f"{history.uptime_7d:.1f}% uptime over 7d")

    first_seen_dt = _parse_ts(first_seen_at)
    if first_seen_dt is not None:
        age_days = (now_dt - first_seen_dt).total_seconds() / 86400
        if age_days < NEW_PROVIDER_DAYS:
            thin_observation.append(
                f"new provider (first seen {math.floor(max(age_days, 0))} days ago)"
            )
            flags.append("new_provider")
    caution.extend(thin_observation)

    # --- ERC-8004 reputation (M6.3 gates, see module docstring) ---
    # Gate on SCORED clusters (not filtered_count): tag-only feedback creates
    # real clusters with no score, and padding the count with them must not
    # let a single scoring cluster move a verdict.
    sybil = binding.sybil if binding is not None and binding.status == "bound" else None
    reputation_vouches = False
    if (
        sybil is not None
        and sybil.status.startswith("complete")
        and sybil.filtered_score is not None
        and sybil.scored_clusters >= REPUTATION_MIN_CLUSTERS
    ):
        # Defense-in-depth clamp: ingestion already bounds each feedback value
        # to 0-100 (subgraph.py), but a band comparison on adversary-derived
        # numbers must never trust a producer, and the reason string prints
        # "/100".
        filtered = min(100.0, max(0.0, sybil.filtered_score))
        clusters = f"{sybil.scored_clusters} independent reviewer clusters"
        if filtered < REPUTATION_BAD_SCORE:
            # :.1f, not :.0f — a 39.7 must not read "40/100" beside a rule
            # that fired at <40 (same convention as _fmt_usd and the TLS
            # floor()).
            caution.append(
                f"bound agent's sybil-filtered reputation is poor"
                f" ({filtered:.1f}/100 across {clusters})"
            )
        elif filtered >= REPUTATION_GOOD_SCORE:
            reputation_vouches = True
            positive.append(
                f"bound agent has strong sybil-filtered reputation"
                f" ({filtered:.1f}/100 across {clusters})"
            )

    # --- roll up ---
    if avoid:
        recommendation = "avoid"
        reasons = avoid + caution
        score = max(5, 20 - 5 * (len(avoid) - 1))
    elif caution:
        if reputation_vouches and all(reason in thin_observation for reason in caution):
            # Independent reviewers supply the evidence our own history
            # hasn't accrued yet — but only the thin-observation cautions are
            # waivable, and the caveats stay visible beside the vouch.
            recommendation = "proceed"
            reasons = positive + caution
            score = 75
        else:
            recommendation = "caution"
            reasons = caution
            score = max(30, 65 - 10 * (len(caution) - 1))
    else:
        recommendation = "proceed"
        reasons = positive
        score = 80
        if history is not None and (history.uptime_7d or 0) >= 99.0:
            score += 5
        if reputation_vouches:
            score += 5  # the reserved reputation points (score cap stays 95)

    if probe_count >= HIGH_CONFIDENCE_PROBES and observed_days >= HIGH_CONFIDENCE_DAYS:
        confidence = "high"
        if recommendation == "proceed":
            score += 5
    elif probe_count >= 2:
        confidence = "medium"
    else:
        confidence = "low"
    if reputation_vouches and recommendation == "proceed" and confidence == "low":
        # The vouch is real corroborating evidence from an independent source;
        # a reputation-upgraded proceed must not read as "low confidence".
        confidence = "medium"

    return Verdict(
        recommendation=recommendation,
        confidence=confidence,
        score=min(score, 95),
        reasons=reasons,
        is_payment_endpoint=is_payment,
        price_usd=price_usd,
        flags=flags,
    )


@dataclass(slots=True)
class PricedOffer:
    """One offer that could be priced in USD (schema assembly reuses these)."""

    usd: float
    amount: str  # atomic units, as offered on the wire
    decimals: int
    network: str | None
    asset: str | None  # token address, or 'usd' for MPP fiat
    pay_to: str | None


def estimate_price_usd(detection: Detection) -> float | None:
    """Cheapest priceable offer in USD, or None when nothing is recognizable.

    An agent picks the cheapest acceptable option, so the minimum is 'the
    price'. Only known USD stablecoins and MPP 'usd' amounts (cents) are
    priced — no oracle guesses in v0.
    """
    candidates = _usd_candidates(detection)
    return min(candidates) if candidates else None


def priced_offers(detection: Detection) -> list[PricedOffer]:
    """Every recognizable offer in USD. Hostile amounts never raise or price:

    only strict atomic-digit strings are converted (int() would happily read
    '-50', '1_0' or '+5' that the parsers warn-and-preserved), and amounts
    beyond float range (OverflowError, ~309+ digits) are skipped.
    """
    offers: list[PricedOffer] = []
    if detection.payment is not None:
        for option in detection.payment.accepts:
            if not (option.amount and option.network and option.asset):
                continue
            if not ATOMIC_AMOUNT.match(option.amount):
                continue
            decimals = KNOWN_USD_ASSETS.get((option.network.lower(), option.asset.lower()))
            if decimals is None:
                continue
            try:
                usd = int(option.amount) / 10**decimals
            except OverflowError:
                continue
            offers.append(
                PricedOffer(
                    usd=usd,
                    amount=option.amount,
                    decimals=decimals,
                    network=option.network,
                    asset=option.asset,
                    pay_to=option.pay_to,
                )
            )
    for challenge in detection.mpp.challenges:
        if not challenge.amount or (challenge.currency or "").lower() != "usd":
            continue
        if not ATOMIC_AMOUNT.match(challenge.amount):
            continue
        try:
            usd = int(challenge.amount) / 100  # base units = cents
        except OverflowError:
            continue
        offers.append(
            PricedOffer(
                usd=usd,
                amount=challenge.amount,
                decimals=2,
                network=None,
                asset="usd",
                pay_to=challenge.recipient,
            )
        )
    return offers


def _usd_candidates(detection: Detection) -> list[float]:
    return [offer.usd for offer in priced_offers(detection)]


def _fmt_usd(value: float) -> str:
    """Format a USD value without rounding it across a rule boundary.

    :.4f would render $0.00005 as the in-range-looking '$0.0001' right next
    to the out-of-range rule that fired on it.
    """
    text = f"{value:.10f}".rstrip("0").rstrip(".")
    return text or "0"


def _deviation_reason(prefix: str, warnings: list[str]) -> str:
    plural = "s" if len(warnings) != 1 else ""
    return f"{prefix} ({len(warnings)} deviation{plural}, e.g. {warnings[0]})"


def _parse_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
