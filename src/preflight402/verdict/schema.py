"""trust-preview.v1 document assembly.

The free tier returns the full structure with the paid fields null:
health.history (deep_report), authenticity.reseller_probability
(trust_verdict), and the reputation counts/score (M5+). Fields are
additive-only within v1 per the build plan; the formal JSON Schema file
ships at M8.
"""

from __future__ import annotations

from typing import Any

from preflight402.db.connection import utcnow_iso
from preflight402.probe.parsers import Detection
from preflight402.probe.prober import ProbeResult
from preflight402.reputation.types import Binding
from preflight402.verdict.rules import KNOWN_USD_ASSETS, Verdict, priced_offers


def payee_address(detection: Detection) -> str | None:
    """The payTo an agent would actually pay: the cheapest priceable offer's,
    else the first accepts entry with a payTo. Shared by the schema's pay_to
    field and the M5 binding lookup so they always describe the same rail."""
    offers = priced_offers(detection)
    if offers:
        return min(offers, key=lambda offer: offer.usd).pay_to
    accepts = detection.payment.accepts if detection.payment is not None else []
    return next((option.pay_to for option in accepts if option.pay_to), None)


def build_trust_preview(
    url: str,
    probe: ProbeResult,
    detection: Detection,
    verdict: Verdict,
    *,
    binding: Binding | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Assemble the trust-preview.v1 response for one preflight."""
    offers = priced_offers(detection)
    cheapest = min(offers, key=lambda offer: offer.usd) if offers else None
    accepts = detection.payment.accepts if detection.payment is not None else []

    assets = []
    for option in accepts:
        if option.network and option.asset:
            known = (option.network.lower(), option.asset.lower()) in KNOWN_USD_ASSETS
            assets.append(
                {
                    "network": option.network,
                    "asset": option.asset,
                    "symbol": "USDC" if known else None,
                }
            )

    # price and pay_to describe ONE offer — the cheapest priceable one — so
    # they must never be spliced from different offers. When that offer is an
    # MPP fiat challenge, its rail (network/asset) differs from the x402
    # accepts in networks/assets, so the price block names its own rail. Only
    # when nothing is priceable does pay_to fall back to the x402 accepts,
    # which is the same rail the networks/assets block describes.
    if cheapest is not None:
        price = {
            "amount": cheapest.amount,
            "decimals": cheapest.decimals,
            "usd_estimate": verdict.price_usd,
            "network": cheapest.network,
            "asset": cheapest.asset,
        }
        pay_to = cheapest.pay_to
    else:
        price = None
        pay_to = next((option.pay_to for option in accepts if option.pay_to), None)

    # spec_compliant and warnings must share a scope, or a consumer sees
    # "compliant: true" beside listed deviations. Judge the handshake as
    # compliant iff there are no warnings from any protocol side; None only
    # when there was no valid 402 to judge.
    combined_warnings = detection.warnings
    handshake_compliant = None if not verdict.is_payment_endpoint else not combined_warnings

    reasons = list(verdict.reasons)
    # The acceptance-criteria presentation: google.com is not dangerous, it
    # just isn't a payment endpoint — say that first and plainly. A 5xx is an
    # erroring endpoint, not a permanent classification, so keep the verdict
    # engine's honest "no 402 challenge (HTTP 503)" reason there.
    non_payment_status = (
        probe.http_status is not None and probe.http_status != 402 and probe.http_status < 500
    )
    if not verdict.is_payment_endpoint and probe.ok and non_payment_status:
        reasons = [f"not a payment endpoint (HTTP {probe.http_status}, no 402 challenge)"] + [
            reason for reason in reasons if "no 402 payment challenge" not in reason
        ]

    return {
        "schema": "trust-preview.v1",
        "generated_at": generated_at or utcnow_iso(),
        "endpoint": {
            "url": url,
            "payment_endpoint": verdict.is_payment_endpoint,
            "protocol": detection.protocol if detection.protocol != "none" else None,
            "mpp_capable": detection.mpp_capable,
            "networks": detection.payment.networks if detection.payment is not None else [],
            "assets": assets,
            "price": price,
            "pay_to": pay_to,
        },
        "health": {
            "status": "up" if probe.ok else "down",
            "method": probe.method,  # GET, or POST when the endpoint 405s a GET
            "latency_ms": round(probe.latency_ms, 1) if probe.latency_ms is not None else None,
            "error": probe.error,
            "ssl": (
                {
                    "valid": probe.tls.valid,
                    "expires_at": probe.tls.expires_at,
                    "issuer": probe.tls.issuer,
                }
                if probe.tls is not None
                else None
            ),
            "handshake": {
                "valid_402": verdict.is_payment_endpoint,
                "spec_compliant": handshake_compliant,
                "warnings": combined_warnings,
            },
            "history": None,  # paid tier; populated from M3 rollups
        },
        "authenticity": {
            "reseller_probability": None,  # paid tier (M8)
            "upstream_fingerprints": [],
            "flags": verdict.flags,  # M3.4: dead | zombie | decoy_price_extreme | new_provider
        },
        "reputation": {"erc8004": _erc8004_block(binding)},
        "verdict": {
            "recommendation": verdict.recommendation,
            "confidence": verdict.confidence,
            "score": verdict.score,
            "reasons": reasons,
        },
    }


def _erc8004_block(binding: Binding | None) -> dict[str, Any]:
    """The reputation.erc8004 sub-block. `binding_status` is the honest signal so
    a failed subgraph lookup is never reported as a real "no agent":
      None binding  -> not_checked (feature off / no payTo): bound=null
      status error  -> could not determine (subgraph failed): bound=null
      status unbound-> checked, no agent: bound=false
      status bound  -> bound=true, populated
    M6 mirrors the convention with `sybil_status`:
      not_checked -> the filter did not run (feature off / unbound / no feedback)
      pending     -> the funding cache is still warming: counts stay null
                     rather than report a number from partial coverage
      complete    -> sybil_filtered_count/filtered_score are populated
      complete_truncated -> populated, but computed over a page-capped feedback
                     window (agents with more feedback than one subgraph page)"""
    status = "not_checked" if binding is None else binding.status
    # bound is only a definite boolean when we actually determined it; a failed
    # lookup leaves it null (unknown), never a misleading False.
    bound = {"bound": True, "unbound": False}.get(status) if binding else None
    block = {
        "bound": bound,
        "binding_status": status,
        "agent_id": None,
        "binding_method": None,
        "binding_confidence": None,
        "raw_feedback_count": None,
        "distinct_reviewers": None,
        "raw_average_score": None,
        "sybil_status": "not_checked",  # M6
        "sybil_filtered_count": None,  # M6
        "filtered_score": None,  # M6
    }
    if binding is None or binding.status != "bound" or binding.agent is None:
        return block
    reputation = binding.reputation
    block.update(
        {
            "agent_id": binding.agent.agent_id,
            "binding_method": binding.method,
            "binding_confidence": binding.confidence,
            "raw_feedback_count": reputation.raw_feedback_count if reputation else 0,
            "distinct_reviewers": reputation.distinct_reviewers if reputation else 0,
            "raw_average_score": reputation.average_score if reputation else None,
        }
    )
    sybil = binding.sybil
    if sybil is not None:
        block["sybil_status"] = sybil.status
        if sybil.status.startswith("complete"):
            block["sybil_filtered_count"] = sybil.filtered_count
            block["filtered_score"] = sybil.filtered_score
    return block
