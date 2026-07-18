import base64
import json

from preflight402.probe.parsers import detect
from preflight402.probe.prober import ProbeResult
from preflight402.probe.tls import TLSInfo
from preflight402.verdict.rules import HistoryStats, estimate_price_usd, evaluate

NOW = "2026-07-15T12:00:00.000Z"
USDC_BASE = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"

GOOD_TLS = TLSInfo(valid=True, expires_at="2027-01-01T00:00:00.000Z", issuer="Let's Encrypt")
GOOD_HISTORY = HistoryStats(
    probe_count=25, observed_days=8.0, uptime_7d=99.5, p50_ms=210.0, p99_ms=800.0
)


def _payload(amount: str = "10000", **overrides) -> dict:
    payload = {
        "x402Version": 2,
        "resource": {"url": "https://api.example.com/data"},
        "accepts": [
            {
                "scheme": "exact",
                "network": "eip155:8453",
                "amount": amount,
                "asset": USDC_BASE,
                "payTo": "0x" + "ab" * 20,
                "maxTimeoutSeconds": 300,
            }
        ],
    }
    payload.update(overrides)
    return payload


def _detection(payload: dict | None = None, headers: dict | None = None, body: str = "{}"):
    headers = dict(headers or {})
    if payload is not None:
        headers["payment-required"] = base64.b64encode(json.dumps(payload).encode()).decode()
    return detect(headers, body)


def _probe(**overrides) -> ProbeResult:
    defaults = dict(
        url="https://api.example.com/data",
        ok=True,
        http_status=402,
        latency_ms=234.0,
        tls=GOOD_TLS,
    )
    defaults.update(overrides)
    return ProbeResult(**defaults)


def _evaluate(probe=None, detection=None, **kwargs):
    kwargs.setdefault("now", NOW)
    return evaluate(
        probe if probe is not None else _probe(),
        detection if detection is not None else _detection(_payload()),
        **kwargs,
    )


# --- avoid branches -----------------------------------------------------------


def test_unreachable_is_avoid() -> None:
    verdict = _evaluate(_probe(ok=False, error="dns", http_status=None, latency_ms=50.0, tls=None))
    assert verdict.recommendation == "avoid"
    assert verdict.is_payment_endpoint is False
    assert any("unreachable (dns)" in r for r in verdict.reasons)
    assert verdict.confidence == "low"
    # Guards that keep unrelated rules out of non-payment verdicts:
    assert not any("price" in r for r in verdict.reasons)
    assert not any("plain-HTTP" in r for r in verdict.reasons)


def test_unreachable_https_does_not_double_report_tls() -> None:
    # DNS-dead https URL: the TLS side also failed, but saw no certificate —
    # one network failure must not surface as two independent reasons.
    dead_tls = TLSInfo(valid=False, error="Name or service not known")
    verdict = _evaluate(_probe(ok=False, error="dns", http_status=None, tls=dead_tls))
    assert verdict.recommendation == "avoid"
    assert not any("TLS verification failed" in r for r in verdict.reasons)


def test_non_402_status_is_avoid_and_not_payment_endpoint() -> None:
    verdict = _evaluate(_probe(http_status=200), _detection(None, body="<h1>hi</h1>"))
    assert verdict.recommendation == "avoid"
    assert verdict.is_payment_endpoint is False
    assert any("no 402 payment challenge (HTTP 200)" in r for r in verdict.reasons)
    assert not any("price" in r for r in verdict.reasons)


def test_402_without_parseable_terms_is_avoid() -> None:
    verdict = _evaluate(detection=_detection(None, body="pay me, somehow"))
    assert verdict.recommendation == "avoid"
    assert any("malformed 402" in r for r in verdict.reasons)


def test_expired_tls_is_avoid() -> None:
    expired = TLSInfo(
        valid=False, expires_at="2026-07-01T00:00:00.000Z", issuer="X", error="cert expired"
    )
    verdict = _evaluate(_probe(tls=expired))
    assert verdict.recommendation == "avoid"
    assert "TLS certificate expired" in verdict.reasons


def test_invalid_tls_with_cert_evidence_is_avoid() -> None:
    bad = TLSInfo(
        valid=False, expires_at="2027-01-01T00:00:00.000Z", issuer="X", error="self-signed"
    )
    verdict = _evaluate(_probe(tls=bad))
    assert verdict.recommendation == "avoid"
    assert any("TLS verification failed (self-signed)" in r for r in verdict.reasons)


def test_price_above_cap_is_avoid() -> None:
    verdict = _evaluate(detection=_detection(_payload(amount="10000000")))  # $10 USDC
    assert verdict.recommendation == "avoid"
    assert any("exceeds the $5 cap" in r for r in verdict.reasons)
    assert verdict.price_usd == 10.0


def test_avoid_reasons_include_cautions_and_score_floors() -> None:
    expired = TLSInfo(valid=False, expires_at="2026-07-01T00:00:00.000Z", error="expired")
    verdict = _evaluate(
        _probe(tls=expired), _detection(_payload(amount="10000000"))
    )  # expired TLS + $10 price + single probe caution
    assert verdict.recommendation == "avoid"
    assert len([r for r in verdict.reasons if "single probe" in r]) == 1
    assert 5 <= verdict.score <= 20


# --- caution branches -----------------------------------------------------------


def test_single_probe_is_caution() -> None:
    verdict = _evaluate()
    assert verdict.recommendation == "caution"
    assert "single probe only (no history)" in verdict.reasons
    assert verdict.confidence == "low"


def test_new_provider_is_caution() -> None:
    verdict = _evaluate(history=GOOD_HISTORY, first_seen_at="2026-07-13T00:00:00.000Z")
    assert verdict.recommendation == "caution"
    assert any("new provider (first seen 2 days ago)" in r for r in verdict.reasons)


def test_old_provider_is_not_new() -> None:
    verdict = _evaluate(history=GOOD_HISTORY, first_seen_at="2026-06-01T00:00:00.000Z")
    assert not any("new provider" in r for r in verdict.reasons)


def test_slow_p99_is_caution() -> None:
    slow = HistoryStats(probe_count=25, observed_days=8.0, uptime_7d=99.5, p99_ms=6500.0)
    verdict = _evaluate(history=slow)
    assert verdict.recommendation == "caution"
    assert any("p99 latency 6500ms" in r for r in verdict.reasons)


def test_slow_single_probe_is_caution() -> None:
    verdict = _evaluate(_probe(latency_ms=7000.0))
    assert any("slow response (7000ms)" in r for r in verdict.reasons)


def test_price_outside_typical_range_is_caution() -> None:
    high = _evaluate(detection=_detection(_payload(amount="2000000")))  # $2
    assert high.recommendation == "caution"
    assert any("outside the typical" in r for r in high.reasons)
    low = _evaluate(detection=_detection(_payload(amount="50")))  # $0.00005
    assert any("outside the typical" in r for r in low.reasons)


def test_unrecognized_asset_is_caution() -> None:
    payload = _payload()
    payload["accepts"][0]["asset"] = "0x" + "99" * 20
    verdict = _evaluate(detection=_detection(payload))
    assert any("not in a recognized USD asset" in r for r in verdict.reasons)
    assert verdict.price_usd is None


def test_tls_expiring_soon_is_caution() -> None:
    soon = TLSInfo(valid=True, expires_at="2026-07-20T12:00:00.000Z", issuer="X")
    verdict = _evaluate(_probe(tls=soon))
    assert any("TLS certificate expires in 5 days" in r for r in verdict.reasons)


def test_plain_http_is_caution() -> None:
    verdict = _evaluate(_probe(url="http://api.example.com/", tls=None))
    assert any("plain-HTTP endpoint" in r for r in verdict.reasons)


def test_non_spec_compliant_402_is_caution() -> None:
    payload = _payload()
    accept = payload["accepts"][0]
    accept["maxAmountRequired"] = accept.pop("amount")
    verdict = _evaluate(detection=_detection(payload))
    assert any("non-spec-compliant 402 (1 deviation" in r for r in verdict.reasons)


def test_body_read_failure_is_caution() -> None:
    verdict = _evaluate(_probe(error="timeout", body_truncated=True))
    assert any("body read failed (timeout)" in r for r in verdict.reasons)


def test_caution_score_decreases_with_reasons_and_floors_at_30() -> None:
    one = _evaluate()  # single-probe only
    many = _evaluate(
        _probe(url="http://x.example/", tls=None, latency_ms=9000.0),
        _detection(_payload(amount="2000000")),
        first_seen_at="2026-07-14T00:00:00.000Z",
    )
    assert one.score == 65
    assert many.score < one.score
    assert many.score >= 30


# --- proceed branch ---------------------------------------------------------------


def test_healthy_endpoint_with_history_is_proceed() -> None:
    verdict = _evaluate(history=GOOD_HISTORY, first_seen_at="2026-06-01T00:00:00.000Z")
    assert verdict.recommendation == "proceed"
    assert verdict.confidence == "high"
    assert verdict.score == 90  # 80 + 5 uptime + 5 high confidence
    assert verdict.is_payment_endpoint is True
    joined = " ".join(verdict.reasons)
    assert "valid x402 v2 handshake" in joined
    assert "99.5% uptime over 7d" in joined
    assert "healthy latency" in joined
    assert "within category norms" in joined
    # proceed reasons are positives only — no cautions leaked in
    assert "single probe" not in joined


def test_mpp_capable_x402_endpoint_gets_positive_reason() -> None:
    headers = {
        "www-authenticate": (
            'Payment realm="m", method="tempo", intent="charge", amount="1", recipient="0x1"'
        )
    }
    verdict = _evaluate(detection=_detection(_payload(), headers=headers), history=GOOD_HISTORY)
    assert verdict.recommendation == "proceed"
    assert any("MPP-capable" in r for r in verdict.reasons)


def test_pure_mpp_endpoint_is_a_payment_endpoint() -> None:
    headers = {
        "www-authenticate": (
            'Payment realm="m", method="stripe", intent="charge", amount="50", '
            'currency="usd", recipient="0x1"'
        )
    }
    verdict = _evaluate(detection=detect(headers, "{}"), history=GOOD_HISTORY)
    assert verdict.is_payment_endpoint is True
    assert verdict.recommendation == "proceed"
    assert any("valid MPP handshake" in r for r in verdict.reasons)
    assert verdict.price_usd == 0.5  # 50 cents


def test_mpp_without_currency_is_honestly_unpriceable() -> None:
    headers = {
        "www-authenticate": (
            'Payment realm="m", method="tempo", intent="charge", amount="50", recipient="0x1"'
        )
    }
    verdict = _evaluate(detection=detect(headers, "{}"), history=GOOD_HISTORY)
    assert verdict.price_usd is None
    assert any("not in a recognized USD asset" in r for r in verdict.reasons)


# --- review-hardened branches ---------------------------------------------------


def test_huge_amount_does_not_crash() -> None:
    # 400 digits passes the parser's atomic regex warning-free; int/float
    # division raises OverflowError, which must never escape evaluate().
    verdict = _evaluate(detection=_detection(_payload(amount="9" * 400)), history=GOOD_HISTORY)
    assert verdict.price_usd is None
    assert any("not in a recognized USD asset" in r for r in verdict.reasons)


def test_signed_or_garbled_amounts_are_never_priced() -> None:
    # int() happily reads '-50', '1_0', '+5', ' 5 ' — the pricer must not.
    for amount in ("-50", "1_0", "+5", " 5 "):
        headers = {
            "www-authenticate": (
                f'Payment method="tempo", intent="charge", amount="{amount}", '
                f'currency="usd", recipient="0x1"'
            )
        }
        verdict = evaluate(_probe(), detect(headers, "{}"), now=NOW)
        assert verdict.price_usd is None, amount


def test_transient_tls_inspection_failure_is_caution_not_avoid() -> None:
    # The GET succeeded over https, so httpx already verified the chain; a
    # cert-less failure of the second (inspection) handshake is transient
    # noise and must not flip a healthy endpoint to avoid.
    flaky = TLSInfo(valid=False, error="tls inspection failed: connection reset by peer")
    verdict = _evaluate(_probe(tls=flaky), history=GOOD_HISTORY)
    assert verdict.recommendation == "caution"
    assert any("TLS details unavailable" in r for r in verdict.reasons)
    assert not any("TLS verification failed" in r for r in verdict.reasons)


def test_invalid_tls_with_evidence_and_failed_get_is_still_avoid() -> None:
    # Self-signed reality: the GET dies on verification while the inspector
    # fetches the offending cert — the evidence arm must fire on its own.
    bad = TLSInfo(
        valid=False, expires_at="2027-01-01T00:00:00.000Z", issuer="X", error="self-signed"
    )
    verdict = _evaluate(_probe(ok=False, error="tls", http_status=None, tls=bad))
    assert verdict.recommendation == "avoid"
    assert any("TLS verification failed (self-signed)" in r for r in verdict.reasons)


def test_expired_tls_via_date_only_and_via_error_only() -> None:
    date_only = TLSInfo(
        valid=False, expires_at="2026-07-01T00:00:00.000Z", issuer="X", error="verify failed"
    )
    assert "TLS certificate expired" in _evaluate(_probe(tls=date_only)).reasons
    error_only = TLSInfo(valid=False, expires_at=None, issuer="X", error="certificate has expired")
    assert "TLS certificate expired" in _evaluate(_probe(tls=error_only)).reasons


def test_valid_tls_with_unparseable_cert_details_is_quiet() -> None:
    # tls.py produces valid=True/expires_at=None when the handshake verified
    # but cryptography rejected the DER — no crash, no TLS reason.
    odd = TLSInfo(valid=True, expires_at=None, issuer=None, error="cert unparseable: boom")
    verdict = _evaluate(_probe(tls=odd), history=GOOD_HISTORY)
    assert verdict.recommendation == "proceed"
    assert not any("TLS" in r for r in verdict.reasons)


def test_undecodable_header_with_junk_body_is_avoid() -> None:
    # A decoy must not upgrade itself from avoid to caution by serving
    # garbage base64 in the PAYMENT-REQUIRED header.
    detection = detect({"payment-required": "!!!not-base64!!!"}, "gibberish")
    verdict = _evaluate(detection=detection, history=GOOD_HISTORY)
    assert verdict.recommendation == "avoid"
    assert any("no usable payment terms" in r for r in verdict.reasons)


def test_boundary_reasons_do_not_contradict_the_rule() -> None:
    below = _evaluate(detection=_detection(_payload(amount="50")))  # $0.00005
    assert any("$0.00005 outside" in r for r in below.reasons)
    just_over = _evaluate(detection=_detection(_payload(amount="5000001")))  # $5.000001
    assert any("$5.000001 exceeds" in r for r in just_over.reasons)
    soon = TLSInfo(valid=True, expires_at="2026-07-29T05:00:00.000Z", issuer="X")  # 13.7d
    verdict = _evaluate(_probe(tls=soon))
    assert any("expires in 13 days" in r for r in verdict.reasons)


def test_price_boundaries_exact() -> None:
    at_cap = _evaluate(detection=_detection(_payload(amount="5000000")), history=GOOD_HISTORY)
    assert at_cap.recommendation == "caution"  # $5: outside typical, not above cap
    assert not any("exceeds" in r for r in at_cap.reasons)
    one_dollar = _evaluate(detection=_detection(_payload(amount="1000000")), history=GOOD_HISTORY)
    assert one_dollar.recommendation == "proceed"  # $1 is range-inclusive
    at_floor = _evaluate(detection=_detection(_payload(amount="100")), history=GOOD_HISTORY)
    assert at_floor.recommendation == "proceed"  # $0.0001 is range-inclusive
    free = _evaluate(detection=_detection(_payload(amount="0")), history=GOOD_HISTORY)
    assert free.recommendation == "caution"
    assert any("outside the typical" in r for r in free.reasons)


def test_above_cap_offer_on_another_network_cautions() -> None:
    payload = _payload(amount="5000")  # $0.005 on Base
    payload["accepts"].append(
        {
            "scheme": "exact",
            "network": "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
            "amount": "8000000",  # $8 on Solana — above the cap
            "asset": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
            "payTo": "recipient11111111111111111111111",
            "maxTimeoutSeconds": 300,
        }
    )
    verdict = _evaluate(detection=_detection(payload), history=GOOD_HISTORY)
    assert verdict.recommendation == "caution"
    assert any("above the $5 cap" in r for r in verdict.reasons)
    assert not any("within category norms" in r for r in verdict.reasons)
    assert verdict.price_usd == 0.005  # min stays "the price" for display


def test_pure_mpp_with_deviations_is_caution() -> None:
    # Unknown method + no recipient: literally unpayable — must not read
    # "proceed: valid MPP handshake".
    headers = {
        "www-authenticate": (
            'Payment realm="m", method="paypal", intent="charge", amount="50", currency="usd"'
        )
    }
    verdict = _evaluate(detection=detect(headers, "{}"), history=GOOD_HISTORY)
    assert verdict.recommendation == "caution"
    assert any("non-spec-compliant MPP challenge" in r for r in verdict.reasons)
    assert not any("valid MPP handshake" in r for r in verdict.reasons)


def test_dual_protocol_broken_mpp_is_not_a_positive() -> None:
    headers = {"www-authenticate": 'Payment realm="m", method="tempo"'}
    verdict = _evaluate(detection=_detection(_payload(), headers=headers), history=GOOD_HISTORY)
    assert verdict.recommendation == "caution"
    assert any("MPP challenge has deviations" in r for r in verdict.reasons)
    assert not any("MPP-capable" in r for r in verdict.reasons)


def test_v1_clean_body_evaluates_with_v1_handshake() -> None:
    body = json.dumps(
        {
            "x402Version": 1,
            "error": "X-PAYMENT header is required",
            "accepts": [
                {
                    "scheme": "exact",
                    "network": "base",
                    "maxAmountRequired": "5000",
                    "asset": USDC_BASE,
                    "payTo": "0x2",
                    "resource": "https://x.example/",
                    "description": "d",
                    "maxTimeoutSeconds": 60,
                }
            ],
        }
    )
    verdict = _evaluate(detection=detect({}, body), history=GOOD_HISTORY)
    assert verdict.recommendation == "proceed"
    assert any("valid x402 v1 handshake" in r for r in verdict.reasons)
    assert verdict.price_usd == 0.005


# --- confidence tiers --------------------------------------------------------------


def test_confidence_tiers() -> None:
    assert _evaluate().confidence == "low"  # 1 probe
    medium = _evaluate(history=HistoryStats(probe_count=5, observed_days=1.0))
    assert medium.confidence == "medium"
    not_long_enough = _evaluate(history=HistoryStats(probe_count=40, observed_days=3.0))
    assert not_long_enough.confidence == "medium"  # count high, span short
    high = _evaluate(history=HistoryStats(probe_count=20, observed_days=7.0, uptime_7d=99.9))
    assert high.confidence == "high"


def test_score_never_exceeds_95() -> None:
    verdict = _evaluate(history=GOOD_HISTORY)
    assert verdict.score <= 95  # headroom reserved for M5+ reputation


# --- price estimation ---------------------------------------------------------------


def test_estimate_price_picks_cheapest_recognized_offer() -> None:
    payload = _payload()
    payload["accepts"].append(
        {
            "scheme": "exact",
            "network": "eip155:8453",
            "amount": "5000",  # $0.005 — cheaper
            "asset": USDC_BASE,
            "payTo": "0x" + "cd" * 20,
            "maxTimeoutSeconds": 300,
        }
    )
    assert estimate_price_usd(_detection(payload)) == 0.005


def test_estimate_price_handles_v1_slug_networks() -> None:
    body = json.dumps(
        {
            "x402Version": 1,
            "error": "pay",
            "accepts": [
                {
                    "scheme": "exact",
                    "network": "base",
                    "maxAmountRequired": "1000000",
                    "asset": USDC_BASE,
                    "payTo": "0x2",
                    "resource": "https://x.example/",
                    "description": "d",
                    "maxTimeoutSeconds": 60,
                }
            ],
        }
    )
    assert estimate_price_usd(detect({}, body)) == 1.0


def test_estimate_price_skips_malformed_and_unknown() -> None:
    payload = _payload(amount="not-a-number")
    assert estimate_price_usd(_detection(payload)) is None
    unknown = _payload()
    unknown["accepts"][0]["network"] = "eip155:1"  # no known USD asset there
    assert estimate_price_usd(_detection(unknown)) is None


# --- M3.4 heuristics: dead / zombie / decoy / new-provider flags -------------


def _history(**overrides) -> HistoryStats:
    defaults = dict(probe_count=25, observed_days=8.0, uptime_7d=99.5)
    defaults.update(overrides)
    return HistoryStats(**defaults)


def test_dead_streak_is_avoid_with_flag() -> None:
    verdict = _evaluate(
        probe=_probe(ok=False, error="timeout", http_status=None, latency_ms=None, tls=None),
        detection=_detection(),
        history=_history(uptime_7d=10.0, consecutive_failures=3),
    )
    assert verdict.recommendation == "avoid"
    assert "dead" in verdict.flags
    assert any("dead endpoint (3 consecutive failed probes)" in r for r in verdict.reasons)


def test_two_failures_is_not_dead_yet() -> None:
    verdict = _evaluate(
        probe=_probe(ok=False, error="timeout", http_status=None, latency_ms=None, tls=None),
        detection=_detection(),
        history=_history(consecutive_failures=2),
    )
    assert "dead" not in verdict.flags  # still avoid (unreachable), but not flagged dead
    assert verdict.recommendation == "avoid"


def test_zombie_streak_is_avoid_with_flag() -> None:
    verdict = _evaluate(
        probe=_probe(http_status=404),
        detection=_detection(),
        history=_history(consecutive_non402=4),
    )
    assert verdict.recommendation == "avoid"
    assert "zombie" in verdict.flags
    assert any("zombie" in r for r in verdict.reasons)


def test_dead_takes_precedence_over_zombie() -> None:
    # the streaks are disjoint by construction; if both are somehow set,
    # dead (transport-level) is the stronger classification
    verdict = _evaluate(
        probe=_probe(ok=False, error="conn_refused", http_status=None, latency_ms=None, tls=None),
        detection=_detection(),
        history=_history(consecutive_failures=5, consecutive_non402=5),
    )
    assert "dead" in verdict.flags
    assert "zombie" not in verdict.flags


def test_healthy_history_has_no_heuristic_flags() -> None:
    verdict = _evaluate(history=GOOD_HISTORY)
    assert verdict.recommendation == "proceed"
    assert verdict.flags == []


def test_extreme_price_gets_decoy_flag() -> None:
    verdict = _evaluate(detection=_detection(_payload(amount="60000000")))  # $60
    assert verdict.recommendation == "avoid"
    assert "decoy_price_extreme" in verdict.flags


def test_above_cap_but_not_extreme_is_not_decoy_flagged() -> None:
    verdict = _evaluate(detection=_detection(_payload(amount="6000000")))  # $6
    assert verdict.recommendation == "avoid"
    assert "decoy_price_extreme" not in verdict.flags


def test_new_provider_gets_flag() -> None:
    verdict = _evaluate(first_seen_at="2026-07-13T12:00:00.000Z")  # 2 days before NOW
    assert "new_provider" in verdict.flags
    assert verdict.recommendation == "caution"
