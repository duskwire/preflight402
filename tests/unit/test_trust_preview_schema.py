import base64
import json

from preflight402.probe.parsers import detect
from preflight402.probe.prober import ProbeResult
from preflight402.probe.tls import TLSInfo
from preflight402.verdict.rules import evaluate
from preflight402.verdict.schema import build_trust_preview

USDC_BASE = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
USDC_POLYGON = "0x3c499c542cef5e3811e1192ce70d8cc03d5c3359"
GOOD_TLS = TLSInfo(valid=True, expires_at="2027-01-01T00:00:00.000Z", issuer="Let's Encrypt")


def _v2_header(accepts: list[dict]) -> str:
    payload = {
        "x402Version": 2,
        "resource": {"url": "https://api.example.com/data"},
        "accepts": accepts,
    }
    return base64.b64encode(json.dumps(payload).encode()).decode()


def _accept(amount: str, network: str, asset: str, pay_to: str | None = "0xpay") -> dict:
    entry = {
        "scheme": "exact",
        "network": network,
        "amount": amount,
        "asset": asset,
        "maxTimeoutSeconds": 300,
    }
    if pay_to is not None:
        entry["payTo"] = pay_to
    return entry


def _probe(headers: dict, body: str = "{}") -> ProbeResult:
    return ProbeResult(
        url="https://api.example.com/data",
        ok=True,
        http_status=402,
        headers=headers,
        body=body,
        latency_ms=180.0,
        tls=GOOD_TLS,
    )


def _document(headers: dict, body: str = "{}") -> dict:
    probe = _probe(headers, body)
    detection = detect(probe.headers, probe.body)
    verdict = evaluate(probe, detection, now="2026-07-15T12:00:00.000Z")
    return build_trust_preview("https://api.example.com/data", probe, detection, verdict)


def test_price_and_pay_to_name_the_same_rail_when_mpp_is_cheapest() -> None:
    # x402 USDC-on-Base at $0.02 plus a cheaper MPP fiat challenge at $0.01:
    # price/pay_to must describe the MPP offer they came from, and the price
    # block must name its own rail rather than borrowing the x402 network.
    headers = {
        "payment-required": _v2_header([_accept("20000", "eip155:8453", USDC_BASE, "0xbase")]),
        "www-authenticate": (
            'Payment realm="m", method="stripe", intent="charge", amount="1", '
            'currency="usd", recipient="acct_stripe_123"'
        ),
    }
    endpoint = _document(headers)["endpoint"]
    assert endpoint["price"]["usd_estimate"] == 0.01
    assert endpoint["price"]["amount"] == "1"
    assert endpoint["price"]["decimals"] == 2
    assert endpoint["price"]["asset"] == "usd"  # the MPP rail, not USDC
    assert endpoint["price"]["network"] is None
    assert endpoint["pay_to"] == "acct_stripe_123"  # same offer as price
    # The x402 rail is still described in networks/assets, unmixed.
    assert endpoint["networks"] == ["eip155:8453"]
    assert endpoint["assets"][0]["asset"] == USDC_BASE


def test_pay_to_never_spliced_from_a_different_offer() -> None:
    # Cheapest offer ($0.01 Base) has no payTo; a pricier Polygon offer does.
    # pay_to must be null, not the Polygon recipient of a different offer.
    headers = {
        "payment-required": _v2_header(
            [
                _accept("10000", "eip155:8453", USDC_BASE, pay_to=None),
                _accept("990000", "eip155:137", USDC_POLYGON, "0xpolygon"),
            ]
        )
    }
    endpoint = _document(headers)["endpoint"]
    assert endpoint["price"]["usd_estimate"] == 0.01  # the Base offer
    assert endpoint["price"]["network"] == "eip155:8453"
    assert endpoint["pay_to"] is None  # NOT "0xpolygon"


def test_handshake_compliant_and_warnings_share_scope() -> None:
    # Clean x402 header beside an MPP challenge with an unknown method: the
    # handshake must not read compliant=true next to a listed deviation.
    headers = {
        "payment-required": _v2_header([_accept("10000", "eip155:8453", USDC_BASE)]),
        "www-authenticate": (
            'Payment realm="m", method="paypal", intent="charge", amount="1", '
            'currency="usd", recipient="0x1"'
        ),
    }
    handshake = _document(headers)["health"]["handshake"]
    assert handshake["valid_402"] is True
    assert handshake["warnings"]  # the paypal deviation is listed
    assert handshake["spec_compliant"] is False  # ...so compliant is false, not true


def test_handshake_compliant_true_only_with_no_warnings() -> None:
    headers = {"payment-required": _v2_header([_accept("10000", "eip155:8453", USDC_BASE)])}
    handshake = _document(headers)["health"]["handshake"]
    assert handshake["warnings"] == []
    assert handshake["spec_compliant"] is True


def test_pure_mpp_deviation_surfaces_in_handshake_compliant() -> None:
    headers = {"www-authenticate": 'Payment realm="m", method="paypal", amount="1", currency="usd"'}
    handshake = _document(headers, body="{}")["health"]["handshake"]
    assert handshake["valid_402"] is True
    assert handshake["spec_compliant"] is False  # not None — deviations exist
    assert handshake["warnings"]


def test_health_method_reflects_probe_method() -> None:
    headers = {"payment-required": _v2_header([_accept("10000", "eip155:8453", USDC_BASE)])}
    assert _document(headers)["health"]["method"] == "GET"
    # a POST-fallback probe surfaces method=POST so agents know to POST
    probe_post = ProbeResult(
        url="https://api.example.com/data",
        ok=True,
        method="POST",
        http_status=402,
        headers=headers,
        body="{}",
        latency_ms=90.0,
        tls=GOOD_TLS,
    )
    detection = detect(headers, "{}")
    verdict = evaluate(probe_post, detection, now="2026-07-15T12:00:00.000Z")
    doc = build_trust_preview("u", probe_post, detection, verdict)
    assert doc["health"]["method"] == "POST"


def test_document_is_strict_json_serializable() -> None:
    headers = {
        "payment-required": _v2_header([_accept("10000", "eip155:8453", USDC_BASE)]),
        "www-authenticate": (
            'Payment realm="m", method="tempo", intent="charge", amount="1", '
            'currency="usd", recipient="0x1"'
        ),
    }
    json.dumps(_document(headers), allow_nan=False)
