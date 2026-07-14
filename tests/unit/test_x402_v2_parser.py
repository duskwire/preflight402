import base64
import json
from pathlib import Path

import pytest

from preflight402.probe.parsers.x402_v2 import parse_payment_required

GOLDEN_DIR = Path(__file__).parents[2] / "tests" / "golden" / "x402"
GOLDENS = sorted(GOLDEN_DIR.glob("*.json"))

USDC_BASE = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"


def _golden(stem: str) -> dict:
    return json.loads((GOLDEN_DIR / f"{stem}.json").read_text())


def _encode(payload: dict) -> str:
    return base64.b64encode(json.dumps(payload).encode()).decode()


def _payload(**overrides) -> dict:
    accept = {
        "scheme": "exact",
        "network": "eip155:8453",
        "amount": "10000",
        "asset": USDC_BASE,
        "payTo": "0x" + "ab" * 20,
        "maxTimeoutSeconds": 300,
        "extra": {"name": "USD Coin", "version": "2"},
    }
    payload = {
        "x402Version": 2,
        "resource": {"url": "https://api.example.com/data"},
        "accepts": [accept],
    }
    payload.update(overrides)
    return payload


# --- golden files: real captured 402s (task 1.2 acceptance: >= 5) ------------


def test_enough_goldens_captured() -> None:
    assert len(GOLDENS) >= 5, "task 1.2 acceptance requires golden tests from >=5 real 402s"


@pytest.mark.parametrize("path", GOLDENS, ids=lambda p: p.stem)
def test_golden_parses_when_header_present(path: Path) -> None:
    golden = json.loads(path.read_text())
    result = parse_payment_required(golden["headers"], golden["body"])
    lowered = {k.lower() for k in golden["headers"]}
    if "payment-required" in lowered:
        # A PAYMENT-REQUIRED header is v2 evidence: never None, however broken.
        assert result is not None
        assert result.source in ("header", "body")
        for option in result.accepts:
            assert option.network is None or ":" in option.network or result.warnings
    # And never raises — reaching here is the assertion for headerless files.


def test_golden_coingecko_fully_compliant() -> None:
    golden = _golden("pro-api.coingecko.com")
    result = parse_payment_required(golden["headers"], golden["body"])
    assert result.spec_compliant, result.warnings
    assert result.version == 2
    assert result.source == "header"  # body is human junk; header is canonical
    assert result.networks == ["eip155:8453", "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"]
    base_option = result.accepts[0]
    assert base_option.scheme == "exact"
    assert base_option.amount == "10000"
    assert base_option.asset == USDC_BASE
    assert base_option.pay_to == "0x110cdBba7FE6434Ec4CE3464CC523942ad6Fb784"


def test_golden_bitrefill_upto_scheme() -> None:
    golden = _golden("api.bitrefill.com")
    result = parse_payment_required(golden["headers"], golden["body"])
    assert result.spec_compliant, result.warnings
    (option,) = result.accepts
    assert option.scheme == "upto"
    assert option.amount == "1000000000"
    assert option.max_timeout_seconds == 3600


def test_golden_minifetch_empty_body_header_only() -> None:
    golden = _golden("minifetch.com")
    assert golden["body"] == "{}"
    result = parse_payment_required(golden["headers"], golden["body"])
    assert result.source == "header"
    assert result.spec_compliant, result.warnings
    assert len(result.accepts) == 2


def test_golden_cheaptokens_header_wins_over_v1_body() -> None:
    # Real capture: v2 PAYMENT-REQUIRED header alongside a v1 JSON body whose
    # network is the non-CAIP-2 'base'. The header is canonical — none of the
    # body's junk may surface.
    golden = _golden("cheaptokens.ai")
    assert json.loads(golden["body"])["x402Version"] == 1
    result = parse_payment_required(golden["headers"], golden["body"])
    assert result.source == "header"
    assert result.version == 2
    assert result.networks == ["eip155:8453"]
    assert result.accepts[0].amount == "1000000"
    assert "base" not in result.networks


def test_golden_voidfeed_unpadded_base64_header() -> None:
    golden = _golden("voidfeed.ai")
    result = parse_payment_required(golden["headers"], golden["body"])
    assert result is not None
    assert result.source == "header"
    assert any("lacks padding" in w for w in result.warnings)
    assert not result.spec_compliant
    assert result.accepts  # payload still fully recovered


# --- synthetic: spec-deviation warnings ---------------------------------------


def test_fully_compliant_synthetic() -> None:
    result = parse_payment_required({"PAYMENT-REQUIRED": _encode(_payload())}, None)
    assert result.spec_compliant
    assert result.version == 2
    assert result.resource_url == "https://api.example.com/data"
    assert result.accepts[0].max_timeout_seconds == 300.0
    db = result.as_db_payment()
    assert db["protocol"] == "x402-v2"
    assert db["networks"] == ["eip155:8453"]
    assert db["accepts"][0]["pay_to"] == "0x" + "ab" * 20


def test_no_v2_evidence_returns_none() -> None:
    assert parse_payment_required({}, None) is None
    assert parse_payment_required({"content-type": "text/html"}, "<h1>Pay me</h1>") is None
    assert parse_payment_required({}, '{"error": "payment required"}') is None


def test_v1_body_without_header_is_not_v2() -> None:
    v1_body = json.dumps({"x402Version": 1, "accepts": [{"maxAmountRequired": "1"}]})
    assert parse_payment_required({}, v1_body) is None


def test_undecodable_header_still_reports_v2_evidence() -> None:
    result = parse_payment_required({"payment-required": "%%% not base64 %%%"}, "junk body")
    assert result is not None
    assert result.version is None
    assert result.accepts == []
    assert any("not decodable" in w for w in result.warnings)


def test_plain_json_header_warns() -> None:
    result = parse_payment_required({"payment-required": json.dumps(_payload())}, None)
    assert result.accepts
    assert any("plain JSON" in w for w in result.warnings)


def test_body_only_payload_warns() -> None:
    result = parse_payment_required({}, json.dumps(_payload()))
    assert result.source == "body"
    assert any("body only" in w for w in result.warnings)


def test_legacy_max_amount_required_warns_but_parses() -> None:
    payload = _payload()
    accept = payload["accepts"][0]
    accept["maxAmountRequired"] = accept.pop("amount")
    result = parse_payment_required({"payment-required": _encode(payload)}, None)
    assert result.accepts[0].amount == "10000"
    assert any("legacy maxAmountRequired" in w for w in result.warnings)


def test_non_caip2_network_warns() -> None:
    payload = _payload()
    payload["accepts"][0]["network"] = "base"
    result = parse_payment_required({"payment-required": _encode(payload)}, None)
    assert result.accepts[0].network == "base"  # preserved, but flagged
    assert any("not CAIP-2" in w for w in result.warnings)


def test_numeric_amount_warns_and_coerces() -> None:
    payload = _payload()
    payload["accepts"][0]["amount"] = 10000
    result = parse_payment_required({"payment-required": _encode(payload)}, None)
    assert result.accepts[0].amount == "10000"
    assert any("is a number" in w for w in result.warnings)


def test_missing_required_accept_fields_warn() -> None:
    payload = _payload(accepts=[{"scheme": "exact"}])
    result = parse_payment_required({"payment-required": _encode(payload)}, None)
    missing = {w.split(".")[1].split(" ")[0] for w in result.warnings if "missing (required)" in w}
    assert {"network", "asset", "payTo", "maxTimeoutSeconds", "amount"} <= missing


def test_string_resource_warns() -> None:
    payload = _payload(resource="https://api.example.com/data")
    result = parse_payment_required({"payment-required": _encode(payload)}, None)
    assert result.resource_url == "https://api.example.com/data"
    assert any("resource is a string" in w for w in result.warnings)


def test_unknown_scheme_and_bad_timeout_warn() -> None:
    payload = _payload()
    payload["accepts"][0]["scheme"] = "subscription"
    payload["accepts"][0]["maxTimeoutSeconds"] = -5
    result = parse_payment_required({"payment-required": _encode(payload)}, None)
    assert any("not a known scheme" in w for w in result.warnings)
    assert any("not a positive finite number" in w for w in result.warnings)
    assert result.accepts[0].max_timeout_seconds is None


def test_wrong_version_and_empty_accepts_warn() -> None:
    payload = _payload(x402Version=3, accepts=[])
    result = parse_payment_required({"payment-required": _encode(payload)}, None)
    assert any("expected 2" in w for w in result.warnings)
    assert any("accepts missing or empty" in w for w in result.warnings)


def test_header_wins_when_body_disagrees() -> None:
    header_payload = _payload(resource={"url": "https://header.example/"})
    body_payload = _payload(resource={"url": "https://body.example/"})
    body_payload["accepts"][0]["amount"] = "999999"
    body_payload["accepts"][0]["network"] = "eip155:1"
    result = parse_payment_required(
        {"payment-required": _encode(header_payload)}, json.dumps(body_payload)
    )
    assert result.source == "header"
    assert result.resource_url == "https://header.example/"
    assert result.accepts[0].amount == "10000"
    assert result.networks == ["eip155:8453"]


def test_null_required_fields_warn_and_are_not_compliant() -> None:
    payload = _payload(
        accepts=[
            {
                "scheme": None,
                "network": None,
                "asset": None,
                "payTo": None,
                "maxTimeoutSeconds": None,
                "amount": "1000",
            }
        ]
    )
    result = parse_payment_required({"payment-required": _encode(payload)}, None)
    assert not result.spec_compliant
    for name in ("scheme", "network", "asset", "payTo", "maxTimeoutSeconds"):
        assert any(name in w for w in result.warnings), name


def test_wrong_typed_fields_warn_and_are_not_compliant() -> None:
    payload = _payload(
        accepts=[
            {
                "scheme": 5,
                "network": 8453,
                "asset": ["0x1"],
                "payTo": "0x" + "ab" * 20,
                "maxTimeoutSeconds": True,  # bool is an int subclass — still wrong
                "amount": "1000",
                "extra": [1, 2],
            }
        ]
    )
    result = parse_payment_required({"payment-required": _encode(payload)}, None)
    assert not result.spec_compliant
    option = result.accepts[0]
    assert option.scheme is None
    assert option.network is None
    assert option.asset is None
    assert option.max_timeout_seconds is None
    assert option.extra is None
    for fragment in ("scheme", "network", "asset", "maxTimeoutSeconds", "extra"):
        assert any(fragment in w for w in result.warnings), fragment


def test_amount_number_edge_cases() -> None:
    for raw, expected in [
        (10000, "10000"),  # integral: coerced with a warning
        (2.0, "2"),  # integral float: coerced
        (0.5, None),  # fractional: refused, not silently zeroed
        (1e-7, None),  # would format() to "0" — a nonzero price become free
        (-5, None),
        (True, None),
        (float("nan"), None),
        (float("inf"), None),
    ]:
        payload = _payload()
        payload["accepts"][0]["amount"] = raw
        # json.dumps/loads round-trips NaN/Infinity via the nonstandard tokens
        result = parse_payment_required({"payment-required": _encode(payload)}, None)
        assert result.accepts[0].amount == expected, raw
        assert not result.spec_compliant


def test_infinite_timeout_rejected_and_db_payment_is_strict_json() -> None:
    payload = _payload()
    payload["accepts"][0]["maxTimeoutSeconds"] = float("inf")
    result = parse_payment_required({"payment-required": _encode(payload)}, None)
    assert result.accepts[0].max_timeout_seconds is None
    assert any("maxTimeoutSeconds" in w for w in result.warnings)
    # The DB payment JSON must round-trip as strict JSON for SQLite json1
    # and non-Python consumers.
    json.dumps(result.as_db_payment(), allow_nan=False)


def test_float_version_two_is_stored_and_compliant() -> None:
    payload = _payload(x402Version=2.0)
    result = parse_payment_required({"payment-required": _encode(payload)}, None)
    assert result.version == 2
    assert result.spec_compliant
    bool_version = parse_payment_required(
        {"payment-required": _encode(_payload(x402Version=True))}, None
    )
    assert bool_version.version is None
    assert any("expected 2" in w for w in bool_version.warnings)


def test_never_raises_on_hostile_payloads() -> None:
    hostile = [
        {"payment-required": _encode({"x402Version": 2, "accepts": "not-a-list"})},
        {"payment-required": _encode({"x402Version": 2, "accepts": [None, 42, []]})},
        {"payment-required": _encode({"x402Version": None, "resource": 7})},
        {"payment-required": base64.b64encode(b'"just a string"').decode()},
        {"payment-required": ""},
    ]
    for headers in hostile:
        result = parse_payment_required(headers, None)
        assert result is None or isinstance(result.warnings, list)
