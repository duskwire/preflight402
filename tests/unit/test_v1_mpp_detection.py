import json
from pathlib import Path

import pytest

from preflight402.probe.parsers import detect
from preflight402.probe.parsers.mpp import parse_mpp
from preflight402.probe.parsers.x402_v1 import parse_x402_v1

GOLDEN_DIR = Path(__file__).parents[2] / "tests" / "golden" / "x402"
GOLDENS = sorted(GOLDEN_DIR.glob("*.json"))


def _golden(stem: str) -> dict:
    return json.loads((GOLDEN_DIR / f"{stem}.json").read_text())


# --- MPP: real captured challenges (acceptance: classifies captured responses) -


def test_golden_ip402_tempo_challenge_with_request_only_terms() -> None:
    # Terms live only in the base64url request payload, not header params.
    result = parse_mpp(_golden("ip402.xyz")["headers"])
    assert result.mpp_capable
    (challenge,) = result.challenges
    assert challenge.method == "tempo"
    assert challenge.intent == "charge"
    assert challenge.realm == "ip402.xyz"
    assert challenge.amount == "10000"  # resolved from the request payload
    assert challenge.recipient == "0x15A6a5B190de7C3bf33abe7a81e0C0eE77dDf581"
    assert challenge.request["methodDetails"] == {"chainId": 4217}
    assert not result.warnings


def test_golden_macro_stripe_challenge_with_header_level_terms() -> None:
    result = parse_mpp(_golden("macro.lonestaroracle.xyz")["headers"])
    (challenge,) = result.challenges
    assert challenge.method == "stripe"
    assert challenge.intent == "charge"
    assert challenge.amount == "125"  # header param, no request decode needed
    assert challenge.recipient == "0x52Ab53912D37759B2ad364f22dD06B16714b6C06"
    assert challenge.expires == "2026-07-14T23:33:07Z"
    assert challenge.challenge_id.startswith("pi_")  # Stripe PaymentIntent id
    assert challenge.request["currency"] == "usd"


@pytest.mark.parametrize("stem", ["api.onesource.io", "dripstack.xyz"])
def test_golden_tempo_challenges(stem: str) -> None:
    # Servers fold several Payment challenges (one per accepted method /
    # currency / session variant) into one header — all must be recovered.
    result = parse_mpp(_golden(stem)["headers"])
    assert result.challenges
    assert "tempo" in {challenge.method for challenge in result.challenges}
    for challenge in result.challenges:
        assert challenge.method in ("tempo", "stripe")
        # onesource offers a live session intent (Tempo payment channel)
        assert challenge.intent in ("charge", "session")
        assert challenge.amount is not None
        assert challenge.recipient is not None
    assert not result.warnings


def test_golden_blockrun_x402_scheme_is_not_mpp() -> None:
    # blockrun.ai sends WWW-Authenticate: X402 requirements="..." — a
    # nonstandard x402 transport, not a Payment challenge.
    result = parse_mpp(_golden("blockrun.ai")["headers"])
    assert not result.mpp_capable
    assert result.other_schemes == ["X402"]


def test_all_goldens_mpp_parse_never_raises() -> None:
    capable = 0
    for path in GOLDENS:
        golden = json.loads(path.read_text())
        capable += parse_mpp(golden["headers"]).mpp_capable
    assert capable >= 4  # onesource, dripstack, ip402, macro (corpus can grow)


# --- MPP: synthetic edge cases -------------------------------------------------


def test_multiple_challenges_in_one_folded_header() -> None:
    # Header folding (proxies, dict-of-headers) comma-joins multiple
    # challenges; realms contain commas to stress the quote-aware splitter.
    value = (
        'Payment realm="a, inc", method="tempo", intent="charge", amount="5", '
        'recipient="0x1", Payment realm="b", method="stripe", intent="charge", '
        'amount="6", recipient="0x2", Bearer realm="api"'
    )
    result = parse_mpp({"WWW-Authenticate": value})
    assert [c.method for c in result.challenges] == ["tempo", "stripe"]
    assert result.challenges[0].realm == "a, inc"
    assert result.challenges[1].amount == "6"
    assert result.other_schemes == ["Bearer"]
    assert not result.warnings


def test_unknown_method_and_missing_terms_warn() -> None:
    result = parse_mpp({"www-authenticate": 'Payment method="paypal", realm="x"'})
    (challenge,) = result.challenges  # still MPP-capable — flag, don't drop
    assert challenge.method == "paypal"
    assert any("not a known method" in w for w in result.warnings)
    assert any("missing intent" in w for w in result.warnings)
    assert any("no amount" in w for w in result.warnings)
    assert any("no recipient" in w for w in result.warnings)


def test_undecodable_request_warns() -> None:
    result = parse_mpp(
        {"www-authenticate": 'Payment method="tempo", intent="charge", request="%%%"'}
    )
    assert result.challenges[0].request is None
    assert any("not decodable" in w for w in result.warnings)


def test_no_www_authenticate_is_not_mpp() -> None:
    result = parse_mpp({"content-type": "application/json"})
    assert not result.mpp_capable
    assert result.other_schemes == []


@pytest.mark.parametrize("spelling", ["payment", "PAYMENT", "Payment"])
def test_scheme_match_is_case_insensitive(spelling: str) -> None:
    # RFC 9110 §11.1: auth-scheme comparison is case-insensitive.
    value = f'{spelling} method="tempo", intent="charge", amount="1", recipient="0x1"'
    assert parse_mpp({"www-authenticate": value}).mpp_capable


def test_space_separated_params_degrade_loudly_not_silently() -> None:
    # A single missing comma must never silently classify a real MPP
    # endpoint as not-a-payment-endpoint.
    value = 'Payment realm="x" method="tempo" intent="charge" amount="5" recipient="0x1"'
    result = parse_mpp({"www-authenticate": value})
    assert result.mpp_capable  # still detected
    assert result.warnings  # and loudly flagged as malformed


def test_pre_scheme_garbage_warns() -> None:
    result = parse_mpp(
        {"www-authenticate": 'realm="orphan", Payment method="tempo", intent="charge", '
                             'amount="1", recipient="0x1"'}
    )
    assert result.mpp_capable
    assert any("before any scheme" in w for w in result.warnings)


def test_token68_challenge_does_not_corrupt_payment_challenge() -> None:
    # RFC 7235 token68 form (Negotiate/NTLM blobs) must become a separate
    # scheme, not a spurious param-warning on the clean Payment challenge.
    value = (
        'Payment method="tempo", intent="charge", amount="5", recipient="0x1", '
        "Negotiate YII+abc=="
    )
    result = parse_mpp({"www-authenticate": value})
    (challenge,) = result.challenges
    assert challenge.amount == "5"
    assert result.other_schemes == ["Negotiate"]
    assert not result.warnings


def test_duplicate_params_warn() -> None:
    value = 'Payment method="tempo", intent="charge", amount="5", amount="6", recipient="0x1"'
    result = parse_mpp({"www-authenticate": value})
    assert any("duplicate" in w and "amount" in w for w in result.warnings)


def test_numeric_request_amount_coerced_with_warning() -> None:
    import base64

    request = base64.urlsafe_b64encode(
        json.dumps({"amount": 10000, "recipient": "0xR"}).encode()
    ).decode().rstrip("=")
    value = f'Payment method="tempo", intent="charge", request="{request}"'
    result = parse_mpp({"www-authenticate": value})
    (challenge,) = result.challenges
    assert challenge.amount == "10000"
    assert challenge.recipient == "0xR"
    assert any("is a number" in w for w in result.warnings)


def test_quoted_pair_unescaping_is_general() -> None:
    # Wire bytes realm="a\\b" (an escaped backslash) must decode to a\b.
    value = 'Payment method="tempo", intent="charge", amount="1", recipient="0x1", realm="a\\\\b"'
    result = parse_mpp({"www-authenticate": value})
    assert result.challenges[0].realm == "a\\b"


# --- x402 v1: the captured legacy body -----------------------------------------


def test_golden_cheaptokens_body_parses_as_v1() -> None:
    body = _golden("cheaptokens.ai")["body"]
    result = parse_x402_v1(body)
    assert result is not None
    assert result.version == 1
    assert result.source == "body"
    (option,) = result.accepts
    assert option.scheme == "exact"
    assert option.network == "base"  # slug is CORRECT v1 — must not warn
    assert not any("CAIP" in w for w in result.warnings)
    assert option.amount == "1000000"
    assert option.pay_to == "0x213c8d7434E2ae7AA1C392767c5120778D413215"
    assert result.resource_url == "https://cheaptokens.ai/api/buy"


def test_v1_returns_none_for_non_v1_bodies() -> None:
    assert parse_x402_v1(None) is None
    assert parse_x402_v1("not json") is None
    assert parse_x402_v1('{"error": "pay"}') is None
    assert parse_x402_v1(json.dumps({"x402Version": 2, "accepts": []})) is None


def test_v1_missing_required_fields_warn() -> None:
    body = json.dumps({"x402Version": 1, "accepts": [{"scheme": "exact"}]})
    result = parse_x402_v1(body)
    assert any("error missing" in w for w in result.warnings)
    joined = " ".join(result.warnings)
    for name in ("network", "maxAmountRequired", "asset", "payTo", "resource", "description"):
        assert name in joined, name


def test_v1_numeric_amount_coerced_like_v2() -> None:
    body = json.dumps(
        {
            "x402Version": 1,
            "error": "pay",
            "accepts": [
                {
                    "scheme": "exact",
                    "network": "base",
                    "maxAmountRequired": 1000000,
                    "asset": "0x1",
                    "payTo": "0x2",
                    "resource": "https://x.example/",
                    "description": "d",
                    "maxTimeoutSeconds": 60,
                }
            ],
        }
    )
    result = parse_x402_v1(body)
    assert result.accepts[0].amount == "1000000"  # price survives, with a warning
    assert any("is a number" in w for w in result.warnings)


def test_v1_flags_v2_amount_field() -> None:
    body = json.dumps(
        {
            "x402Version": 1,
            "error": "pay",
            "accepts": [
                {
                    "scheme": "exact",
                    "network": "base",
                    "amount": "5000",
                    "asset": "0x1",
                    "payTo": "0x2",
                    "resource": "https://x.example/",
                    "description": "d",
                    "maxTimeoutSeconds": 60,
                }
            ],
        }
    )
    result = parse_x402_v1(body)
    assert result.accepts[0].amount == "5000"
    assert any("v2's amount field" in w for w in result.warnings)


# --- detect(): the dispatcher ----------------------------------------------------


def test_detect_dual_protocol_golden() -> None:
    golden = _golden("ip402.xyz")
    detection = detect(golden["headers"], golden["body"])
    assert detection.protocol == "x402-v2"
    assert detection.mpp_capable  # same endpoint, both protocols
    payment_record = detection.as_db_payment()
    assert payment_record["protocol"] == "x402-v2"
    assert payment_record["mpp"][0]["method"] == "tempo"
    json.dumps(payment_record, allow_nan=False)


def test_detect_v2_header_beats_v1_body() -> None:
    golden = _golden("cheaptokens.ai")
    detection = detect(golden["headers"], golden["body"])
    assert detection.protocol == "x402-v2"
    assert detection.payment.version == 2


def test_detect_pure_v1() -> None:
    body = _golden("cheaptokens.ai")["body"]  # v1 body, no v2 header this time
    detection = detect({"content-type": "application/json"}, body)
    assert detection.protocol == "x402-v1"
    assert detection.payment.version == 1
    assert not detection.mpp_capable
    assert detection.as_db_payment()["protocol"] == "x402-v1"


def test_detect_pure_mpp() -> None:
    headers = {
        "www-authenticate": (
            'Payment realm="m", method="tempo", intent="charge", amount="9", recipient="0x1"'
        )
    }
    detection = detect(headers, '{"type": "about:blank", "title": "Payment Required"}')
    assert detection.protocol == "mpp"
    assert detection.mpp_capable
    assert detection.payment is None
    assert detection.spec_compliant is None
    assert detection.as_db_payment() == {
        "protocol": "mpp",
        "mpp": [
            {
                "method": "tempo",
                "intent": "charge",
                "amount": "9",
                "currency": None,
                "recipient": "0x1",
                "realm": "m",
                "expires": None,
                "description": None,
            }
        ],
    }


def test_detect_not_a_payment_endpoint() -> None:
    detection = detect({"content-type": "text/html"}, "<h1>hello</h1>")
    assert detection.protocol == "none"
    assert not detection.is_payment_endpoint
    assert detection.as_db_payment() is None


def test_detect_broken_v2_header_falls_back_to_v1_body() -> None:
    # A proxy-mangled PAYMENT-REQUIRED header must not make the v2 parser
    # swallow a valid v1 body and grade it against v2 rules.
    body = _golden("cheaptokens.ai")["body"]
    detection = detect({"payment-required": "!!!not-base64!!!"}, body)
    assert detection.protocol == "x402-v1"
    assert detection.payment.version == 1
    assert detection.payment.accepts[0].network == "base"
    assert not any("CAIP" in w for w in detection.warnings)  # v1 rules applied
    assert any("undecodable" in w for w in detection.warnings)  # header evidence kept
    assert detection.as_db_payment()["protocol"] == "x402-v1"


def test_db_protocol_always_matches_detection_protocol() -> None:
    # Broken header + junk body: payload version is unknowable, but the
    # persisted protocol must still be the documented Detection enum, never
    # a payload-derived variant like "x402".
    detection = detect({"payment-required": "%%%"}, "junk")
    assert detection.protocol == "x402-v2"
    assert detection.as_db_payment()["protocol"] == "x402-v2"


def test_detect_all_goldens_classify_as_payment_endpoints() -> None:
    # Growth-safe: future captures may legitimately be v1-only or MPP-only.
    protocols = {}
    for path in GOLDENS:
        golden = json.loads(path.read_text())
        detection = detect(golden["headers"], golden["body"])
        assert detection.is_payment_endpoint, path.stem
        assert detection.protocol in ("x402-v2", "x402-v1", "mpp"), path.stem
        protocols[path.stem] = detection.protocol
    assert sum(p == "x402-v2" for p in protocols.values()) >= 20  # today's corpus
