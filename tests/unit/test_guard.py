"""preflight402-guard: policy engine, fail-open semantics, x402 SDK hook."""

from __future__ import annotations

import copy
import json

import httpx
import pytest
import respx
from preflight402_guard import Guard, PaymentBlocked

pytestmark = pytest.mark.anyio

SERVICE = "https://preflight.test"
CHECK = f"{SERVICE}/preflight"
URL = "https://api.example.com/data"
USDC_BASE = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"

PROCEED_DOC = {
    "schema": "trust-preview.v1",
    "endpoint": {"url": URL, "payment_endpoint": True, "price": {"usd_estimate": 0.01}},
    "reputation": {"erc8004": {"bound": True, "sybil_status": "complete", "filtered_score": 89.7}},
    "verdict": {
        "recommendation": "proceed",
        "confidence": "medium",
        "score": 75,
        "reasons": ["valid x402 v2 handshake"],
    },
}


def doc(recommendation: str = "proceed", **over) -> dict:
    document = copy.deepcopy(PROCEED_DOC)
    document["verdict"]["recommendation"] = recommendation
    for dotted, value in over.items():
        node = document
        *parents, leaf = dotted.split("__")
        for key in parents:
            node = node.setdefault(key, {})
        node[leaf] = value
    return document


def mock_verdict(document: dict) -> None:
    respx.get(CHECK).mock(return_value=httpx.Response(200, json=document))


def guard(**over) -> Guard:
    over.setdefault("cache_ttl_s", 0)
    return Guard(SERVICE, **over)


# --- policy matrix ------------------------------------------------------------


@respx.mock
async def test_proceed_allows() -> None:
    mock_verdict(doc("proceed"))
    decision = await guard().check(URL)
    assert (decision.allowed, decision.action) == (True, "allow")
    assert decision.recommendation == "proceed"


@respx.mock
async def test_avoid_blocks_and_carries_verdict_reasons() -> None:
    mock_verdict(doc("avoid", verdict__reasons=["dead endpoint (5 consecutive failed probes)"]))
    decision = await guard().check(URL)
    assert (decision.allowed, decision.action) == (False, "block")
    assert any("verdict is 'avoid'" in r for r in decision.reasons)
    assert any("dead endpoint" in r for r in decision.reasons)


@respx.mock
async def test_caution_warns_by_default_blocks_when_strict() -> None:
    mock_verdict(doc("caution"))
    default = await guard().check(URL)
    assert (default.allowed, default.action) == (True, "warn")
    strict = await guard(block=("avoid", "caution"), warn=()).check(URL)
    assert (strict.allowed, strict.action) == (False, "block")


@respx.mock
async def test_assert_allowed_raises_payment_blocked() -> None:
    mock_verdict(doc("avoid"))
    with pytest.raises(PaymentBlocked) as excinfo:
        await guard().assert_allowed(URL)
    assert excinfo.value.decision.url == URL
    assert URL in str(excinfo.value)


@respx.mock
async def test_max_price_uses_observed_price() -> None:
    mock_verdict(doc("proceed", endpoint__price={"usd_estimate": 0.50}))
    decision = await guard(max_price_usd=0.10).check(URL)
    assert decision.allowed is False
    assert any("exceeds your $0.1 ceiling" in r for r in decision.reasons)


@respx.mock
async def test_max_price_prefers_locally_selected_terms() -> None:
    # The endpoint showed the scanner $0.01 but the client's selected terms
    # cost $5 — the LOCAL price must win (scanner-vs-payer price games).
    mock_verdict(doc("proceed", endpoint__price={"usd_estimate": 0.01}))
    decision = await guard(max_price_usd=1.0).check(URL, local_price_usd=5.0)
    assert decision.allowed is False


@respx.mock
async def test_require_bound_identity() -> None:
    mock_verdict(doc("proceed", reputation__erc8004={"bound": False}))
    decision = await guard(require_bound_identity=True).check(URL)
    assert decision.allowed is False
    assert any("no bound ERC-8004 identity" in r for r in decision.reasons)


@respx.mock
async def test_min_filtered_score_only_applies_when_present() -> None:
    mock_verdict(doc("proceed", reputation__erc8004={"bound": True, "filtered_score": 12.0}))
    low = await guard(min_filtered_score=50).check(URL)
    assert low.allowed is False
    mock_verdict(doc("proceed", reputation__erc8004={"bound": True, "filtered_score": None}))
    absent = await guard(min_filtered_score=50).check(URL)
    assert absent.allowed is True  # unbound/unfiltered endpoints are unaffected


# --- fail-open / service failure ---------------------------------------------


@respx.mock
async def test_service_error_fails_open_by_default() -> None:
    respx.get(CHECK).mock(return_value=httpx.Response(500))
    decision = await guard().check(URL)
    assert (decision.allowed, decision.action) == (True, "warn")
    assert decision.recommendation is None
    assert any("HTTP 500" in r for r in decision.reasons)


@respx.mock
async def test_service_error_blocks_when_fail_closed() -> None:
    respx.get(CHECK).mock(side_effect=httpx.ConnectError("down"))
    decision = await guard(fail_open=False).check(URL)
    assert (decision.allowed, decision.action) == (False, "block")


@respx.mock
async def test_garbage_json_takes_the_failure_path() -> None:
    respx.get(CHECK).mock(return_value=httpx.Response(200, text="not json"))
    decision = await guard().check(URL)
    assert decision.recommendation is None
    assert decision.allowed is True


# --- caching + sync + callback -------------------------------------------------


@respx.mock
async def test_decision_cache_prevents_repeat_lookups() -> None:
    route = respx.get(CHECK).mock(return_value=httpx.Response(200, json=doc("proceed")))
    cached_guard = Guard(SERVICE, cache_ttl_s=60)
    first = await cached_guard.check(URL)
    second = await cached_guard.check(URL)
    assert first.allowed and second.allowed
    assert route.call_count == 1


@respx.mock
def test_check_sync_matches_async_policy() -> None:
    mock_verdict(doc("avoid"))
    decision = guard().check_sync(URL)
    assert decision.allowed is False
    with pytest.raises(PaymentBlocked):
        guard().assert_allowed_sync(URL)


@respx.mock
async def test_on_decision_callback_fires_and_cannot_break_the_path() -> None:
    mock_verdict(doc("proceed"))
    seen: list = []

    def boom(decision):
        seen.append(decision)
        raise RuntimeError("callback bug")

    decision = await guard(on_decision=boom).check(URL)
    assert decision.allowed is True
    assert len(seen) == 1


# --- x402 SDK integration ------------------------------------------------------


def _payment_required(url: str = URL, amount: str = "10000"):
    from x402.schemas import PaymentRequired, PaymentRequirements, ResourceInfo

    return PaymentRequired(
        accepts=[
            PaymentRequirements(
                scheme="exact",
                network="eip155:8453",
                asset=USDC_BASE,
                amount=amount,
                pay_to="0x" + "ab" * 20,
                max_timeout_seconds=300,
            )
        ],
        resource=ResourceInfo(url=url),
    )


class StubScheme:
    scheme = "exact"

    def create_payment_payload(self, requirements):
        return {"signed": "yes"}


@respx.mock
async def test_installed_guard_allows_a_clean_payment_end_to_end() -> None:
    from x402 import x402Client

    mock_verdict(doc("proceed"))
    client = guard().install(x402Client())
    client.register("eip155:8453", StubScheme())
    payload = await client.create_payment_payload(_payment_required())
    assert payload.payload == {"signed": "yes"}


@respx.mock
async def test_installed_guard_aborts_payment_on_avoid() -> None:
    from x402 import x402Client
    from x402.schemas import PaymentAbortedError

    mock_verdict(doc("avoid", verdict__reasons=["zombie: registered but serving no 402"]))
    client = guard().install(x402Client())
    client.register("eip155:8453", StubScheme())
    with pytest.raises(PaymentAbortedError) as excinfo:
        await client.create_payment_payload(_payment_required())
    assert "preflight402" in str(excinfo.value)
    assert "avoid" in str(excinfo.value)


@respx.mock
async def test_hook_enforces_price_of_selected_terms() -> None:
    # Verdict says $0.01, but the terms the client actually selected cost $6.
    from x402.schemas import PaymentCreationContext

    mock_verdict(doc("proceed", endpoint__price={"usd_estimate": 0.01}))
    payment_required = _payment_required(amount="6000000")  # $6 USDC
    ctx = PaymentCreationContext(
        payment_required=payment_required,
        selected_requirements=payment_required.accepts[0],
    )
    result = await guard(max_price_usd=1.0).hook(ctx)
    assert result is not None  # AbortResult
    assert "ceiling" in result.reason


@respx.mock
async def test_hook_fails_open_when_no_resource_url() -> None:
    from x402.schemas import PaymentCreationContext, PaymentRequired

    payment_required = PaymentRequired(accepts=_payment_required().accepts, resource=None)
    ctx = PaymentCreationContext(
        payment_required=payment_required,
        selected_requirements=payment_required.accepts[0],
    )
    open_result = await guard().hook(ctx)
    assert open_result is None  # fail-open allows
    closed_result = await guard(fail_open=False).hook(ctx)
    assert closed_result is not None
    assert "no resource URL" in closed_result.reason


def test_install_rejects_non_x402_objects() -> None:
    with pytest.raises(TypeError):
        guard().install(object())


def test_install_picks_sync_hook_for_sync_client() -> None:
    from x402 import x402Client, x402ClientSync

    async_client = guard().install(x402Client())
    assert async_client._before_payment_creation_hooks  # registered
    sync_client = guard().install(x402ClientSync())
    assert sync_client._before_payment_creation_hooks


# --- CLI -----------------------------------------------------------------------


@respx.mock
def test_cli_check_exit_codes(monkeypatch, capsys) -> None:
    from preflight402_guard import cli

    mock_verdict(doc("avoid"))
    monkeypatch.setattr("sys.argv", ["preflight402-guard", "check", URL, "--service", SERVICE])
    with pytest.raises(SystemExit) as excinfo:
        cli.main()
    assert excinfo.value.code == 2
    out = capsys.readouterr().out
    assert "BLOCK" in out and "avoid" in out

    mock_verdict(doc("proceed"))
    with pytest.raises(SystemExit) as excinfo:
        cli.main()
    assert excinfo.value.code == 0


@respx.mock
def test_cli_json_output(monkeypatch, capsys) -> None:
    from preflight402_guard import cli

    mock_verdict(doc("proceed"))
    monkeypatch.setattr(
        "sys.argv", ["preflight402-guard", "check", URL, "--service", SERVICE, "--json"]
    )
    with pytest.raises(SystemExit):
        cli.main()
    document = json.loads(capsys.readouterr().out)
    assert document["schema"] == "trust-preview.v1"


# --- adversarial bypasses (resource.url is attacker-controlled) -----------------


@respx.mock
async def test_resource_url_spoof_caught_by_payee_mismatch() -> None:
    # A malicious endpoint points resource.url at someone ELSE's clean
    # endpoint to inherit its verdict. The verdict document carries the payee
    # WE observed there; the locally selected recipient differs -> block.
    mock_verdict(doc("proceed", endpoint__pay_to="0x" + "11" * 20))
    decision = await guard().check(URL, local_pay_to="0x" + "22" * 20)
    assert decision.allowed is False
    assert any("resource-URL spoof" in r for r in decision.reasons)
    # matching payee (case-insensitive) stays allowed
    mock_verdict(doc("proceed", endpoint__pay_to="0x" + "AB" * 20))
    ok = await guard().check(URL, local_pay_to="0x" + "ab" * 20)
    assert ok.allowed is True


@respx.mock
async def test_hook_passes_selected_pay_to_end_to_end() -> None:
    from x402.schemas import PaymentCreationContext

    # The endpoint's OWN 402 pays to 0xabab..; the preflighted document says
    # the endpoint at resource.url pays someone else -> abort.
    mock_verdict(doc("proceed", endpoint__pay_to="0x" + "33" * 20))
    payment_required = _payment_required()
    ctx = PaymentCreationContext(
        payment_required=payment_required,
        selected_requirements=payment_required.accepts[0],
    )
    result = await guard().hook(ctx)
    assert result is not None
    assert "spoof" in result.reason


@respx.mock
async def test_service_refusal_blocks_even_when_fail_open() -> None:
    # resource.url pointed at a private/invalid target: our service refuses
    # (403/400). That is a judgment, not an outage — fail-open must NOT
    # launder it into an allow.
    respx.get(CHECK).mock(return_value=httpx.Response(403))
    decision = await guard().check(URL)  # fail_open=True default
    assert (decision.allowed, decision.action) == (False, "block")
    assert any("refused the URL" in r for r in decision.reasons)
    # 429 (rate limit) stays a genuine availability problem -> fail-open
    respx.get(CHECK).mock(return_value=httpx.Response(429))
    limited = await guard().check(URL)
    assert limited.allowed is True


@respx.mock
async def test_cache_does_not_mix_different_local_terms() -> None:
    route = respx.get(CHECK).mock(
        return_value=httpx.Response(200, json=doc("proceed", endpoint__pay_to="0x" + "11" * 20))
    )
    cached_guard = Guard(SERVICE, cache_ttl_s=60)
    clean = await cached_guard.check(URL)
    assert clean.allowed is True
    spoofed = await cached_guard.check(URL, local_pay_to="0x" + "99" * 20)
    assert spoofed.allowed is False  # must not reuse the clean cached decision
    assert route.call_count == 2


# --- review fixes: ceiling fail-closed, crash-safety, exit order, dispatch ------


def _ctx(network: str, asset: str, amount: str, url: str = URL, pay_to: str = "0x" + "ab" * 20):
    from x402.schemas import (
        PaymentCreationContext,
        PaymentRequired,
        PaymentRequirements,
        ResourceInfo,
    )

    pr = PaymentRequired(
        accepts=[
            PaymentRequirements(
                scheme="exact",
                network=network,
                asset=asset,
                amount=amount,
                pay_to=pay_to,
                max_timeout_seconds=300,
            )
        ],
        resource=ResourceInfo(url=url),
    )
    return PaymentCreationContext(payment_required=pr, selected_requirements=pr.accepts[0])


@respx.mock
async def test_ceiling_fails_closed_on_unpriceable_selected_asset() -> None:
    # An unlisted rail (some random ERC-20) that the scanner saw at $0.01 but
    # whose selected amount we can't price: the ceiling must NOT trust the
    # scanner price — block instead (the scanner-vs-payer bypass).
    mock_verdict(doc("proceed", endpoint__price={"usd_estimate": 0.01}))
    ctx = _ctx("eip155:8453", "0x" + "de" * 20, "5000000000")
    result = await guard(max_price_usd=1.0).hook(ctx)
    assert result is not None
    assert "cannot verify the price" in result.reason


@respx.mock
async def test_ceiling_priced_across_more_stablecoins() -> None:

    # Arbitrum USDC $6 now prices (table expanded) -> blocks under a $1 ceiling.
    mock_verdict(doc("proceed"))
    ctx = _ctx("eip155:42161", "0xaf88d065e77c8cc2239327c5edb3a432268e5831", "6000000")
    result = await guard(max_price_usd=1.0).hook(ctx)
    assert result is not None and "6" in result.reason
    # DAI (18 decimals) prices correctly too
    ctx_dai = _ctx("eip155:1", "0x6b175474e89094c44da98b954eedeac495271d0f", "3" + "0" * 18)
    price, unpriceable = guard()._selected_price(ctx_dai)
    assert price == 3.0 and unpriceable is False


@respx.mock
async def test_usd_assets_override_extends_pricing() -> None:
    mock_verdict(doc("proceed"))
    custom = {("eip155:8453", "0x" + "de" * 20): 6}
    ctx = _ctx("eip155:8453", "0x" + "DE" * 20, "9000000")  # $9 on a custom asset
    result = await guard(max_price_usd=1.0, usd_assets=custom).hook(ctx)
    assert result is not None and "9" in result.reason


@respx.mock
async def test_unicode_digit_amount_does_not_crash_the_hook() -> None:
    # amount='²' passes str.isdigit() but int() would raise — must be treated
    # as unpriceable, never propagate a ValueError out of the payment path.
    mock_verdict(doc("proceed"))
    ctx = _ctx("eip155:8453", "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", "²")
    price, unpriceable = guard()._selected_price(ctx)
    assert price is None and unpriceable is True
    # with a ceiling set, an unpriceable term fails closed rather than crashing
    result = await guard(max_price_usd=1.0).hook(ctx)
    assert result is not None


@respx.mock
async def test_assert_allowed_runs_payee_check_when_terms_passed() -> None:
    mock_verdict(doc("proceed", endpoint__pay_to="0x" + "11" * 20))
    with pytest.raises(PaymentBlocked):
        await guard().assert_allowed(URL, local_pay_to="0x" + "22" * 20)
    # and honors a passed price ceiling
    with pytest.raises(PaymentBlocked):
        await guard(max_price_usd=1.0).assert_allowed(URL, local_price_usd=5.0)


@respx.mock
def test_cli_service_refusal_is_exit_2_not_3(monkeypatch, capsys) -> None:
    from preflight402_guard import cli

    respx.get(CHECK).mock(return_value=httpx.Response(403))  # SSRF/invalid-URL refusal
    monkeypatch.setattr("sys.argv", ["preflight402-guard", "check", URL, "--service", SERVICE])
    with pytest.raises(SystemExit) as excinfo:
        cli.main()
    assert excinfo.value.code == 2  # blocked, not "no verdict"
    assert "BLOCK" in capsys.readouterr().out


@respx.mock
async def test_install_dispatches_by_structure_for_sync_subclass() -> None:
    from x402 import x402ClientSync
    from x402.schemas import PaymentAbortedError

    class MySync(x402ClientSync):
        pass

    mock_verdict(doc("avoid"))
    client = guard().install(MySync())
    client.register("eip155:8453", StubScheme())
    # a sync subclass must get the SYNC hook — else this raises the SDK's
    # "async hooks not supported" TypeError instead of a clean abort
    with pytest.raises(PaymentAbortedError):
        client.create_payment_payload(_payment_required())


# --- Phase A: delivery reporting (crowdsourced delivery verification) ----------

REPORTS = f"{SERVICE}/delivery-reports"


def _response_ctx(*, success: bool, url: str = URL, tx: str = "0xdead", error=None, payer="0xpay"):
    from x402.schemas import PaymentRequired, ResourceInfo, SettleResponse

    settle = SettleResponse(
        success=success, transaction=tx, network="eip155:8453", payer=payer, amount="10000"
    )
    pr = PaymentRequired(accepts=_payment_required().accepts, resource=ResourceInfo(url=url))
    # fields: payment_payload, requirements, settle_response, payment_required, error
    from x402.schemas import PaymentResponseContext

    return PaymentResponseContext(
        payment_payload=None,
        requirements=pr.accepts[0],
        settle_response=settle,
        payment_required=pr,
        error=error,
    )


@respx.mock
async def test_response_hook_reports_successful_delivery() -> None:
    route = respx.post(REPORTS).mock(return_value=httpx.Response(200, json={"accepted": 1}))
    g = Guard(SERVICE)  # report_outcomes defaults ON
    await g.response_hook(_response_ctx(success=True))
    # the send is a detached task; let it run
    import asyncio

    await asyncio.sleep(0.05)
    assert route.called
    body = json.loads(route.calls.last.request.content)["reports"][0]
    assert body == {"url": URL, "delivered": True, "tier": "anonymous"}


@respx.mock
async def test_response_hook_reports_paid_but_denied() -> None:
    # settle succeeded but the HTTP request errored after payment — the
    # "settlement preemption" attack signature the whole feature exists to catch.
    route = respx.post(REPORTS).mock(return_value=httpx.Response(200))
    g = Guard(SERVICE)
    await g.response_hook(_response_ctx(success=True, error=httpx.ConnectError("boom")))
    import asyncio

    await asyncio.sleep(0.05)
    body = json.loads(route.calls.last.request.content)["reports"][0]
    assert body["delivered"] is False
    assert body["outcome"] == "post_payment_error:ConnectError"
    assert "payer" not in body and "tx_hash" not in body  # anonymous tier


@respx.mock
async def test_verified_tier_includes_settlement_only_when_opted_in() -> None:
    route = respx.post(REPORTS).mock(return_value=httpx.Response(200))
    g = Guard(SERVICE, report_settlements=True)
    await g.response_hook(_response_ctx(success=True, tx="0xBEEF", payer="0xPAYER"))
    import asyncio

    await asyncio.sleep(0.05)
    body = json.loads(route.calls.last.request.content)["reports"][0]
    assert body["tier"] == "verified"
    assert body["tx_hash"] == "0xBEEF"
    assert body["payer"] == "0xPAYER"
    assert body["network"] == "eip155:8453"


@respx.mock
async def test_reporting_off_sends_nothing() -> None:
    route = respx.post(REPORTS).mock(return_value=httpx.Response(200))
    g = Guard(SERVICE, report_outcomes=False)
    await g.response_hook(_response_ctx(success=True))
    import asyncio

    await asyncio.sleep(0.05)
    assert not route.called
    assert g._reporter.enabled is False


@respx.mock
async def test_env_kill_switch_forces_reporting_off(monkeypatch) -> None:
    monkeypatch.setenv("PREFLIGHT402_GUARD_NO_TELEMETRY", "1")
    route = respx.post(REPORTS).mock(return_value=httpx.Response(200))
    g = Guard(SERVICE, report_outcomes=True)  # code says on, env overrides
    assert g._reporter.enabled is False
    await g.response_hook(_response_ctx(success=True))
    import asyncio

    await asyncio.sleep(0.05)
    assert not route.called


@respx.mock
async def test_response_hook_never_raises_on_reporter_failure() -> None:
    respx.post(REPORTS).mock(side_effect=httpx.ConnectError("service down"))
    g = Guard(SERVICE)
    # must return None (never raise) even though the send fails
    assert await g.response_hook(_response_ctx(success=True)) is None
    import asyncio

    await asyncio.sleep(0.05)


async def test_build_report_skips_ctx_without_url() -> None:
    from x402.schemas import PaymentRequired, PaymentResponseContext, SettleResponse

    pr = PaymentRequired(accepts=_payment_required().accepts, resource=None)
    ctx = PaymentResponseContext(
        payment_payload=None,
        requirements=pr.accepts[0],
        settle_response=SettleResponse(success=True, transaction="0x1", network="eip155:8453"),
        payment_required=pr,
        error=None,
    )
    assert Guard(SERVICE)._build_report(ctx) is None


@respx.mock
async def test_install_registers_response_hook_when_reporting_on() -> None:
    from x402 import x402Client

    g = Guard(SERVICE)
    client = g.install(x402Client())
    assert client._payment_response_hooks  # on_payment_response registered
    # and NOT registered when reporting is off
    g_off = Guard(SERVICE, report_outcomes=False)
    client_off = g_off.install(x402Client())
    assert not client_off._payment_response_hooks


@respx.mock
def test_manual_report_blocking_send() -> None:
    route = respx.post(REPORTS).mock(return_value=httpx.Response(200, json={"accepted": 1}))
    Guard(SERVICE).report(URL, delivered=True, blocking=True)
    assert route.called
    body = json.loads(route.calls.last.request.content)["reports"][0]
    assert body == {"url": URL, "delivered": True, "tier": "anonymous"}


@respx.mock
def test_cli_report_subcommand(monkeypatch, capsys) -> None:
    from preflight402_guard import cli

    route = respx.post(REPORTS).mock(return_value=httpx.Response(200))
    monkeypatch.setattr(
        "sys.argv",
        ["preflight402-guard", "report", URL, "--service", SERVICE, "--failed", "--tx", "0xabc"],
    )
    cli.main()
    assert route.called
    body = json.loads(route.calls.last.request.content)["reports"][0]
    assert body["delivered"] is False and body["tier"] == "verified" and body["tx_hash"] == "0xabc"
    assert "verified" in capsys.readouterr().out


# --- Phase A review fixes: URL secret stripping, dispatch safety, CLI honesty --


def test_report_url_strips_query_and_userinfo() -> None:
    from preflight402_guard.guard import _safe_report_url

    assert _safe_report_url("https://api.x.com/data?api_key=SECRET") == "https://api.x.com/data"
    assert _safe_report_url("https://user:pw@api.x.com/data") == "https://api.x.com/data"
    assert _safe_report_url("https://api.x.com:8443/p?t=1#frag") == "https://api.x.com:8443/p"
    assert _safe_report_url("https://[2001:db8::1]/p?x=1") == "https://[2001:db8::1]/p"
    assert _safe_report_url("not a url") is None


@respx.mock
async def test_anonymous_report_never_leaks_url_secrets_end_to_end() -> None:
    route = respx.post(REPORTS).mock(return_value=httpx.Response(200))
    g = Guard(SERVICE)
    ctx = _response_ctx(success=True, url="https://api.example.com/data?api_key=SECRET123")
    await g.response_hook(ctx)
    import asyncio

    await asyncio.sleep(0.05)
    body = json.loads(route.calls.last.request.content)["reports"][0]
    assert body["url"] == "https://api.example.com/data"
    assert "SECRET123" not in json.dumps(body)


@respx.mock
async def test_response_hook_never_raises_when_dispatch_fails(monkeypatch) -> None:
    # Thread.start() blowing up (thread exhaustion) must not surface in the
    # payment path — the review's paid-but-crashed scenario.
    import preflight402_guard.reporting as reporting

    def boom(*a, **k):
        raise RuntimeError("can't start new thread")

    monkeypatch.setattr(reporting.threading, "Thread", boom)
    g = Guard(SERVICE)
    assert g.response_hook_sync(_response_ctx(success=True)) is None  # swallowed


def test_report_returns_send_result_for_blocking(monkeypatch) -> None:
    import preflight402_guard.reporting as reporting

    monkeypatch.setattr(reporting.DeliveryReporter, "send_blocking", lambda self, p: False)
    assert Guard(SERVICE).report(URL, delivered=True, blocking=True) is False
    monkeypatch.setattr(reporting.DeliveryReporter, "send_blocking", lambda self, p: True)
    assert Guard(SERVICE).report(URL, delivered=True, blocking=True) is True


@respx.mock
def test_cli_report_exit_4_when_send_fails(monkeypatch, capsys) -> None:
    from preflight402_guard import cli

    respx.post(REPORTS).mock(return_value=httpx.Response(503))
    monkeypatch.setattr("sys.argv", ["p", "report", URL, "--service", SERVICE, "--delivered"])
    with pytest.raises(SystemExit) as excinfo:
        cli.main()
    assert excinfo.value.code == 4
    assert "NOT recorded" in capsys.readouterr().err


def test_cli_report_refuses_when_telemetry_disabled(monkeypatch) -> None:
    from preflight402_guard import cli

    monkeypatch.setenv("PREFLIGHT402_GUARD_NO_TELEMETRY", "1")
    monkeypatch.setattr("sys.argv", ["p", "report", URL, "--service", SERVICE, "--delivered"])
    with pytest.raises(SystemExit) as excinfo:
        cli.main()
    assert excinfo.value.code != 0
