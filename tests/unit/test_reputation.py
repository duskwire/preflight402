"""ERC-8004 binding + reputation (M5): subgraph client, binding, schema wiring."""

from __future__ import annotations

import httpx
import pytest
import respx

from preflight402.config import Settings
from preflight402.reputation import resolve_binding
from preflight402.reputation.subgraph import SUBGRAPH_IDS, SubgraphClient
from preflight402.reputation.types import UNBOUND

pytestmark = pytest.mark.anyio

KEY = "test-graph-key"
BASE = 8453
GW = f"https://gateway.thegraph.com/api/{KEY}/subgraphs/id/{SUBGRAPH_IDS[BASE]}"
WALLET = "0x89e9e1ab11dd1b138b1dce6d6a4a0926aafd5029"


def settings(**over) -> Settings:
    return Settings(_env_file=None, graph_api_key=KEY, **over)


def agent_row(**over) -> dict:
    row = {
        "id": "8453:1",
        "chainId": "8453",
        "agentId": "1",
        "owner": WALLET,
        "agentWallet": WALLET,
        "totalFeedback": "39",
        "registrationFile": {
            "name": "ClawNews",
            "active": True,
            "x402Support": False,
            "mcpEndpoint": None,
            "a2aEndpoint": None,
            "webEndpoint": "https://clawnews.io",
            "oasfEndpoint": None,
            "emailEndpoint": None,
        },
    }
    row.update(over)
    return row


def graphql_mock(agents: list[dict], feedbacks: list[dict] | None = None):
    def handler(request: httpx.Request) -> httpx.Response:
        body = request.content.decode()
        if "feedbacks" in body:
            return httpx.Response(200, json={"data": {"feedbacks": feedbacks or []}})
        return httpx.Response(200, json={"data": {"agents": agents}})

    respx.post(GW).mock(side_effect=handler)


# --- subgraph client ---------------------------------------------------------


@respx.mock
async def test_client_parses_agent_and_endpoints() -> None:
    graphql_mock([agent_row()])
    client = SubgraphClient(KEY)
    agents = await client.agents_by_wallet(BASE, WALLET.upper())  # case-insensitive
    assert len(agents) == 1
    a = agents[0]
    assert a.agent_id == "1"
    assert a.chain_id == 8453
    assert a.agent_wallet == WALLET  # lowercased
    assert a.name == "ClawNews"
    assert a.active is True
    assert a.endpoints == ["https://clawnews.io"]


@respx.mock
async def test_client_summarizes_feedback() -> None:
    graphql_mock(
        [agent_row()],
        feedbacks=[
            {"value": "80", "tag1": "quality", "tag2": None, "clientAddress": "0xAAA"},
            {"value": "90", "tag1": "quality", "tag2": "trust", "clientAddress": "0xBBB"},
            {"value": "70", "tag1": "trust", "tag2": None, "clientAddress": "0xAAA"},
        ],
    )
    summary = await SubgraphClient(KEY).reputation_summary(BASE, "8453:1")
    assert summary.raw_feedback_count == 3
    assert summary.distinct_reviewers == 2  # 0xAAA appears twice
    assert summary.average_score == 80.0  # (80+90+70)/3
    assert summary.top_tags[:2] == ["quality", "trust"]  # quality:2, trust:2 -> insertion tiebreak


@respx.mock
async def test_client_clamps_out_of_range_feedback_values() -> None:
    # On-chain value is a SIGNED int128 posted permissionlessly: an extreme
    # value must weigh like an extreme score, not dominate every downstream
    # mean (review finding: unbounded filtered_score).
    graphql_mock(
        [agent_row()],
        feedbacks=[
            {"value": "-1000000000", "clientAddress": "0xAAA"},
            {"value": "1e18", "clientAddress": "0xBBB"},
            {"value": "90", "clientAddress": "0xCCC"},
        ],
    )
    summary = await SubgraphClient(KEY).reputation_summary(BASE, "8453:1")
    assert summary.reviewer_scores == {"0xaaa": [0.0], "0xbbb": [100.0], "0xccc": [90.0]}
    assert summary.average_score == round((0 + 100 + 90) / 3, 1)


@respx.mock
async def test_client_redacts_api_key_from_failure_logs(caplog) -> None:
    # httpx exception strings embed the gateway URL, which embeds the key.
    respx.post(GW).mock(return_value=httpx.Response(429))
    with caplog.at_level("WARNING"):
        await SubgraphClient(KEY).agents_by_wallet(BASE, WALLET)
    assert caplog.records, "expected a warning to be logged"
    assert KEY not in caplog.text
    assert "<key>" in caplog.text


@respx.mock
async def test_client_returns_none_on_http_error() -> None:
    # None = "could not check" (NOT an empty match); never raises
    respx.post(GW).mock(return_value=httpx.Response(500))
    assert await SubgraphClient(KEY).agents_by_wallet(BASE, WALLET) is None
    assert await SubgraphClient(KEY).reputation_summary(BASE, "8453:1") is None


@respx.mock
async def test_client_returns_none_on_graphql_errors() -> None:
    respx.post(GW).mock(return_value=httpx.Response(200, json={"errors": [{"message": "bad"}]}))
    assert await SubgraphClient(KEY).agents_by_wallet(BASE, WALLET) is None


@respx.mock
async def test_client_returns_none_on_non_http_exception() -> None:
    # a reputation read must never break the preflight, even on exception types
    # outside httpx.HTTPError (e.g. a transport raising ValueError/InvalidURL)
    respx.post(GW).mock(side_effect=RuntimeError("unexpected"))
    assert await SubgraphClient(KEY).agents_by_wallet(BASE, WALLET) is None
    assert await SubgraphClient(KEY).reputation_summary(BASE, "8453:1") is None


@respx.mock
async def test_client_empty_list_is_a_genuine_no_match() -> None:
    # a successful query with no agents is [] (checked, nothing) — distinct
    # from None (failed). This is the whole point of the observability fix.
    respx.post(GW).mock(return_value=httpx.Response(200, json={"data": {"agents": []}}))
    assert await SubgraphClient(KEY).agents_by_wallet(BASE, WALLET) == []


async def test_client_unknown_chain_returns_none() -> None:
    assert await SubgraphClient(KEY).agents_by_wallet(999999, WALLET) is None


# --- binding engine ----------------------------------------------------------


async def test_binding_none_without_key() -> None:
    # feature off = "didn't check" -> None (block stays all-null), not UNBOUND
    result = await resolve_binding(WALLET, "https://clawnews.io/x", Settings(_env_file=None))
    assert result is None


async def test_binding_none_without_payto() -> None:
    assert await resolve_binding(None, "https://clawnews.io/x", settings()) is None


@respx.mock
async def test_binding_unbound_when_checked_but_no_match() -> None:
    # feature on + payTo present + no agent = UNBOUND (bound=False), we checked
    graphql_mock([])
    result = await resolve_binding(WALLET, "https://x.example/y", settings())
    assert result is UNBOUND
    assert result.status == "unbound"


@respx.mock
async def test_binding_error_when_subgraph_fails_not_a_false_no_match() -> None:
    # THE observability fix: a failed subgraph call must NOT masquerade as
    # "no agent". It returns the error state (bound False but status 'error'),
    # which the schema surfaces as bound=null, not bound=false.
    from preflight402.reputation.types import BINDING_ERROR

    respx.post(GW).mock(return_value=httpx.Response(403))  # rate-limited / exhausted key
    result = await resolve_binding(WALLET, "https://clawnews.io/x", settings())
    assert result is BINDING_ERROR
    assert result.status == "error"
    assert result.bound is False  # internal flag; schema maps this status to null


@respx.mock
async def test_binding_high_confidence_on_endpoint_host_match() -> None:
    graphql_mock([agent_row()], feedbacks=[{"value": "80", "clientAddress": "0xAAA"}])
    result = await resolve_binding(WALLET, "https://clawnews.io/api/x402", settings())
    assert result.bound is True
    assert result.method == "agent_wallet+endpoint"
    assert result.confidence == "high"
    assert result.agent.agent_id == "1"
    assert result.reputation.raw_feedback_count == 1


@respx.mock
async def test_binding_medium_confidence_when_host_differs_but_active() -> None:
    graphql_mock([agent_row()], feedbacks=[])
    result = await resolve_binding(WALLET, "https://elsewhere.example/pay", settings())
    assert result.bound is True
    assert result.method == "agent_wallet"
    assert result.confidence == "medium"


@respx.mock
async def test_binding_low_confidence_when_inactive() -> None:
    row = agent_row()
    row["registrationFile"]["active"] = False
    graphql_mock([row], feedbacks=[])
    result = await resolve_binding(WALLET, "https://elsewhere.example/pay", settings())
    assert result.confidence == "low"


@respx.mock
async def test_binding_unbound_when_no_agent_matches() -> None:
    graphql_mock([])
    assert (await resolve_binding(WALLET, "https://x.example/y", settings())).bound is False


@respx.mock
async def test_binding_records_ambiguity_but_still_binds() -> None:
    a1 = agent_row(id="8453:1", agentId="1", totalFeedback="5")
    a2 = agent_row(id="8453:2", agentId="2", totalFeedback="12")
    a2["registrationFile"]["webEndpoint"] = "https://other.example"
    graphql_mock([a1, a2], feedbacks=[])
    result = await resolve_binding(WALLET, "https://nomatch.example/x", settings())
    assert result.bound is True
    assert sorted(result.ambiguous_agent_ids) == ["1", "2"]
    assert result.agent.agent_id == "2"  # most-reviewed wins when no host match


@respx.mock
async def test_binding_prefers_endpoint_match_over_feedback_count() -> None:
    a1 = agent_row(id="8453:1", agentId="1", totalFeedback="50")  # more feedback, wrong host
    a1["registrationFile"]["webEndpoint"] = "https://other.example"
    a2 = agent_row(id="8453:2", agentId="2", totalFeedback="3")  # less feedback, right host
    graphql_mock([a1, a2], feedbacks=[])
    result = await resolve_binding(WALLET, "https://clawnews.io/x", settings())
    assert result.agent.agent_id == "2"
    assert result.confidence == "high"


@respx.mock
async def test_binding_skips_reputation_when_no_feedback() -> None:
    row = agent_row(totalFeedback="0")
    graphql_mock([row])
    result = await resolve_binding(WALLET, "https://clawnews.io/x", settings())
    assert result.bound is True
    assert result.reputation is None  # no feedback query issued


# --- schema block ------------------------------------------------------------


def test_schema_block_not_checked_when_no_binding() -> None:
    from preflight402.verdict.schema import _erc8004_block

    block = _erc8004_block(None)
    assert block["bound"] is None
    assert block["binding_status"] == "not_checked"
    assert block["sybil_filtered_count"] is None


def test_schema_block_unbound() -> None:
    from preflight402.verdict.schema import _erc8004_block

    block = _erc8004_block(UNBOUND)
    assert block["bound"] is False  # genuine "checked, no agent"
    assert block["binding_status"] == "unbound"
    assert block["agent_id"] is None


def test_schema_block_error_reports_null_not_false() -> None:
    # the observability fix at the API surface: a failed lookup is bound=null
    # with binding_status "error" — never a misleading bound=false
    from preflight402.reputation.types import BINDING_ERROR
    from preflight402.verdict.schema import _erc8004_block

    block = _erc8004_block(BINDING_ERROR)
    assert block["bound"] is None
    assert block["binding_status"] == "error"
    assert block["agent_id"] is None


def test_schema_block_populated_from_binding() -> None:
    from preflight402.reputation.types import AgentIdentity, Binding, ReputationSummary
    from preflight402.verdict.schema import _erc8004_block

    binding = Binding(
        bound=True,
        status="bound",
        agent=AgentIdentity(
            global_id="8453:1",
            chain_id=8453,
            agent_id="1",
            owner=WALLET,
            agent_wallet=WALLET,
            total_feedback=39,
            name="ClawNews",
            active=True,
        ),
        method="agent_wallet+endpoint",
        confidence="high",
        reputation=ReputationSummary(
            raw_feedback_count=39,
            distinct_reviewers=20,
            average_score=81.2,
            top_tags=["quality"],
        ),
    )
    block = _erc8004_block(binding)
    assert block["bound"] is True
    assert block["agent_id"] == "1"
    assert block["binding_method"] == "agent_wallet+endpoint"
    assert block["binding_confidence"] == "high"
    assert block["raw_feedback_count"] == 39
    assert block["distinct_reviewers"] == 20
    assert block["raw_average_score"] == 81.2
    # M6 did not run (no sybil attached): honest not_checked, null counts
    assert block["sybil_status"] == "not_checked"
    assert block["sybil_filtered_count"] is None


def _bound_binding(sybil):
    from preflight402.reputation.types import AgentIdentity, Binding, ReputationSummary

    return Binding(
        bound=True,
        status="bound",
        agent=AgentIdentity(
            global_id="8453:1",
            chain_id=8453,
            agent_id="1",
            owner=WALLET,
            agent_wallet=WALLET,
            total_feedback=3,
        ),
        method="agent_wallet",
        confidence="medium",
        reputation=ReputationSummary(
            raw_feedback_count=3, distinct_reviewers=3, average_score=99.8
        ),
        sybil=sybil,
    )


def test_schema_block_sybil_complete_fills_filtered_fields() -> None:
    from preflight402.reputation.types import SybilResult
    from preflight402.verdict.schema import _erc8004_block

    block = _erc8004_block(
        _bound_binding(
            SybilResult(
                status="complete",
                reviewers=3,
                resolved=3,
                filtered_count=1,
                filtered_score=99.8,
            )
        )
    )
    assert block["sybil_status"] == "complete"
    assert block["sybil_filtered_count"] == 1
    assert block["filtered_score"] == 99.8


def test_schema_block_sybil_complete_truncated_fills_but_labels_honestly() -> None:
    # An agent with more feedback than one subgraph page still gets numbers,
    # but the status says they describe the newest-window reviewers only.
    from preflight402.reputation.types import SybilResult
    from preflight402.verdict.schema import _erc8004_block

    block = _erc8004_block(
        _bound_binding(
            SybilResult(
                status="complete_truncated",
                reviewers=996,
                resolved=1005,
                filtered_count=12,
                filtered_score=89.7,
            )
        )
    )
    assert block["sybil_status"] == "complete_truncated"
    assert block["sybil_filtered_count"] == 12
    assert block["filtered_score"] == 89.7


def test_schema_block_sybil_pending_keeps_counts_null() -> None:
    # partial coverage must never masquerade as a filtered number
    from preflight402.reputation.types import SybilResult
    from preflight402.verdict.schema import _erc8004_block

    block = _erc8004_block(_bound_binding(SybilResult(status="pending", reviewers=3, resolved=1)))
    assert block["sybil_status"] == "pending"
    assert block["sybil_filtered_count"] is None
    assert block["filtered_score"] is None


# --- full pipeline through the service ---------------------------------------


@respx.mock
async def test_preflight_populates_reputation_block(tmp_path, monkeypatch) -> None:
    import base64
    import json

    from preflight402 import service
    from preflight402.probe.prober import ProbeResult
    from preflight402.probe.tls import TLSInfo

    # a 402 whose payTo is the ClawNews wallet, served from clawnews.io
    payload = {
        "x402Version": 2,
        "resource": {"url": "https://clawnews.io/api/x402"},
        "accepts": [
            {
                "scheme": "exact",
                "network": "eip155:8453",
                "amount": "10000",
                "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                "payTo": WALLET,
                "maxTimeoutSeconds": 300,
            }
        ],
    }
    headers = {"payment-required": base64.b64encode(json.dumps(payload).encode()).decode()}

    async def stub_probe(url, *, timeout_s=10.0, pinned_ip=None, enforce_pin=False, **_):
        return ProbeResult(
            url=url,
            ok=True,
            http_status=402,
            headers=headers,
            body="{}",
            latency_ms=120.0,
            tls=TLSInfo(valid=True, expires_at="2027-01-01T00:00:00.000Z", issuer="LE"),
        )

    monkeypatch.setattr(service, "probe", stub_probe)
    graphql_mock([agent_row()], feedbacks=[{"value": "80", "clientAddress": "0xAAA"}])

    st = settings(db_path=tmp_path / "rep.db", allow_private_targets=True)
    service.ensure_migrated.cache_clear()
    result = await service.get_preflight("https://clawnews.io/api/x402", st)
    erc = result.document["reputation"]["erc8004"]
    assert erc["bound"] is True
    assert erc["agent_id"] == "1"
    assert erc["binding_confidence"] == "high"
    assert erc["raw_feedback_count"] == 1


async def test_preflight_reputation_null_when_feature_off(tmp_path, monkeypatch) -> None:
    from preflight402 import service
    from preflight402.probe.prober import ProbeResult

    async def stub_probe(url, *, timeout_s=10.0, pinned_ip=None, enforce_pin=False, **_):
        return ProbeResult(url=url, ok=True, http_status=200, body="hi")

    monkeypatch.setattr(service, "probe", stub_probe)
    st = Settings(_env_file=None, db_path=tmp_path / "off.db", allow_private_targets=True)
    service.ensure_migrated.cache_clear()
    result = await service.get_preflight("http://plain.example/x", st)
    assert result.document["reputation"]["erc8004"]["bound"] is None
    assert result.document["reputation"]["erc8004"]["binding_status"] == "not_checked"


@respx.mock
async def test_preflight_reputation_error_is_not_a_false_unbound(tmp_path, monkeypatch) -> None:
    # end-to-end: feature ON, real payment endpoint, but the subgraph is
    # rate-limited (403). The block must say bound=null + status=error, NOT
    # bound=false — the exact silent-misreport this fix prevents.
    import base64
    import json

    from preflight402 import service
    from preflight402.probe.prober import ProbeResult
    from preflight402.probe.tls import TLSInfo

    payload = {
        "x402Version": 2,
        "resource": {"url": "https://pay.example/x402"},
        "accepts": [
            {
                "scheme": "exact",
                "network": "eip155:8453",
                "amount": "10000",
                "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                "payTo": WALLET,
                "maxTimeoutSeconds": 300,
            }
        ],
    }
    headers = {"payment-required": base64.b64encode(json.dumps(payload).encode()).decode()}

    async def stub_probe(url, *, timeout_s=10.0, pinned_ip=None, enforce_pin=False, **_):
        return ProbeResult(
            url=url,
            ok=True,
            http_status=402,
            headers=headers,
            body="{}",
            latency_ms=100.0,
            tls=TLSInfo(valid=True, expires_at="2027-01-01T00:00:00.000Z", issuer="LE"),
        )

    monkeypatch.setattr(service, "probe", stub_probe)
    respx.post(GW).mock(return_value=httpx.Response(403))  # exhausted shared key

    st = settings(db_path=tmp_path / "err.db", allow_private_targets=True)
    service.ensure_migrated.cache_clear()
    result = await service.get_preflight("https://pay.example/x402", st)
    erc = result.document["reputation"]["erc8004"]
    assert erc["bound"] is None  # unknown, NOT a false "no agent"
    assert erc["binding_status"] == "error"


# --- M6: sybil wiring through the service -------------------------------------

ALCHEMY_KEY = "test-alchemy-key"
ALCHEMY_URL = f"https://base-mainnet.g.alchemy.com/v2/{ALCHEMY_KEY}"
FUNDER = "0x" + "f1".rjust(40, "0")


def _x402_headers() -> dict[str, str]:
    import base64
    import json

    payload = {
        "x402Version": 2,
        "resource": {"url": "https://clawnews.io/api/x402"},
        "accepts": [
            {
                "scheme": "exact",
                "network": "eip155:8453",
                "amount": "10000",
                "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                "payTo": WALLET,
                "maxTimeoutSeconds": 300,
            }
        ],
    }
    return {"payment-required": base64.b64encode(json.dumps(payload).encode()).decode()}


def _stub_probe_factory(headers):
    from preflight402.probe.prober import ProbeResult
    from preflight402.probe.tls import TLSInfo

    async def stub_probe(url, *, timeout_s=10.0, pinned_ip=None, enforce_pin=False, **_):
        return ProbeResult(
            url=url,
            ok=True,
            http_status=402,
            headers=headers,
            body="{}",
            latency_ms=100.0,
            tls=TLSInfo(valid=True, expires_at="2027-01-01T00:00:00.000Z", issuer="LE"),
        )

    return stub_probe


def _alchemy_mock() -> None:
    import json as jsonlib

    def handler(request: httpx.Request) -> httpx.Response:
        payload = jsonlib.loads(request.content)
        if payload["method"] == "alchemy_getAssetTransfers":
            transfers = [{"from": FUNDER, "hash": "0x1", "blockNum": "0x10"}]
            return httpx.Response(
                200, json={"jsonrpc": "2.0", "id": 1, "result": {"transfers": transfers}}
            )
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": "0x"})

    respx.post(ALCHEMY_URL).mock(side_effect=handler)


@respx.mock
async def test_preflight_sybil_complete_end_to_end(tmp_path, monkeypatch) -> None:
    # Two reviewers, both first-funded by the same EOA -> one cluster.
    from preflight402 import service

    monkeypatch.setattr(service, "probe", _stub_probe_factory(_x402_headers()))
    graphql_mock(
        [agent_row()],
        feedbacks=[
            {"value": "100", "clientAddress": "0x" + "a1".rjust(40, "0")},
            {"value": "90", "clientAddress": "0x" + "a2".rjust(40, "0")},
        ],
    )
    _alchemy_mock()

    st = settings(
        db_path=tmp_path / "sybil.db", allow_private_targets=True, alchemy_api_key=ALCHEMY_KEY
    )
    service.ensure_migrated.cache_clear()
    result = await service.get_preflight("https://clawnews.io/api/x402", st)
    erc = result.document["reputation"]["erc8004"]
    assert erc["bound"] is True
    assert erc["raw_feedback_count"] == 2
    assert erc["distinct_reviewers"] == 2
    assert erc["sybil_status"] == "complete"
    assert erc["sybil_filtered_count"] == 1  # shared funder collapses them
    assert erc["filtered_score"] == 95.0


@respx.mock
async def test_preflight_strong_filtered_reputation_upgrades_verdict(tmp_path, monkeypatch) -> None:
    # M6.3 end-to-end: three reviewers with three DISTINCT EOA funders = three
    # independent clusters at 90 avg — enough to waive the thin-history
    # cautions on a first-ever probe into proceed/medium.
    import json as jsonlib

    from preflight402 import service

    monkeypatch.setattr(service, "probe", _stub_probe_factory(_x402_headers()))
    graphql_mock(
        [agent_row()],
        feedbacks=[
            {"value": "90", "clientAddress": "0x" + "a1".rjust(40, "0")},
            {"value": "85", "clientAddress": "0x" + "a2".rjust(40, "0")},
            {"value": "95", "clientAddress": "0x" + "a3".rjust(40, "0")},
        ],
    )

    def handler(request: httpx.Request) -> httpx.Response:
        payload = jsonlib.loads(request.content)
        if payload["method"] == "alchemy_getAssetTransfers":
            target = payload["params"][0]["toAddress"].lower()
            funder = "0x" + f"f{target[-1]}".rjust(40, "0")  # distinct funder per reviewer
            transfers = [{"from": funder, "hash": "0x1", "blockNum": "0x10"}]
            return httpx.Response(
                200, json={"jsonrpc": "2.0", "id": 1, "result": {"transfers": transfers}}
            )
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": "0x"})

    respx.post(ALCHEMY_URL).mock(side_effect=handler)

    st = settings(
        db_path=tmp_path / "vouch.db", allow_private_targets=True, alchemy_api_key=ALCHEMY_KEY
    )
    service.ensure_migrated.cache_clear()
    result = await service.get_preflight("https://clawnews.io/api/x402", st)
    erc = result.document["reputation"]["erc8004"]
    assert erc["sybil_status"] == "complete"
    assert erc["sybil_filtered_count"] == 3
    assert erc["filtered_score"] == 90.0
    verdict = result.document["verdict"]
    assert verdict["recommendation"] == "proceed"
    assert verdict["confidence"] == "medium"
    assert any("strong sybil-filtered reputation" in r for r in verdict["reasons"])
    assert any("single probe only" in r for r in verdict["reasons"])


@respx.mock
async def test_preflight_sybil_not_checked_without_alchemy_key(tmp_path, monkeypatch) -> None:
    from preflight402 import service

    monkeypatch.setattr(service, "probe", _stub_probe_factory(_x402_headers()))
    graphql_mock([agent_row()], feedbacks=[{"value": "80", "clientAddress": "0xAAA"}])

    st = settings(db_path=tmp_path / "nokey.db", allow_private_targets=True)
    service.ensure_migrated.cache_clear()
    result = await service.get_preflight("https://clawnews.io/api/x402", st)
    erc = result.document["reputation"]["erc8004"]
    assert erc["bound"] is True
    assert erc["sybil_status"] == "not_checked"
    assert erc["sybil_filtered_count"] is None


@respx.mock
async def test_preflight_sybil_pending_when_rpc_down(tmp_path, monkeypatch) -> None:
    # Alchemy unreachable: the preflight still serves, sybil reports pending.
    from preflight402 import service

    monkeypatch.setattr(service, "probe", _stub_probe_factory(_x402_headers()))
    graphql_mock([agent_row()], feedbacks=[{"value": "80", "clientAddress": "0xAAA"}])
    respx.post(ALCHEMY_URL).mock(side_effect=httpx.ConnectError("down"))

    st = settings(
        db_path=tmp_path / "down.db", allow_private_targets=True, alchemy_api_key=ALCHEMY_KEY
    )
    service.ensure_migrated.cache_clear()
    result = await service.get_preflight("https://clawnews.io/api/x402", st)
    erc = result.document["reputation"]["erc8004"]
    assert erc["bound"] is True
    assert erc["sybil_status"] == "pending"
    assert erc["sybil_filtered_count"] is None
