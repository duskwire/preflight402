"""Sybil engine (M6): clustering, ancestry, hub exclusion, coverage honesty."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import httpx
import pytest
import respx

from preflight402.config import Settings
from preflight402.db import connect, migrate
from preflight402.db import queries as q
from preflight402.reputation.sybil import sybil_filter

pytestmark = pytest.mark.anyio

KEY = "test-alchemy-key"
URL = f"https://base-mainnet.g.alchemy.com/v2/{KEY}"
BASE = 8453
AGENT = "8453:1380"

# 40-hex-char addresses (checksum irrelevant; engine lowercases).
A1, A2, A3 = (f"0x{i:040x}" for i in (0xA1, 0xA2, 0xA3))
F, G, R = (f"0x{i:040x}" for i in (0xF1, 0xF2, 0xEE))
I1, I2 = (f"0x{i:040x}" for i in (0x11, 0x12))
CONTRACT_CODE = "0x6080604052"
DELEGATION_CODE = "0xef0100" + "ab" * 20
# A real labeled hub from the vendored set (Coinbase 10).
HUB = "0xa9d1e08c7793af67e9d92fe308d5697fb81d3e43"


@pytest.fixture()
def db(tmp_path: Path):
    conn = connect(tmp_path / "test.db")
    migrate(conn)
    yield conn
    conn.close()


def settings(**over) -> Settings:
    over.setdefault("alchemy_api_key", KEY)
    over.setdefault("sybil_pass_timeout_s", 0)  # tests control their own time
    return Settings(_env_file=None, **over)


def rpc_mock(funders: dict[str, str | None], codes: dict[str, str], calls: list[dict]):
    """Route Alchemy JSON-RPC by method: funders maps address->first funder
    (absent/None = no external funding), codes maps address->eth_getCode."""

    def handler(request: httpx.Request) -> httpx.Response:
        import json

        payload = json.loads(request.content)
        calls.append(payload)
        if payload["method"] == "alchemy_getAssetTransfers":
            target = payload["params"][0]["toAddress"].lower()
            funder = funders.get(target)
            transfers = (
                [] if funder is None else [{"from": funder, "hash": "0xdead", "blockNum": "0x10"}]
            )
            return httpx.Response(
                200, json={"jsonrpc": "2.0", "id": 1, "result": {"transfers": transfers}}
            )
        if payload["method"] == "eth_getCode":
            code = codes.get(payload["params"][0].lower(), "0x")
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": code})
        raise AssertionError(f"unexpected method {payload['method']}")

    respx.post(URL).mock(side_effect=handler)


@respx.mock
async def test_shared_eoa_funder_clusters_one_vote(db) -> None:
    calls: list[dict] = []
    rpc_mock({A1: F, A2: F, A3: G}, {}, calls)
    result = await sybil_filter(db, BASE, AGENT, {A1: [100.0], A2: [90.0], A3: [50.0]}, settings())
    assert result.status == "complete"
    assert result.reviewers == 3
    assert result.resolved == 5  # 3 reviewers + ancestry facts for F and G
    assert result.filtered_count == 2  # {A1, A2} via F, {A3} via G
    # cluster means: (100+90)/2 = 95 and 50 -> (95+50)/2
    assert result.filtered_score == 72.5
    # the shared funder F cost exactly one eth_getCode
    code_calls = [c for c in calls if c["method"] == "eth_getCode"]
    assert sorted(c["params"][0].lower() for c in code_calls) == sorted([F, G])


@respx.mock
async def test_funding_chain_clusters_transitively(db) -> None:
    # A1 funded by reviewer A2; A2 and A3 share funder F -> one cluster.
    rpc_mock({A1: A2, A2: F, A3: F}, {}, [])
    result = await sybil_filter(db, BASE, AGENT, {A1: [90.0], A2: [80.0], A3: [70.0]}, settings())
    assert result.filtered_count == 1
    assert result.filtered_score == 80.0


@respx.mock
async def test_one_hop_intermediaries_cluster_by_root(db) -> None:
    # The paper's ROOT-ancestry rule: A1<-I1<-R and A2<-I2<-R must be ONE
    # cluster even though the direct funders differ (one-hop intermediary
    # wallets per Sybil must not defeat the filter).
    rpc_mock({A1: I1, A2: I2, I1: R, I2: R}, {}, [])
    result = await sybil_filter(db, BASE, AGENT, {A1: [100.0], A2: [0.0]}, settings())
    assert result.status == "complete"
    assert result.filtered_count == 1
    assert result.filtered_score == 50.0


@respx.mock
async def test_ancestry_depth_1_reverts_to_direct_funder_only(db) -> None:
    rpc_mock({A1: I1, A2: I2, I1: R, I2: R}, {}, [])
    result = await sybil_filter(
        db, BASE, AGENT, {A1: [100.0], A2: [0.0]}, settings(sybil_ancestry_depth=1)
    )
    assert result.filtered_count == 2  # depth 1 never sees the shared root


@respx.mock
async def test_contract_funder_gives_no_edge(db) -> None:
    rpc_mock({A1: F, A2: F}, {F: CONTRACT_CODE}, [])
    result = await sybil_filter(db, BASE, AGENT, {A1: [100.0], A2: [0.0]}, settings())
    assert result.status == "complete"
    assert result.filtered_count == 2  # infrastructure funder: independent
    assert result.filtered_score == 50.0


@respx.mock
async def test_delegated_eoa_funder_still_clusters(db) -> None:
    rpc_mock({A1: F, A2: F}, {F: DELEGATION_CODE}, [])
    result = await sybil_filter(db, BASE, AGENT, {A1: [100.0], A2: [0.0]}, settings())
    assert result.filtered_count == 1  # EIP-7702 delegated EOA qualifies


@respx.mock
async def test_labeled_hub_funder_never_clusters(db) -> None:
    rpc_mock({A1: HUB, A2: HUB}, {}, [])
    result = await sybil_filter(db, BASE, AGENT, {A1: [100.0], A2: [0.0]}, settings())
    assert result.filtered_count == 2  # onboarded via the same CEX != same person
    assert result.excluded_hub_funders == 1


def _seed_cross_agent_spread(db, funder: str, agents: int) -> None:
    for i in range(agents):
        other = f"0x{0xB0 + i:040x}"
        q.put_reviewer_funding(
            db, BASE, other, status="ok", funder=funder, funder_is_contract=False
        )
        q.record_reviewer_agents(db, BASE, [other], f"8453:{i}")


@respx.mock
async def test_fanout_hub_heuristic_is_off_by_default(db) -> None:
    # The spread derives from attacker-writable feedback: with the default
    # config a farm funder spanning many agents must STILL cluster its
    # reviewers (whitewash regression — the finding that disabled fan-out).
    _seed_cross_agent_spread(db, F, agents=4)
    rpc_mock({A1: F, A2: F}, {}, [])
    result = await sybil_filter(db, BASE, AGENT, {A1: [100.0], A2: [0.0]}, settings())
    assert result.filtered_count == 1
    assert result.excluded_hub_funders == 0


@respx.mock
async def test_cross_agent_fanout_marks_unlabeled_hub_when_opted_in(db) -> None:
    # F already funded cached reviewers spanning 4 OTHER agents; with this
    # agent it reaches the 5-distinct-agents threshold -> de-facto hub.
    _seed_cross_agent_spread(db, F, agents=4)
    rpc_mock({A1: F, A2: F}, {}, [])
    result = await sybil_filter(
        db, BASE, AGENT, {A1: [100.0], A2: [0.0]}, settings(sybil_hub_min_agents=5)
    )
    assert result.filtered_count == 2
    assert result.excluded_hub_funders == 1


@respx.mock
async def test_within_agent_fanout_is_not_hub_evidence(db) -> None:
    # Ten reviewers of ONE agent sharing a funder is the Sybil signal itself,
    # even with the fan-out heuristic opted in.
    reviewers = {f"0x{0xC0 + i:040x}": [99.0] for i in range(10)}
    rpc_mock(dict.fromkeys(reviewers, F), {}, [])
    result = await sybil_filter(db, BASE, AGENT, reviewers, settings(sybil_hub_min_agents=5))
    assert result.filtered_count == 1
    assert result.excluded_hub_funders == 0


@respx.mock
async def test_no_external_funding_is_a_complete_singleton(db) -> None:
    rpc_mock({A1: None, A2: F}, {}, [])
    result = await sybil_filter(db, BASE, AGENT, {A1: [80.0], A2: [60.0]}, settings())
    assert result.status == "complete"
    assert result.filtered_count == 2


@respx.mock
async def test_truncated_feedback_window_reports_complete_truncated(db) -> None:
    rpc_mock({A1: F}, {}, [])
    result = await sybil_filter(db, BASE, AGENT, {A1: [80.0]}, settings(), feedback_truncated=True)
    assert result.status == "complete_truncated"
    assert result.filtered_count == 1  # numbers still populate, honestly labeled
    assert result.filtered_score == 80.0


@respx.mock
async def test_budget_yields_pending_then_cache_converges(db) -> None:
    calls: list[dict] = []
    rpc_mock({A1: F, A2: F, A3: G}, {}, calls)
    scores = {A1: [100.0], A2: [90.0], A3: [50.0]}
    st = settings(sybil_max_lookups_per_pass=2)

    first = await sybil_filter(db, BASE, AGENT, scores, st)
    assert first.status == "pending"
    assert first.resolved == 2  # A1, A2; budget spent
    assert first.filtered_count is None and first.filtered_score is None
    assert len([c for c in calls if c["method"] == "alchemy_getAssetTransfers"]) == 2

    second = await sybil_filter(db, BASE, AGENT, scores, st)
    assert second.status == "pending"
    assert second.resolved == 4  # + A3, + one of the ancestry facts (F or G)

    third = await sybil_filter(db, BASE, AGENT, scores, st)
    assert third.status == "complete"
    assert third.resolved == 5
    assert third.filtered_count == 2
    # 5 facts total, each looked up exactly once across all passes
    assert len([c for c in calls if c["method"] == "alchemy_getAssetTransfers"]) == 5


@respx.mock
async def test_rpc_failure_is_pending_and_uncached_then_recovers(db) -> None:
    respx.post(URL).mock(return_value=httpx.Response(500))
    result = await sybil_filter(db, BASE, AGENT, {A1: [80.0]}, settings())
    assert result.status == "pending"
    assert result.resolved == 0
    assert q.get_reviewer_funding(db, BASE, [A1]) == {}  # failures never cached
    respx.post(URL).mock(side_effect=None)
    rpc_mock({A1: F}, {}, [])
    retry = await sybil_filter(db, BASE, AGENT, {A1: [80.0]}, settings())
    assert retry.status == "complete"


@respx.mock
async def test_code_check_failure_leaves_whole_fact_uncached(db) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        import json

        payload = json.loads(request.content)
        if payload["method"] == "alchemy_getAssetTransfers":
            return httpx.Response(
                200,
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {"transfers": [{"from": F, "hash": "0x1", "blockNum": "0x10"}]},
                },
            )
        return httpx.Response(500)  # eth_getCode fails

    respx.post(URL).mock(side_effect=handler)
    result = await sybil_filter(db, BASE, AGENT, {A1: [80.0]}, settings())
    assert result.status == "pending"
    assert q.get_reviewer_funding(db, BASE, [A1]) == {}  # no half-fact rows


async def test_feature_off_and_edge_cases_return_none(db) -> None:
    assert await sybil_filter(db, BASE, AGENT, {A1: [1.0]}, Settings(_env_file=None)) is None
    assert await sybil_filter(db, 999, AGENT, {A1: [1.0]}, settings()) is None  # unknown chain
    assert await sybil_filter(db, BASE, AGENT, {}, settings()) is None  # no reviewers


async def test_never_raises_on_db_failure(db, monkeypatch) -> None:
    # The free preflight must survive a locked/broken DB: pending, not raise.
    def boom(*args, **kwargs):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(q, "get_reviewer_funding", boom)
    result = await sybil_filter(db, BASE, AGENT, {A1: [80.0]}, settings())
    assert result.status == "pending"
    assert result.resolved == 0


async def test_never_raises_on_labels_failure(db, monkeypatch) -> None:
    # A corrupt/missing vendored hub file (bad deploy) degrades to pending.
    import preflight402.reputation.sybil as sybil_module

    def boom():
        raise FileNotFoundError("hub_addresses.txt.gz missing")

    monkeypatch.setattr(sybil_module, "hub_addresses", boom)
    result = await sybil_filter(db, BASE, AGENT, {A1: [80.0]}, settings())
    assert result.status == "pending"


@respx.mock
async def test_unscored_reviewers_count_but_do_not_score(db) -> None:
    rpc_mock({A1: F, A2: G}, {}, [])
    result = await sybil_filter(db, BASE, AGENT, {A1: [], A2: [70.0]}, settings())
    assert result.filtered_count == 2
    assert result.filtered_score == 70.0
    only_unscored = await sybil_filter(db, BASE, "8453:2", {A1: []}, settings())
    assert only_unscored.filtered_count == 1
    assert only_unscored.filtered_score is None


@respx.mock
async def test_counters_meter_lookups_and_completions(db) -> None:
    rpc_mock({A1: F}, {}, [])
    await sybil_filter(db, BASE, AGENT, {A1: [80.0]}, settings())
    counters = q.counters_since(db, "1970-01-01")
    assert sum(counters["sybil_lookups"].values()) == 2  # A1 + ancestry fact for F
    assert sum(counters["sybil_passes_complete"].values()) == 1
    # a fully cached pass does not bump lookups again
    await sybil_filter(db, BASE, AGENT, {A1: [80.0]}, settings())
    counters = q.counters_since(db, "1970-01-01")
    assert sum(counters["sybil_lookups"].values()) == 2
    assert sum(counters["sybil_passes_complete"].values()) == 2


@respx.mock
async def test_daily_lookup_cap_stops_service_path_but_not_backfill(db) -> None:
    calls: list[dict] = []
    rpc_mock({A1: F}, {}, calls)
    q.bump_counter(db, "sybil_lookups", by=5000)  # today's budget already spent
    result = await sybil_filter(db, BASE, AGENT, {A1: [80.0]}, settings())
    assert result.status == "pending"
    assert calls == []  # not a single RPC call past the cap
    # an operator backfill (explicit max_lookups) bypasses the daily cap
    backfill = await sybil_filter(db, BASE, AGENT, {A1: [80.0]}, settings(), max_lookups=0)
    assert backfill.status == "complete"
