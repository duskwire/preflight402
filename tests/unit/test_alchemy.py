"""Alchemy client (M6): first-funder lookup + EOA check, never-raises contract."""

from __future__ import annotations

import httpx
import pytest
import respx

from preflight402.reputation.alchemy import AlchemyClient, FirstFunder

pytestmark = pytest.mark.anyio

KEY = "test-alchemy-key"
URL = f"https://base-mainnet.g.alchemy.com/v2/{KEY}"
REVIEWER = "0x89e9e1ab11dd1b138b1dce6d6a4a0926aafd5029"
FUNDER = "0xAB4CE88DB0277E05CFB5EEB346F6DFB635950ED0"


def rpc_result(result: object) -> httpx.Response:
    return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": result})


def transfers(items: list) -> object:
    return {"transfers": items, "pageKey": "ignored"}


@respx.mock
async def test_first_funder_parses_earliest_transfer() -> None:
    respx.post(URL).mock(
        return_value=rpc_result(
            transfers([{"from": FUNDER, "hash": "0xdead", "blockNum": "0x27be867"}])
        )
    )
    async with AlchemyClient(KEY) as client:
        funder = await client.first_funder(REVIEWER)
    assert funder == FirstFunder(funder=FUNDER.lower(), tx_hash="0xdead", block_num=0x27BE867)


@respx.mock
async def test_first_funder_none_transfers_is_a_cacheable_none() -> None:
    respx.post(URL).mock(return_value=rpc_result(transfers([])))
    async with AlchemyClient(KEY) as client:
        funder = await client.first_funder(REVIEWER)
    assert funder == FirstFunder(funder=None)  # lookup WORKED, no funding exists


@respx.mock
async def test_first_funder_failure_is_not_cacheable() -> None:
    respx.post(URL).mock(return_value=httpx.Response(500))
    async with AlchemyClient(KEY) as client:
        assert await client.first_funder(REVIEWER) is None


@respx.mock
async def test_first_funder_rpc_error_body_is_a_failure() -> None:
    respx.post(URL).mock(
        return_value=httpx.Response(
            200, json={"jsonrpc": "2.0", "id": 1, "error": {"code": -32000, "message": "capacity"}}
        )
    )
    async with AlchemyClient(KEY) as client:
        assert await client.first_funder(REVIEWER) is None


@respx.mock
async def test_first_funder_malformed_transfer_is_a_failure() -> None:
    respx.post(URL).mock(return_value=rpc_result(transfers([{"hash": "0xdead"}])))  # no "from"
    async with AlchemyClient(KEY) as client:
        assert await client.first_funder(REVIEWER) is None


@respx.mock
async def test_first_funder_survives_bad_block_hex() -> None:
    respx.post(URL).mock(
        return_value=rpc_result(transfers([{"from": FUNDER, "hash": 7, "blockNum": "zzz"}]))
    )
    async with AlchemyClient(KEY) as client:
        funder = await client.first_funder(REVIEWER)
    assert funder == FirstFunder(funder=FUNDER.lower(), tx_hash=None, block_num=None)


@respx.mock
async def test_is_contract_distinguishes_eoa_delegated_and_contract() -> None:
    codes = iter(["0x", "0xEF0100" + "ab" * 20, "0x6080604052", "not-hex"])
    respx.post(URL).mock(side_effect=lambda request: rpc_result(next(codes)))
    async with AlchemyClient(KEY) as client:
        assert await client.is_contract("0xa") is False  # plain EOA
        assert await client.is_contract("0xb") is False  # EIP-7702 delegated EOA
        assert await client.is_contract("0xc") is True  # deployed contract
        assert await client.is_contract("0xd") is None  # garbage result = failure


@respx.mock
async def test_network_exception_degrades_to_none() -> None:
    respx.post(URL).mock(side_effect=httpx.ConnectError("boom"))
    async with AlchemyClient(KEY) as client:
        assert await client.first_funder(REVIEWER) is None
        assert await client.is_contract(REVIEWER) is None


async def test_unknown_chain_returns_none_without_network() -> None:
    async with AlchemyClient(KEY, chain_id=999999) as client:
        assert await client.first_funder(REVIEWER) is None
        assert await client.is_contract(REVIEWER) is None


@respx.mock
async def test_api_key_never_reaches_logs(caplog) -> None:
    # httpx exception strings embed the request URL, which embeds the key —
    # observed live: a 429's message printed the full keyed URL.
    respx.post(URL).mock(return_value=httpx.Response(429))
    with caplog.at_level("WARNING"):
        async with AlchemyClient(KEY) as client:
            await client.first_funder(REVIEWER)
    assert caplog.records, "expected a warning to be logged"
    assert KEY not in caplog.text
    assert "<key>" in caplog.text
