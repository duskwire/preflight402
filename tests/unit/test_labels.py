"""Vendored hub-label set (M6): loader integrity."""

from __future__ import annotations

import re

from preflight402.reputation.labels import hub_addresses, is_hub

HEX_ADDRESS = re.compile(r"^0x[0-9a-f]{40}$")


def test_hub_set_loads_and_is_wellformed() -> None:
    hubs = hub_addresses()
    assert len(hubs) > 30_000  # ~37k at generation; guard against a truncated vendor file
    sample = list(hubs)[:200]
    assert all(HEX_ADDRESS.match(address) for address in sample)


def test_known_coinbase_hot_wallet_is_a_hub() -> None:
    # Coinbase 10 (Etherscan-labeled) — a canonical CEX hot wallet whose EOA
    # key is chain-agnostic. If this ever fails the vendor file regressed.
    assert is_hub("0xA9D1e08C7793af67e9d92fe308d5697FB81d3E43")  # checksummed input
    assert is_hub("0xa9d1e08c7793af67e9d92fe308d5697fb81d3e43")


def test_random_address_is_not_a_hub() -> None:
    assert not is_hub("0x0000000000000000000000000000000000001234")
