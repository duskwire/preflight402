"""Alchemy JSON-RPC client (M6): first-funder lookup + EOA-vs-contract check.

The two primitives of the Sybil filter (Research4-M6-sybil.md §1):
  - alchemy_getAssetTransfers(toAddress, category=["external"], order="asc",
    maxCount=1) — the earliest inbound native-token transfer IS the first
    funder (~150 CU). Base supports only the "external" category, which
    matches the paper's rule anyway (internal/contract-mediated funding does
    not qualify).
  - eth_getCode — funders must be EOAs; an EIP-7702 delegation designator
    (0xef0100 || address) still counts as a (delegated) EOA per the paper.

Never raises for network/RPC failures: a Sybil-filter read that fails must
degrade to "unresolved this pass" (retried next pass), never break the free
preflight. Failed lookups return None and are NOT cached by callers.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from types import TracebackType

import httpx

logger = logging.getLogger(__name__)

# Alchemy network slugs by chain id; Base first, same extension pattern as
# subgraph.SUBGRAPH_IDS.
ALCHEMY_NETWORKS: dict[int, str] = {
    8453: "base-mainnet",
}

# EIP-7702 delegation designator prefix: code = 0xef0100 || delegate address.
_DELEGATION_PREFIX = "0xef0100"


@dataclass(slots=True)
class FirstFunder:
    """The resolved first-funder fact for one address (a lookup that WORKED).

    funder is None when the address has no inbound external native transfer
    at all (funded via a contract/internal path) — a permanent, cacheable
    "none" per the funding schema.
    """

    funder: str | None  # lowercased, or None when no external funding exists
    tx_hash: str | None = None
    block_num: int | None = None


class AlchemyClient:
    """Async JSON-RPC client over one chain's Alchemy endpoint.

    Use as an async context manager so all lookups of a Sybil pass share one
    connection pool; `concurrency` bounds parallel in-flight calls to stay
    polite against the free-tier throughput cap (25 rps / 500 CUPS).
    """

    def __init__(
        self,
        api_key: str,
        *,
        chain_id: int = 8453,
        timeout_s: float = 5.0,
        concurrency: int = 8,
    ) -> None:
        self._chain_id = chain_id
        self._api_key = api_key
        network = ALCHEMY_NETWORKS.get(chain_id)
        self._url = f"https://{network}.g.alchemy.com/v2/{api_key}" if network else None
        self._timeout_s = timeout_s
        self._semaphore = asyncio.Semaphore(max(1, concurrency))
        self._client: httpx.AsyncClient | None = None

    def _redact(self, exc: Exception) -> str:
        """httpx exception strings embed the request URL — and the API key is
        IN the URL, so it must never reach the logs verbatim."""
        return str(exc).replace(self._api_key, "<key>")

    async def __aenter__(self) -> AlchemyClient:
        self._client = httpx.AsyncClient(timeout=self._timeout_s)
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def _call(self, method: str, params: list) -> object | None:
        """One JSON-RPC call; None on ANY failure (network, HTTP, RPC error)."""
        if self._url is None or self._client is None:
            return None
        payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
        try:
            async with self._semaphore:
                response = await self._client.post(self._url, json=payload)
            response.raise_for_status()
            body = response.json()
        except Exception as exc:  # never-raises boundary, same as subgraph.py:
            # CancelledError is a BaseException and still propagates, so the
            # pass-level asyncio.timeout cancels cleanly through here.
            logger.warning(
                "alchemy %s failed (chain %s): %s", method, self._chain_id, self._redact(exc)
            )
            return None
        if not isinstance(body, dict) or body.get("error") is not None:
            logger.warning(
                "alchemy %s returned error (chain %s): %s",
                method,
                self._chain_id,
                body.get("error") if isinstance(body, dict) else type(body),
            )
            return None
        return body.get("result")

    async def first_funder(self, address: str) -> FirstFunder | None:
        """The earliest inbound external native transfer to `address`.

        None means the LOOKUP FAILED (do not cache); FirstFunder(funder=None)
        means the lookup worked and no external funding exists (cache 'none').
        """
        result = await self._call(
            "alchemy_getAssetTransfers",
            [
                {
                    "fromBlock": "0x0",
                    "toBlock": "latest",
                    "toAddress": address,
                    "category": ["external"],
                    "order": "asc",
                    "maxCount": "0x1",
                    "excludeZeroValue": True,
                }
            ],
        )
        if not isinstance(result, dict) or not isinstance(result.get("transfers"), list):
            return None
        transfers = result["transfers"]
        if not transfers:
            return FirstFunder(funder=None)
        first = transfers[0]
        if not isinstance(first, dict) or not isinstance(first.get("from"), str):
            return None
        block_hex = first.get("blockNum")
        try:
            block_num = int(block_hex, 16) if isinstance(block_hex, str) else None
        except ValueError:
            block_num = None
        tx_hash = first.get("hash")
        return FirstFunder(
            funder=first["from"].lower(),
            tx_hash=tx_hash if isinstance(tx_hash, str) else None,
            block_num=block_num,
        )

    async def is_contract(self, address: str) -> bool | None:
        """True when `address` has real contract code deployed.

        An empty code ("0x") is a plain EOA and an EIP-7702 delegation
        designator still qualifies as a (delegated) EOA — both return False.
        None means the lookup failed.
        """
        result = await self._call("eth_getCode", [address, "latest"])
        if not isinstance(result, str) or not result.startswith("0x"):
            return None
        code = result.lower()
        if code == "0x":
            return False
        return not code.startswith(_DELEGATION_PREFIX)
