"""CDP Bazaar seed source.

GET https://api.cdp.coinbase.com/platform/v2/x402/discovery/resources
(open, no auth) — offset-paginated {items, pagination:{limit, offset,
total}}. Items are x402 v2 discovery records: `resource` is the endpoint
URL (some are /:param route templates — the runner skips those), `type` is
"http" for probe-able endpoints, `accepts` carries the offers (re-learned
live at probe time, so not copied into meta).

Registry payloads are untrusted: every shape is isinstance-checked, junk
records are skipped, and a non-dict page aborts this source with ValueError
(the runner records it and moves on). MAX_PAGES bounds the crawl even
against a server that repeats non-empty pages with a junk total.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import httpx

from preflight402.ingest.types import SeedRecord

SOURCE = "bazaar"
BASE_URL = "https://api.cdp.coinbase.com/platform/v2/x402/discovery/resources"
PAGE_SIZE = 100
MAX_PAGES = 1000  # 100k records — ~4x the catalog as of 2026-07


async def records(
    client: httpx.AsyncClient, *, max_records: int | None = None
) -> AsyncIterator[SeedRecord]:
    """Yield one SeedRecord per http-typed catalog item, paging through all."""
    offset = 0
    yielded = 0
    for _ in range(MAX_PAGES):
        response = await client.get(BASE_URL, params={"limit": PAGE_SIZE, "offset": offset})
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, dict):
            raise ValueError(f"bazaar page is not a JSON object: {type(payload).__name__}")
        items = payload.get("items")
        if not isinstance(items, list) or not items:
            return
        for item in items:
            if not isinstance(item, dict):
                continue
            url = item.get("resource")
            if item.get("type") != "http" or not isinstance(url, str) or not url.startswith("http"):
                continue
            meta = {
                key: item[key]
                for key in ("serviceName", "lastUpdated")
                if isinstance(item.get(key), str)
            }
            yield SeedRecord(url=url, source=SOURCE, meta=meta or None)
            yielded += 1
            if max_records is not None and yielded >= max_records:
                return
        offset += len(items)
        pagination = payload.get("pagination")
        total = pagination.get("total") if isinstance(pagination, dict) else None
        if isinstance(total, int) and offset >= total:
            return
