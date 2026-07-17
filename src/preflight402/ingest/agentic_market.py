"""agentic.market seed source.

GET https://api.agentic.market/v1/services — offset-paginated {services,
total, limit, offset}. Each service embeds its endpoints inline:
endpoints[].url is absolute, with pricing/method beside it. ~1,900 services
as of 2026-07; the best free bulk seed after Bazaar.

Untrusted input: shapes are isinstance-checked, junk records skipped, a
non-dict page raises ValueError for the runner to record, and MAX_PAGES
bounds the crawl against weird servers.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import httpx

from preflight402.ingest.types import SeedRecord

SOURCE = "agentic.market"
BASE_URL = "https://api.agentic.market/v1/services"
PAGE_SIZE = 100
MAX_PAGES = 200  # 20k services — ~10x the catalog as of 2026-07


async def records(
    client: httpx.AsyncClient, *, max_records: int | None = None
) -> AsyncIterator[SeedRecord]:
    """Yield one SeedRecord per endpoint of every listed service."""
    offset = 0
    yielded = 0
    for _ in range(MAX_PAGES):
        response = await client.get(BASE_URL, params={"limit": PAGE_SIZE, "offset": offset})
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, dict):
            raise ValueError(f"agentic.market page is not a JSON object: {type(payload).__name__}")
        services = payload.get("services")
        if not isinstance(services, list) or not services:
            return
        for service in services:
            if not isinstance(service, dict):
                continue
            service_meta = {
                key: value
                for key, value in (
                    ("service", service.get("name") or service.get("id")),
                    ("category", service.get("category")),
                )
                if isinstance(value, str) and value
            }
            endpoints = service.get("endpoints")
            for endpoint in endpoints if isinstance(endpoints, list) else []:
                if not isinstance(endpoint, dict):
                    continue
                url = endpoint.get("url")
                if not isinstance(url, str) or not url.startswith("http"):
                    continue
                yield SeedRecord(url=url, source=SOURCE, meta=service_meta or None)
                yielded += 1
                if max_records is not None and yielded >= max_records:
                    return
        offset += len(services)
        total = payload.get("total")
        if isinstance(total, int) and offset >= total:
            return
