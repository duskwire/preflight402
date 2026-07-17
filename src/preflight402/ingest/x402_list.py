"""x402-list.com seed source.

GET https://x402-list.com/api/v1/services — page-numbered {data,
meta:{total, page, per_page, total_pages}}. List items carry only a
service-level base_url; the actual endpoint paths live in the per-slug
detail (GET .../services/{slug} → data.endpoints[].path). ~140 services,
rate-limited at 200 req/min, so detail fetches are spaced by DETAIL_DELAY_S.

Endpoints are seeded whether or not the registry marks them active — a
listed-but-dead endpoint is exactly what our zombie detection wants to see.
A failed or junk-shaped detail fetch falls back to seeding the service
base_url, marked with meta x402-list.detail_fallback=true so a systematic
detail outage stays visible (the runner counts these in seeded_fallback).

Path joining: a '/'-anchored detail path is root-relative (observed live:
services whose base_url itself has a path, with detail paths repeating that
full path — plain concatenation would double it); anything else is joined
under base_url. Untrusted input rules match the other sources: isinstance
checks, junk skipped, non-dict page raises ValueError, MAX_PAGES bound.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from urllib.parse import quote, urlsplit

import httpx

from preflight402.ingest.types import SeedRecord

SOURCE = "x402-list"
BASE_URL = "https://x402-list.com/api/v1/services"
PAGE_SIZE = 100
MAX_PAGES = 50  # 5k services — ~35x the catalog as of 2026-07
PAGE_DELAY_S = 0.25  # courtesy spacing between list pages
DETAIL_DELAY_S = 0.35  # 200 req/min limit; stay comfortably under it


async def records(
    client: httpx.AsyncClient, *, max_records: int | None = None
) -> AsyncIterator[SeedRecord]:
    """Yield one SeedRecord per endpoint of every listed service."""
    yielded = 0
    for page in range(1, MAX_PAGES + 1):
        if page > 1:
            await asyncio.sleep(PAGE_DELAY_S)
        response = await client.get(BASE_URL, params={"page": page, "per_page": PAGE_SIZE})
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, dict):
            raise ValueError(f"x402-list page is not a JSON object: {type(payload).__name__}")
        services = payload.get("data")
        if not isinstance(services, list) or not services:
            return
        for service in services:
            if not isinstance(service, dict):
                continue
            base = service.get("base_url")
            slug = service.get("slug")
            if not isinstance(base, str) or not base.startswith("http"):
                continue
            meta = {
                key: value
                for key, value in (
                    ("service", service.get("name") or slug),
                    ("category", service.get("category")),
                )
                if isinstance(value, str) and value
            }
            urls, is_fallback = await _endpoint_urls(
                client, slug if isinstance(slug, str) else "", base
            )
            record_meta = dict(meta, detail_fallback=True) if is_fallback else (meta or None)
            for url in urls:
                yield SeedRecord(url=url, source=SOURCE, meta=record_meta)
                yielded += 1
                if max_records is not None and yielded >= max_records:
                    return
        meta_block = payload.get("meta")
        total_pages = meta_block.get("total_pages") if isinstance(meta_block, dict) else None
        if isinstance(total_pages, int) and page >= total_pages:
            return


async def _endpoint_urls(client: httpx.AsyncClient, slug: str, base: str) -> tuple[list[str], bool]:
    """(endpoint URLs, used_fallback) — ([base], True) when detail is unusable."""
    if not slug:
        return [base], True
    await asyncio.sleep(DETAIL_DELAY_S)
    try:
        response = await client.get(f"{BASE_URL}/{quote(slug, safe='')}")
        response.raise_for_status()
        payload = response.json()
        data = payload.get("data") if isinstance(payload, dict) else None
        endpoints = data.get("endpoints") if isinstance(data, dict) else None
        if not isinstance(endpoints, list):
            return [base], True
    except (httpx.HTTPError, httpx.InvalidURL, ValueError):
        return [base], True
    urls = []
    for endpoint in endpoints:
        if not isinstance(endpoint, dict):
            continue
        path = endpoint.get("path")
        if isinstance(path, str) and path:
            urls.append(_join(base, path))
    return (urls, False) if urls else ([base], True)


def _join(base: str, path: str) -> str:
    """Root-relative for '/'-anchored paths, under-base for bare ones."""
    if path.startswith("/"):
        parts = urlsplit(base)
        return f"{parts.scheme}://{parts.netloc}{path}"
    return base.rstrip("/") + "/" + path
