"""Capture real 402 responses from Bazaar-listed endpoints as golden files.

Usage: uv run python scripts/capture_goldens.py [N]

Pages the CDP Bazaar discovery catalog (open, no auth), takes at most one
directly-probeable URL per host (route templates with :param segments are
skipped — they 404/400 without substitution), probes each with our own
prober, and writes responses that came back 402 to tests/golden/x402/ as
<host>.json. Existing goldens are never overwritten, so reruns only add
hosts. Parsers must treat these files as read-only fixtures.
"""

import asyncio
import json
import re
import sys
from datetime import UTC, datetime
from pathlib import Path

import httpx

from preflight402.probe.prober import probe

BAZAAR = "https://api.cdp.coinbase.com/platform/v2/x402/discovery/resources"
GOLDEN_DIR = Path(__file__).parents[1] / "tests" / "golden" / "x402"
TEMPLATE_SEGMENT = re.compile(r"/:[^/]+|/\{[^}]+\}")


async def candidate_urls(target_hosts: int) -> list[str]:
    urls: dict[str, str] = {}  # one URL per host, first listing wins
    async with httpx.AsyncClient(timeout=30) as client:
        offset = 0
        while len(urls) < target_hosts:
            resp = await client.get(BAZAAR, params={"limit": 100, "offset": offset})
            resp.raise_for_status()
            data = resp.json()
            items = data.get("items", [])
            if not items:
                break
            for item in items:
                url = item.get("resource", "")
                if item.get("type") != "http" or not url.startswith("http"):
                    continue
                if TEMPLATE_SEGMENT.search(url):
                    continue
                try:
                    host = httpx.URL(url).host
                except httpx.InvalidURL:
                    continue
                urls.setdefault(host, url)
            offset += 100
            if offset >= data.get("pagination", {}).get("total", 0):
                break
    return list(urls.values())


async def main(want: int) -> None:
    GOLDEN_DIR.mkdir(parents=True, exist_ok=True)
    have = {p.stem for p in GOLDEN_DIR.glob("*.json")}
    urls = await candidate_urls(want * 8)  # 402 hit-rate is unknown; oversample
    print(f"{len(urls)} candidate hosts ({len(have)} goldens already present)")

    semaphore = asyncio.Semaphore(10)
    lock = asyncio.Lock()
    captured = 0

    async def capture_one(url: str) -> None:
        nonlocal captured
        host = httpx.URL(url).host
        if host in have:
            return
        async with semaphore:
            if captured >= want:
                return
            result = await probe(url, timeout_s=10)
        # Header-only 402s (empty body) are valid v2 — the PAYMENT-REQUIRED
        # header is the canonical wire location; don't bias the corpus.
        has_pr_header = any(k.lower() == "payment-required" for k in result.headers)
        if not (result.ok and result.http_status == 402 and (has_pr_header or result.body)):
            return
        async with lock:
            if captured >= want or host in have:
                return
            have.add(host)
            captured += 1
        golden = {
            "url": result.url,
            "captured_at": datetime.now(UTC).isoformat(timespec="seconds"),
            "http_status": result.http_status,
            "headers": result.headers,
            "body": result.body,
            "body_truncated": result.body_truncated,
        }
        (GOLDEN_DIR / f"{host}.json").write_text(
            json.dumps(golden, indent=2, ensure_ascii=False) + "\n"
        )
        print(f"  captured {host}")

    await asyncio.gather(*(capture_one(u) for u in urls))
    total = len(list(GOLDEN_DIR.glob("*.json")))
    print(f"done: {captured} new, {total} goldens total")


if __name__ == "__main__":
    asyncio.run(main(int(sys.argv[1]) if len(sys.argv) > 1 else 25))
