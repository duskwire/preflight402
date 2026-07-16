"""Validation sweep: run the full preflight pipeline over a live Bazaar sample.

Not a scheduler and not the deployed service — this runs the real
probe -> detect -> evaluate pipeline in-process against real endpoints, to
answer "does it actually work against reality" before we build M3 or expose
the service more widely. Run from a throwaway IP (not the home LXC).

    uv run python scripts/validate_against_reality.py [N_HOSTS]

Writes a JSON report + saves any 402 that classified as protocol=none
(parser gaps) to scripts/validation-anomalies/ for follow-up golden capture.
"""

import asyncio
import json
import re
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

import httpx

from preflight402.probe.parsers import detect
from preflight402.probe.prober import probe
from preflight402.verdict.rules import evaluate

BAZAAR = "https://api.cdp.coinbase.com/platform/v2/x402/discovery/resources"
OUT_DIR = Path(__file__).parent / "validation-anomalies"
TEMPLATE_SEGMENT = re.compile(r"/:[^/]+|/\{[^}]+\}")


async def candidate_urls(target_hosts: int) -> tuple[list[str], int, int]:
    """One directly-probeable URL per host; also count total + templates skipped."""
    urls: dict[str, str] = {}
    templates_skipped = 0
    async with httpx.AsyncClient(timeout=30) as client:
        offset = 0
        total = 0
        while len(urls) < target_hosts:
            resp = await client.get(BAZAAR, params={"limit": 100, "offset": offset})
            resp.raise_for_status()
            data = resp.json()
            total = data.get("pagination", {}).get("total", 0)
            items = data.get("items", [])
            if not items:
                break
            for item in items:
                url = item.get("resource", "")
                if item.get("type") != "http" or not url.startswith("http"):
                    continue
                if TEMPLATE_SEGMENT.search(url):
                    templates_skipped += 1
                    continue
                try:
                    host = httpx.URL(url).host
                except httpx.InvalidURL:
                    continue
                urls.setdefault(host, url)
            offset += 100
            if offset >= total:
                break
    return list(urls.values())[:target_hosts], total, templates_skipped


async def run(want: int) -> None:
    OUT_DIR.mkdir(exist_ok=True)
    urls, catalog_total, templates_skipped = await candidate_urls(want)
    print(f"catalog total: {catalog_total} | templates skipped: {templates_skipped}")
    print(f"probing {len(urls)} unique hosts (egress = this box, not the home LXC)...")

    reach = Counter()
    http_status = Counter()
    protocol = Counter()
    compliant = Counter()
    warnings_top = Counter()
    verdicts = Counter()
    confidence = Counter()
    priceable = Counter()
    prices: list[float] = []
    crashes: list[dict] = []
    unclassified_402: list[dict] = []
    done = 0

    semaphore = asyncio.Semaphore(12)

    async def one(url: str) -> None:
        nonlocal done
        async with semaphore:
            try:
                result = await probe(url, timeout_s=12)
                detection = detect(result.headers, result.body)
                # single-probe verdict (no history) — the free-tier case
                verdict = evaluate(result, detection, history=None)
            except Exception as exc:  # the pipeline promises never to raise
                crashes.append({"url": url, "error": f"{type(exc).__name__}: {exc}"})
                return
        done += 1
        reach["ok" if result.ok else f"err:{result.error}"] += 1
        if result.http_status is not None:
            http_status[result.http_status] += 1
        protocol[detection.protocol] += 1
        if detection.spec_compliant is not None:
            compliant[detection.spec_compliant] += 1
        for w in detection.warnings:
            warnings_top[re.sub(r"\d+", "N", w)[:70]] += 1
        verdicts[verdict.recommendation] += 1
        confidence[verdict.confidence] += 1
        priceable["yes" if verdict.price_usd is not None else "no"] += 1
        if verdict.price_usd is not None:
            prices.append(verdict.price_usd)
        # a 402 that we couldn't classify is a parser gap worth capturing
        if result.ok and result.http_status == 402 and detection.protocol == "none":
            host = httpx.URL(url).host
            unclassified_402.append({"url": url, "host": host})
            (OUT_DIR / f"{host}.json").write_text(
                json.dumps(
                    {"url": url, "headers": result.headers, "body": result.body}, indent=2
                )
            )

    await asyncio.gather(*(one(u) for u in urls))

    def top(counter: Counter, n: int = 12) -> dict:
        return dict(counter.most_common(n))

    prices.sort()
    report = {
        "ran_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "catalog_total": catalog_total,
        "templates_skipped": templates_skipped,
        "hosts_probed": len(urls),
        "pipeline_crashes": crashes,  # MUST be empty (never-raises contract)
        "reachability": top(reach),
        "dead_pct": round(100 * sum(v for k, v in reach.items() if k != "ok") / max(done, 1), 1),
        "http_status": top(http_status),
        "protocol": dict(protocol),
        "is_payment_endpoint_pct": round(
            100 * sum(v for k, v in protocol.items() if k != "none") / max(done, 1), 1
        ),
        "spec_compliant": dict(compliant),
        "verdicts": dict(verdicts),
        "confidence": dict(confidence),
        "priceable": dict(priceable),
        "price_usd": {
            "n": len(prices),
            "min": prices[0] if prices else None,
            "median": prices[len(prices) // 2] if prices else None,
            "max": prices[-1] if prices else None,
        },
        "top_warnings": top(warnings_top),
        "unclassified_402_count": len(unclassified_402),
        "unclassified_402_hosts": [u["host"] for u in unclassified_402],
    }
    out = Path(__file__).parent / "validation-report.json"
    out.write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))
    print(f"\nreport -> {out}")
    print(f"crashes: {len(crashes)} (must be 0)  |  unclassified 402s: {len(unclassified_402)}")


if __name__ == "__main__":
    asyncio.run(run(int(sys.argv[1]) if len(sys.argv) > 1 else 250))
