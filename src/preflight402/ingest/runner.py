"""Ingest driver: pull every source, dedupe, upsert into endpoints.

Shared policy lives here so all sources are treated identically:
- URLs that fail canonicalization are skipped per-record, never aborting
  the batch (registries contain junk);
- /:param and /{param} route templates are skipped (not probe-able as-is),
  judged on the canonical PATH only — a '/:' inside a query string is not
  a template;
- meta is namespaced per source ({"bazaar": {...}, "x402-list": {...}}) and
  merged inside the upsert transaction (queries.upsert_endpoint source_meta),
  so concurrent ingesters can't lose each other's namespace;
- a source that dies mid-crawl is recorded in its report and the remaining
  sources still run. The guard is a blanket `except Exception`: registry
  output is untrusted, so ANY failure shape (junk JSON raising
  AttributeError included) must isolate to its source. CancelledError is a
  BaseException and still propagates.

SSRF policy: seeding accepts any canonicalizable http(s) URL; the guard
runs at probe time (service.py and the M3 scheduler), which is the only
enforcement point that survives DNS changes.
"""

from __future__ import annotations

import re
import sqlite3
from types import ModuleType
from urllib.parse import urlsplit

import httpx

from preflight402.config import Settings
from preflight402.db import connect, migrate, queries
from preflight402.ingest import agentic_market, bazaar, x402_list
from preflight402.ingest.types import IngestReport, SeedRecord, SourceReport

# Same shapes scripts/validate_against_reality.py skips: /:param and /{param}.
TEMPLATE_SEGMENT = re.compile(r"/:[^/]+|/\{[^}]+\}")

USER_AGENT = "preflight402-ingest/0.1 (+https://github.com/duskwire/preflight402)"

ALL_SOURCES: tuple[ModuleType, ...] = (bazaar, agentic_market, x402_list)


async def run_ingest(
    settings: Settings,
    *,
    sources: tuple[ModuleType, ...] = ALL_SOURCES,
    client: httpx.AsyncClient | None = None,
    max_records: int | None = None,
) -> IngestReport:
    """Crawl the given sources and upsert their endpoints; return the report.

    `max_records` caps each source individually (conservative test runs).
    A caller-supplied client is left open; an internally created one is closed.
    """
    own_client = client is None
    if client is None:
        client = httpx.AsyncClient(
            timeout=30, headers={"User-Agent": USER_AGENT}, follow_redirects=False
        )
    conn = connect(settings.db_path)
    report = IngestReport()
    try:
        migrate(conn)
        report.endpoints_before = _endpoint_count(conn)
        for module in sources:
            source_report = SourceReport(source=module.SOURCE)
            report.sources.append(source_report)
            try:
                async for record in module.records(client, max_records=max_records):
                    source_report.fetched += 1
                    _ingest_record(conn, record, source_report)
            except Exception as exc:  # blanket by design — see module docstring
                source_report.error = f"{type(exc).__name__}: {exc}"
        report.endpoints_after = _endpoint_count(conn)
        return report
    finally:
        conn.close()
        if own_client:
            await client.aclose()


def _ingest_record(
    conn: sqlite3.Connection, record: SeedRecord, source_report: SourceReport
) -> None:
    try:
        canonical = queries.canonicalize_url(record.url)
    except ValueError:
        # InvalidURLError, or any bare ValueError a hostile URL squeezes out
        # of urllib despite canonicalize_url's wrapping — same outcome.
        source_report.skipped_invalid += 1
        return
    if TEMPLATE_SEGMENT.search(urlsplit(canonical).path):
        source_report.skipped_template += 1
        return
    queries.upsert_endpoint(conn, canonical, source=record.source, source_meta=record.meta or None)
    source_report.seeded += 1
    if record.meta and record.meta.get("detail_fallback"):
        source_report.seeded_fallback += 1


def _endpoint_count(conn: sqlite3.Connection) -> int:
    return conn.execute("SELECT COUNT(*) FROM endpoints").fetchone()[0]
