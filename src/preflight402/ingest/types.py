"""Shared shapes for the seed ingesters.

Each source module (bazaar, agentic_market, x402_list) exposes
`SOURCE: str` and `records(client, *, max_records=None)` — an async
generator of SeedRecord, one per candidate endpoint URL, already filtered
down to things that claim to be probe-able HTTP endpoints. All shared
policy (route-template skipping, URL canonicalization, upserts, counting)
lives in runner.run_ingest so every source is treated identically.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class SeedRecord:
    """One candidate endpoint from a registry."""

    url: str
    source: str
    meta: dict[str, Any] | None = None  # small source-specific extras


@dataclass(slots=True)
class SourceReport:
    """What one source contributed to an ingest run.

    `error` is set when the source aborted mid-stream (network failure,
    malformed page); counts then cover everything ingested before the abort,
    so a partial crawl is still recorded honestly.
    """

    source: str
    fetched: int = 0  # records the source yielded
    seeded: int = 0  # records upserted into endpoints
    seeded_fallback: int = 0  # seeded via a degraded path (e.g. detail fetch failed)
    skipped_template: int = 0  # /:param or /{param} route templates
    skipped_invalid: int = 0  # canonicalize_url rejected the URL
    error: str | None = None


@dataclass(slots=True)
class IngestReport:
    sources: list[SourceReport] = field(default_factory=list)
    endpoints_before: int = 0
    endpoints_after: int = 0

    @property
    def new_endpoints(self) -> int:
        return self.endpoints_after - self.endpoints_before
