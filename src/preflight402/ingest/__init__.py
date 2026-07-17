"""Seed ingesters (M3.1): pull endpoint URLs from free x402 registries.

Sources: CDP Bazaar, agentic.market, x402-list. x402scan's ToS prohibits
scraping — its paid API becomes a supplement after M4's payment client.
"""

from preflight402.ingest.runner import ALL_SOURCES, run_ingest
from preflight402.ingest.types import IngestReport, SeedRecord, SourceReport

__all__ = ["ALL_SOURCES", "IngestReport", "SeedRecord", "SourceReport", "run_ingest"]
