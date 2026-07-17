"""CLI: python -m preflight402.ingest [--source NAME ...] [--max-records N]

Runs the seed ingesters against the configured database (PREFLIGHT402_DB_PATH
or ./preflight402.db) and prints a per-source summary. Exits non-zero only
when every requested source errored — a partial crawl is a usable crawl.
"""

from __future__ import annotations

import argparse
import asyncio
import sys

from preflight402.config import get_settings
from preflight402.ingest.runner import ALL_SOURCES, run_ingest

_BY_NAME = {module.SOURCE: module for module in ALL_SOURCES}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="preflight402.ingest", description=__doc__)
    parser.add_argument(
        "--source",
        action="append",
        choices=sorted(_BY_NAME),
        help="ingest only this source (repeatable; default: all)",
    )
    parser.add_argument(
        "--max-records",
        type=int,
        default=None,
        metavar="N",
        help="cap records per source (conservative test runs)",
    )
    args = parser.parse_args(argv)
    sources = tuple(_BY_NAME[name] for name in args.source) if args.source else ALL_SOURCES

    report = asyncio.run(run_ingest(get_settings(), sources=sources, max_records=args.max_records))

    for source_report in report.sources:
        line = (
            f"{source_report.source}: fetched={source_report.fetched}"
            f" seeded={source_report.seeded}"
            f" skipped_template={source_report.skipped_template}"
            f" skipped_invalid={source_report.skipped_invalid}"
        )
        if source_report.seeded_fallback:
            line += f" seeded_fallback={source_report.seeded_fallback}"
        if source_report.error:
            line += f" ERROR={source_report.error}"
        print(line)
    print(
        f"endpoints: {report.endpoints_before} -> {report.endpoints_after}"
        f" (+{report.new_endpoints})"
    )
    return 1 if all(r.error is not None for r in report.sources) else 0


if __name__ == "__main__":
    sys.exit(main())
