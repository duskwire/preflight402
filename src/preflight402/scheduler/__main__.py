"""CLI: python -m preflight402.scheduler [--once] [--max-endpoints N]

Explicit invocation always runs regardless of PREFLIGHT402_SCHEDULER_ENABLED
(that flag gates only the in-app background loop). --once runs a single
cycle and prints its stats — the conservative-home-test mode; without it the
loop runs until interrupted.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import logging
import signal
import sys

from preflight402.config import get_settings
from preflight402.scheduler.loop import Scheduler, run_scheduler


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="preflight402.scheduler", description=__doc__)
    parser.add_argument("--once", action="store_true", help="run one cycle and exit")
    parser.add_argument(
        "--max-endpoints",
        type=int,
        default=None,
        metavar="N",
        help="cap endpoints probed per cycle (overrides scheduler_max_per_cycle)",
    )
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    settings = get_settings()
    max_endpoints = (
        args.max_endpoints
        if args.max_endpoints is not None
        else (settings.scheduler_max_per_cycle or None)
    )

    if args.once:
        stats = asyncio.run(Scheduler(settings).run_cycle(max_endpoints=max_endpoints))
        print(stats.as_line())
        return 0

    async def forever() -> None:
        stop = asyncio.Event()
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            with contextlib.suppress(NotImplementedError):
                loop.add_signal_handler(sig, stop.set)
        await run_scheduler(settings, stop=stop)

    asyncio.run(forever())
    return 0


if __name__ == "__main__":
    sys.exit(main())
