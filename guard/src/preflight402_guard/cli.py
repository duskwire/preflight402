"""CLI: validate an x402 payment endpoint before a person (or CI) pays.

    preflight402-guard check https://api.example.com/data
    preflight402-guard check URL --block-caution --max-price-usd 0.05 --json

Exit codes: 0 = allowed, 1 = allowed with warnings, 2 = blocked,
3 = no verdict (service unreachable; fail-open would allow).
"""

from __future__ import annotations

import argparse
import json

from preflight402_guard.guard import DEFAULT_SERVICE_URL, Guard


def main() -> None:
    parser = argparse.ArgumentParser(prog="preflight402-guard", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    check = sub.add_parser("check", help="preflight one endpoint URL and apply policy")
    check.add_argument("url", help="the x402 payment endpoint to validate")
    check.add_argument("--service", default=DEFAULT_SERVICE_URL, help="preflight402 service URL")
    check.add_argument(
        "--block-caution",
        action="store_true",
        help="treat 'caution' as blocking (default: warn only)",
    )
    check.add_argument("--max-price-usd", type=float, default=None)
    check.add_argument(
        "--require-bound-identity",
        action="store_true",
        help="block unless the payee binds to an ERC-8004 identity",
    )
    check.add_argument("--min-filtered-score", type=float, default=None)
    check.add_argument("--timeout", type=float, default=8.0)
    check.add_argument("--json", action="store_true", help="print the full verdict document")
    args = parser.parse_args()

    guard = Guard(
        args.service,
        block=("avoid", "caution") if args.block_caution else ("avoid",),
        warn=() if args.block_caution else ("caution",),
        max_price_usd=args.max_price_usd,
        require_bound_identity=args.require_bound_identity,
        min_filtered_score=args.min_filtered_score,
        timeout_s=args.timeout,
        cache_ttl_s=0,
    )
    decision = guard.check_sync(args.url)

    if args.json and decision.document is not None:
        print(json.dumps(decision.document, indent=2))
    else:
        verdict = decision.recommendation or "unavailable"
        print(f"{decision.action.upper()}  {args.url}")
        print(f"  verdict: {verdict}")
        for reason in decision.reasons:
            print(f"  - {reason}")

    if decision.recommendation is None:
        raise SystemExit(3)
    if not decision.allowed:
        raise SystemExit(2)
    raise SystemExit(1 if decision.action == "warn" else 0)


if __name__ == "__main__":
    main()
