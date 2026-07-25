"""CLI: validate an x402 payment endpoint before a person (or CI) pays, and
optionally report how a payment turned out.

    preflight402-guard check https://api.example.com/data
    preflight402-guard check URL --block-caution --max-price-usd 0.05 --json
    preflight402-guard report URL --delivered            # contribute an outcome
    preflight402-guard report URL --failed --tx 0xabc…   # verified-tier report

`check` exit codes: 0 = allowed, 1 = allowed with warnings, 2 = blocked,
3 = no verdict (service unreachable; fail-open would allow).
`report` exit codes: 0 = recorded, 4 = not recorded (service unreachable/rejected).
"""

from __future__ import annotations

import argparse
import json
import sys

from preflight402_guard.guard import DEFAULT_SERVICE_URL, Guard


def _run_check(args: argparse.Namespace) -> None:
    guard = Guard(
        args.service,
        block=("avoid", "caution") if args.block_caution else ("avoid",),
        warn=() if args.block_caution else ("caution",),
        max_price_usd=args.max_price_usd,
        require_bound_identity=args.require_bound_identity,
        min_filtered_score=args.min_filtered_score,
        timeout_s=args.timeout,
        cache_ttl_s=0,
        report_outcomes=False,  # `check` never emits telemetry
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

    # A hard block (e.g. the service REFUSED the URL as invalid/SSRF) is exit 2
    # even though it carries no verdict — check allowed before no-verdict.
    if not decision.allowed:
        raise SystemExit(2)
    if decision.recommendation is None:
        raise SystemExit(3)
    raise SystemExit(1 if decision.action == "warn" else 0)


def _run_report(args: argparse.Namespace) -> None:
    if args.delivered == args.failed:
        raise SystemExit("specify exactly one of --delivered / --failed")
    guard = Guard(args.service, report_outcomes=True, cache_ttl_s=0)
    if not guard.reporting_enabled:
        raise SystemExit("telemetry is disabled (PREFLIGHT402_GUARD_NO_TELEMETRY); nothing sent")
    sent = guard.report(
        args.url,
        delivered=args.delivered,
        tx_hash=args.tx,
        outcome=None if args.delivered else "reported_failure",
        blocking=True,  # inline send; a daemon thread would die at exit
    )
    tier = "verified" if args.tx else "anonymous"
    status = "delivered" if args.delivered else "failed"
    if sent:
        print(f"reported ({tier}): {args.url} -> {status}")
        return
    # exit 4 = the contribution was NOT recorded (service down / rejected)
    print(
        f"delivery report NOT recorded for {args.url} (service unreachable or rejected)",
        file=sys.stderr,
    )
    raise SystemExit(4)


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
    check.set_defaults(func=_run_check)

    report = sub.add_parser("report", help="contribute a delivery outcome for an endpoint")
    report.add_argument("url", help="the x402 endpoint you paid")
    report.add_argument("--service", default=DEFAULT_SERVICE_URL, help="preflight402 service URL")
    report.add_argument("--delivered", action="store_true", help="the paid request succeeded")
    report.add_argument("--failed", action="store_true", help="you paid but got no/bad service")
    report.add_argument(
        "--tx", default=None, help="settlement tx hash (makes it a verified-tier report)"
    )
    report.set_defaults(func=_run_report)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
