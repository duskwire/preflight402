# preflight402-guard

**One free check before your agent pays.** The guard validates any x402
payment endpoint — liveness, TLS, 402 handshake compliance, price sanity,
probe history, ERC-8004 identity and Sybil-filtered reputation — against the
free [preflight402](https://preflight402.ironshell.io) service, and blocks
the payment when the verdict says to walk away.

Real numbers from the service this guard calls: one popular agent shows a
**99.8/100 average from 996 reviewers — until Sybil filtering collapses them
to 12 independent funding clusters at 89.7**. That's the difference between
raw reputation and what this guard checks.

## Install

```sh
pip install preflight402-guard          # explicit checks + CLI
pip install "preflight402-guard[x402]"  # + automatic x402 SDK integration
```

## Guard every payment automatically (x402 SDK)

```python
from preflight402_guard import Guard
from x402 import x402Client

guard = Guard()          # block "avoid" verdicts, warn on "caution"
client = x402Client()
guard.install(client)    # every payment is preflighted before signing;
                         # a blocked verdict raises PaymentAbortedError
```

Works with every x402 transport (httpx wrapper, requests, manual
`create_payment_payload`) because it hooks the client itself.

## Explicit checks

```python
from preflight402_guard import Guard, PaymentBlocked

guard = Guard(max_price_usd=0.10, min_filtered_score=50)
await guard.assert_allowed("https://api.example.com/data")  # raises PaymentBlocked
decision = guard.check_sync("https://api.example.com/data")  # sync, non-raising
print(decision.action, decision.recommendation, decision.reasons)
```

## CLI (humans and CI)

```sh
preflight402-guard check https://api.example.com/data
preflight402-guard check URL --block-caution --max-price-usd 0.05 --json
# exit codes: 0 allowed, 1 allowed-with-warnings, 2 blocked, 3 no verdict
```

## Policy knobs

| Option | Default | Meaning |
|---|---|---|
| `block` | `("avoid",)` | verdict recommendations that block payment |
| `warn` | `("caution",)` | recommendations that allow with a warning |
| `max_price_usd` | off | ceiling on the price actually being signed (checked against your client's selected terms, not just what the scanner saw) |
| `require_bound_identity` | off | block payees with no ERC-8004 identity |
| `min_filtered_score` | off | floor on Sybil-filtered reputation, when available |
| `fail_open` | `True` | service unreachable → allow with warning (set `False` to block) |
| `cache_ttl_s` | 60 | per-URL decision cache for hot loops |

**Fail-open by design:** your commerce must not depend on our uptime. Strict
environments set `fail_open=False`.

Self-hosting the service? Point `Guard(service_url=...)` at your own
[preflight402](https://github.com/duskwire/preflight402) instance.

MIT. Part of [preflight402](https://github.com/duskwire/preflight402).
