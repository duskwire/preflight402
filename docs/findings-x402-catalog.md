# What 7.8 million probes say about the x402 economy

*Published 2026-08-04. Data snapshot 2026-08-04T22:01Z. Method, caveats and
raw figures: [checkpoint-m3.md](checkpoint-m3.md). Reproduce:
[`scripts/checkpoint_report.py`](../scripts/checkpoint_report.py).*

We ran a continuous prober against every x402 endpoint we could find — the
union of three registries, 51,331 listed endpoints across 1,985 hosts — for 15
days from a clean egress IP. 7,762,432 probes. Here is what we found, including
the part where our own measurement was wrong.

## 1. 58% of the "x402 economy" is two squatting hosts

| Host | Listed endpoints | What it returns, every time |
|---|---|---|
| orbisapi.com | 19,295 (37.6% of catalog) | HTTP 404 — a hosting placeholder titled *"This app isn't live yet"* |
| lowpaymentfee.com | 10,633 (20.7%) | HTTP 525 — Cloudflare edge-to-origin TLS handshake failure |

Together **29,928 endpoints, 58.3% of every listed x402 endpoint**, and neither
has served a single valid 402 challenge in 15 days of probing. One is an
undeployed app; the other has a broken TLS origin.

These are **two broken servers, not 29,928 findings**. The median host in the
catalog lists two endpoints. Any statistic that counts listings will be
dominated by whoever bulk-registered the most URLs.

**If you are sizing this market from registry counts, halve your number and
then look at the host distribution.**

## 2. Probing method changes the answer more than the ecosystem does

Our prober issued a GET, and retried with POST only when the GET returned
exactly `405 Method Not Allowed`. That seemed reasonable. It was wrong: most
x402 endpoints are **POST** endpoints, and they answer a stray GET with 404,
200, or 401 — none of which triggered the retry.

We re-probed stratified samples with POST, validating every response through
our own x402 parser:

| What a GET returned | Share that serve a valid 402 on POST |
|---|---|
| 404 | 55% |
| 200 | 78% |
| 401 / 403 | 63% |
| 405, 5xx | 0% — correctly classified |

After fixing the prober and re-probing the full catalog, **2,007 endpoints and
205 hosts moved from "broken" to "works"**:

| | GET-only | GET + POST retry |
|---|---|---|
| Serving a valid 402 | 16,671 (77.9%) | **18,678 (87.3%)** |
| Answered but never a 402 | 4,483 (20.9%) | **2,353 (11.0%)** |
| Hosts serving ≥1 valid 402 | 1,502 (75.7%) | **1,707 (86.1%)** |

Of the endpoints that served a 402 via the POST retry, **1,786 had never served
one in the entire pre-fix window.** They were live payment endpoints the whole
time.

**The implication generalizes.** A GET-only crawl overstates x402 invalidity by
roughly 2×. Most published "% of x402 endpoints are dead" figures — ours before
this fix, and, as far as we can tell from their descriptions, others' — are
measuring their own prober at least as much as the ecosystem. If you cite one,
ask what HTTP method it used.

## 3. So how much is actually broken? Pick your unit and say which

The same corrected dataset supports three defensible numbers that differ by 5×:

| Unit of analysis | Not usable |
|---|---|
| **Providers (hosts)** | **13.9%** — 276 of 1,985 |
| Endpoints we measured individually | 12.7% — 2,725 of 21,403 |
| Registry *listings* | 63.6% |

The listing-weighted figure is the most quotable and the least meaningful:
**86% of it is those two squatting hosts.** The honest headline is the
provider-weighted one — **roughly one x402 provider in seven serves no valid
402** — which is a real reliability problem and an order of magnitude smaller
than the listing figure implies.

## What we'd want a reader to take away

1. **Registry listing counts are a poor proxy for the size of the x402
   economy.** Two servers are 58% of the catalog.
2. **Liveness statistics describe the prober as much as the ecosystem.**
   Switching one HTTP method moved more endpoints than any real-world change
   over the same period.
3. **The working ecosystem is healthier than the headline suggests** — 87% of
   real endpoints serve a valid 402 — **and smaller.**

## Limits of this data, stated plainly

- **Scope is registry listings** — agentic.market (96.8% of the catalog),
  Coinbase Bazaar, x402-list. Not the protocol, not its traffic, not what
  agents actually call. Nothing is usage-weighted: a listing nobody has ever
  called counts the same as a high-traffic commercial endpoint.
- **"Valid 402" means advertised payability, not delivery.** We never paid. An
  endpoint that returns a well-formed challenge and then delivers nothing
  counts as working here.
- **15.0% of the catalog was never probed** (7,723 endpoints, all on
  orbisapi.com) and is counted unusable by host-level inference from 11,572
  probed siblings that were uniformly 404. Measurement-only bounds are given in
  the [full report](checkpoint-m3.md).
- **Every endpoint on the two dominant hosts was probed at most twice, ever.**
  The host-level conclusion is strong; the per-endpoint one is not.
- **This is a snapshot** of a database that grew ~566k probes/day. Re-running
  gives different numbers; the as-of timestamp is at the top.
- **We are not treating any third-party figure as corroboration.** A widely
  cited July 2026 report puts x402 endpoints at 68% dead-or-invalid; it covers
  a ~2,160-endpoint catalog that almost certainly excludes both squatting
  hosts, and our comparable non-farm rate is 12.7%. Where methods and catalogs
  differ this much, agreement would be coincidence and disagreement is not
  evidence of error on either side.

## Reproducing

The prober, the report generator, and the full methodology are MIT-licensed at
[github.com/duskwire/preflight402](https://github.com/duskwire/preflight402).

```sh
PREFLIGHT402_DB_PATH=/path/to/preflight402.db \
    python scripts/checkpoint_report.py --json
```

The script prints its own caveats alongside its numbers, including the sampling
blind spot that made our first cut of these figures wrong by 3× — per-host
politeness spreads a mega-host's probes so thin that its endpoints never
accumulate enough observations to enter a rollup sample, so the naive query
silently omits exactly the hosts that dominate the catalog.
