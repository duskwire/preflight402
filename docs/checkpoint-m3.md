# M3 acceptance: continuous-probing checkpoint

**Snapshot: 2026-08-04T22:01Z — re-measured after the GET-only fix
(commit abd767a).** Reproduce with `scripts/checkpoint_report.py` (see
[Reproducing](#reproducing) for why the published figures come from raw probes,
not that script's rollup shortcut). The superseded pre-fix figures are kept
inline for traceability, marked *(pre-fix)*.

## Acceptance: MET

The build plan's M3 criterion was *7 days of continuous probing over 1,000+
endpoints*. Actual:

| | |
|---|---|
| Observation window | 2026-07-20T22:38Z → 2026-08-04T22:01Z (**15.0 days**, uninterrupted) |
| Probes recorded | **7,762,432** (~566k/day pre-fix; the POST retry adds a second request on non-402 endpoints) |
| Distinct endpoints probed (rolling 7d) | **36,520** (38,836 pre-fix — the retry costs throughput) |
| Catalog under management | 51,331 listed endpoints across 1,985 hosts |
| Infrastructure | Hetzner VPS, clean DE egress, uncapped scheduler since 2026-07-21 |

Exceeded on both axes (9.24 days vs 7; 38.8k endpoints vs 1,000). One
interruption in the whole run — `unattended-upgrades` restarted services on
07-21 and our graceful shutdown stalled past systemd's 90s window, so the unit
was SIGKILLed and auto-restarted 3s later with no data loss (WAL + per-probe
commits). Mitigated by `TimeoutStopSec=15` (commit 6169fed).

## What the data says about catalog health

**Do not quote a single headline number without its unit.** The same dataset
yields three legitimate figures that differ by 6×, because the catalog is
extraordinarily concentrated:

| Unit of analysis | Not usable (measured) | pre-fix estimate |
|---|---|---|
| **Providers (hosts)** — the honest default | **13.9%** (276 of 1,983 hosts) | 14.2% [12.4–15.8] |
| Measured endpoints (individually probed) | 12.7% (2,725 of 21,403) | 10.5% [7.8–13.3] |
| Registry *listings* (endpoint rows) | 63.6% | 62.7% [61.5–63.8] |

These are now **measured** with the fixed prober, not extrapolated: every one
of the 21,403 endpoints has been re-probed with the POST retry. Both
method-corrected estimates landed inside or beside their measured values (the
provider figure within 0.3pp), which is a good sign for the correction
methodology. The listing-weighted figure remains the most quotable and the
least meaningful: **86% of it is two hostnames.**

### Two squatting hosts are 58% of the "x402 economy"

| Host | Listed endpoints | Behaviour on every probe |
|---|---|---|
| orbisapi.com | 19,295 (37.6% of catalog) | HTTP 404, hosting placeholder titled *"This app isn't live yet"* |
| lowpaymentfee.com | 10,633 (20.7%) | HTTP 525 — Cloudflare edge-to-origin TLS handshake failure |

Together **29,928 endpoints (58.3%)**, and neither has served a single valid
402 in the entire window. These are two broken servers, not 29,928 independent
findings. The median host in the catalog lists **2** endpoints.

**The defensible framing:** *two squatting hosts account for 58% of the x402
catalog; strip them out and 78% of real endpoints work.* Registry listing
counts are a poor proxy for the size of the x402 economy.

### The real ecosystem, measured (21,403 endpoints, 1,983 hosts)

| | endpoints | share | *(pre-fix)* |
|---|---|---|---|
| Serving a valid 402 | **18,678** | **87.3%** | *16,671 / 77.9%* |
| Zombie — answered, never a valid 402 | **2,353** | **11.0%** | *4,483 / 20.9%* |
| Dead — never answered | 372 | 1.7% | *249 / 1.2%* |
| Hosts serving ≥1 valid 402 | **1,707** of 1,983 | **86.1%** | *1,502 / 75.7%* |

**The fix moved 2,007 endpoints and 205 hosts from "broken" to "works".** The
zombie population fell 47% (4,483 → 2,353) — close to the 55% the correction
predicted, and lower than the 81% recovery seen in the stratified live sample,
which is expected: that sample was weighted toward the recoverable buckets.

Dead rose slightly (249 → 372): partly real churn over a 15-day window, partly
that the retry halves per-endpoint probe throughput, so a transient failure has
fewer successes to offset it. Zero `blocked` (SSRF-refused) rows in the window.

## The GET-only correction

**Our prober's method inflated the invalidity rate ~2.1×, and this is a
product bug, not just a reporting one.** `probe()` issues a GET and retries
with POST *only when the GET returns exactly 405* (`probe/prober.py`), with
redirects not followed by design. But most x402 endpoints are POST endpoints
that answer a GET with 404, 200, or 401 — none of which trigger the fallback.

Re-probing stratified samples with POST and with redirects followed, and
validating every response through our own `detect()` parser:

| Recorded behaviour | Serve a valid 402 on POST/redirect |
|---|---|
| 404-only | 33/60 = **55.0%** [42.5–66.9] |
| 200-only | 31/40 = **77.5%** [62.5–87.7] |
| 401/403-only | 19/30 = **63.3%** [45.5–78.1] |
| 3xx-only (following the redirect) | 12/30 = **40.0%** [24.6–57.7] |
| 405-only, 5xx-only | 0/19, 0/20 — correctly classified |

Population-weighted: **2,489 of 4,483 "zombies" (55.5%, CI 42.2–68.4%) do
serve a valid x402 challenge.** This is not temporal drift — live GET re-probes
reproduced the recorded status exactly in every bucket; only the HTTP method
changed. Corrected zombie count ≈ 1,994.

**Consequence beyond this report — the checkpoint's most valuable finding:**
the free preflight was returning `avoid` for a large class of endpoints that
work. **Fixed 2026-08-04 (commit abd767a)**; the tables above are re-measured
with the fixed prober. Post-deploy verification on the live VPS: of the 2,840
endpoints that served a 402 via the POST retry in the first hours,
**1,786 had never served a 402 in the entire pre-fix window** — those are
verdicts that were simply wrong, now right.

Two criticals were caught by adversarial review before this shipped: the broad
retry set had to be **gated on registry-catalog membership** (applying it to
arbitrary caller-supplied URLs would have turned the free `/preflight` into an
attacker-directed POST relay), and a **429 answering the retry** had to trigger
host backoff instead of being discarded and *resetting* it.

## Caveats any publication must carry

1. **Unit of analysis, in the headline sentence.** 86% of the unusable
   listings (29,928 of 34,660) are two hosts, each failing identically across
   every listing. Per provider, 14.2% of 1,985 hosts serve no valid 402.
2. **Method limitation** (above): any x402 liveness figure from GET-only
   probing — ours before the 2026-08-04 fix, or anyone else's — overstates
   invalidity by roughly 2×. Ours is now measured with the POST retry; most
   published x402 liveness figures are not, and are not comparable to these.
3. **What "not usable" excludes**: endpoints answering POST but not GET;
   endpoints reachable only after a redirect; endpoints needing a real request
   body (400/422 to our empty `{}`); auth-gated endpoints. "Valid 402" means
   HTTP 402 with terms our parser reads as x402 v1/v2 or MPP — **not** that a
   payment would settle. We never paid, so this measures *advertised
   payability*, not delivery.
4. **15.0% of the catalog was never probed.** 7,723 endpoints — all
   orbisapi.com — have zero probes; they are counted unusable by host-level
   *inference*, not measurement. Because the scheduler rotates by
   last-probe-time then row id, the unprobed remainder is a contiguous
   ingest-order block (alphabetically later slugs), not a random sample. A
   live spot-check of 14 never-probed endpoints returned 404 on GET,
   GET-with-redirects and POST, 14/14. Measurement-only bounds: 57.1%
   (probed in 7d) / 61.7% (ever probed).
5. **Thin per-endpoint evidence on the farms.** Every farm endpoint was probed
   at most twice, ever (orbisapi: exactly once, for 11,573 of them). The
   host-level conclusion is very strong; the per-endpoint one is not — our own
   verdict engine grades a single probe "low confidence".
6. **Both directions of error.** The "valid" bucket is generous too: 1,954 of
   16,671 (11.7%) served a 402 on fewer than all probes, 262 on under half.
   Under the stricter *spec-compliant* reading only 15,474 qualify, which
   would move the listing-weighted figure to 69.9%.
7. **Population/selection bias.** The catalog is the union of three registries
   — agentic.market (49,672 listings, 96.8%), Coinbase Bazaar (24,355),
   x402-list (1,527). This describes *what those registries list*, dominated
   by one, not the protocol, its traffic, or endpoints agents actually call.
   Nothing is usage-weighted. 175 listings are percent-encoded URL templates
   (e.g. `/projects/%7Bid%7D/renders`) that were never resolvable.
8. **Snapshot, not a constant.** The DB grows ~566k probes/day; figures move
   on re-run. Always publish the as-of timestamp.
9. **PulseFeed is NOT corroboration.** Their July 2026 "68% dead or invalid"
   covers a ~2,160-endpoint catalog (CDP Bazaar + 402index) that almost
   certainly excludes both farms; our comparable non-farm rate is 12.7%
   measured, which *contradicts* 68%. And if they also probe GET-only,
   agreement would be shared-method bias, not convergent validity. The
   67.5%-vs-68% coincidence across incompatible denominators is meaningless.

## What survives scrutiny

Two claims, both defensible:

1. **Registry listing counts are a poor proxy for the x402 economy's size.**
   58.3% of listed endpoints are two servers — one undeployed, one with a
   broken TLS origin — and the median host lists two endpoints.
2. **Among providers we can measure individually, roughly one in seven serves
   no valid 402** (13.9%, measured). A real reliability problem, an order of
   magnitude smaller than the listing-weighted figure suggests.
3. **Probing method dominates the answer.** Switching from GET-only to a
   GET-plus-POST probe moved 2,007 endpoints and 205 hosts from "broken" to
   "works" — a larger effect than any real-world change over the same period.
   Liveness statistics about x402 are statements about the prober as much as
   the ecosystem.

## Follow-ups this checkpoint opened

- **[product bug] Broaden the POST fallback — ✅ FIXED 2026-08-04 (commit
  abd767a), live on both hosts.** The retry now fires on a configurable status
  set (200/400/401/403/404/405/415/422); 5xx and 3xx stay excluded. Live
  re-probing of 47 endpoints classified "zombie" recovered **38 (80.9%)** —
  higher than the 55% estimate above — and in the first minute after deploy the
  VPS recorded **431 endpoints returning a valid 402 via POST** that GET-only
  probing had written off. Two criticals were caught by adversarial review
  before shipping: the broad set is **gated on registry-catalog membership**
  (applying it to arbitrary caller-supplied URLs would have made the free
  `/preflight` an attacker-directed POST relay; unlisted URLs get `{405}`), and
  a **429 answering the retry now triggers host backoff** instead of being
  discarded and *resetting* it. `probes.method` + `probes.retry_status`
  (migration 0005) make the retry auditable.
  **⚠️ The numbers in this report predate the fix and understate liveness.**
- **[product bug] Follow redirects (or record the target).** 40% of 3xx-only
  endpoints serve a 402 at the redirect target. Still open — needs revalidation
  of the redirect target against the SSRF guard, so it is not a one-liner.
- **[ops] Migrations cost a whole-database scan.** Deploying 0003+0004+0005 to
  the 7.9GB VPS DB took ~9 minutes of downtime: `migrate()` runs
  `PRAGMA foreign_key_check` over the entire database before every COMMIT, even
  for a pure `ADD COLUMN`. Logged as a follow-up task.
- **[minor] Ingest filter misses percent-encoded templates.**
  `TEMPLATE_SEGMENT` matches `/:param` and `/{param}` but not `/%7Bid%7D`
  (175 listings).
- **[hygiene] Taxonomy drift.** Three different definitions of zombie/downtime
  exist across `rollups.py`, `stats.py`, and this report; 5xx-only endpoints
  are "downtime" in one and "answers, never 402" in another.
- **[hygiene] Rollups are not a calendar window.** A 7d rollup is recomputed
  only when its endpoint is next probed, so the table mixes windows up to 9
  days apart. Published figures must come from raw probes.

## Reproducing

`scripts/checkpoint_report.py` regenerates the structure of this report from
any prober DB and prints its own caveats. It reads the `rollups` table for
speed, which is why the figures above were **re-derived from raw probes** by
two independent verification passes — the rollup shortcut agrees here, but it
is not a consistent calendar window and should not be the published source.

```sh
PREFLIGHT402_DB_PATH=/var/lib/preflight402/preflight402.db \
    python scripts/checkpoint_report.py --json
```

Verification: both the arithmetic and the partition were independently
reconfirmed (the 21,403 non-farm / 29,928 farm split is set-equal at ID level —
no overlap, no double-count, no remainder), and the method correction above
came from an adversarial review that re-probed live samples. The uncorrected
"67.5% of listings" figure this report supersedes was arithmetically right and
substantively misleading; it is recorded here only so the correction is
traceable.
