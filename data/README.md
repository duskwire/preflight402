# Dataset behind the published findings

Per-host aggregates from the continuous-probing run that produced
[`docs/findings-x402-catalog.md`](../docs/findings-x402-catalog.md) and
[`docs/checkpoint-m3.md`](../docs/checkpoint-m3.md). Archived when the prober
was retired, so the published numbers stay checkable after the infrastructure
is gone.

## Files

**`x402-catalog-hosts-2026-08-04.csv`** — one row per host (1,985 rows):

| column | meaning |
|---|---|
| `host` | the hostname |
| `listed_endpoints` | endpoints this host has in the catalog (union of three registries) |
| `classified` | endpoints with enough probe history in the 7-day window to classify |
| `serving_402` | classified endpoints observed serving a valid 402 challenge |
| `zombie` | answered every probe, never with a valid 402 |
| `dead` | never answered |

**`x402-catalog-meta-2026-08-04.json`** — snapshot timestamp, observation
window, total probes, catalog size.

## Reading it honestly

- **The two dominant hosts are measured directly, not classified.**
  `orbisapi.com` (19,295 listed) and `lowpaymentfee.com` (10,633) have
  `classified = 0`: per-host politeness spreads their probes so thin that no
  individual endpoint accumulates enough observations to enter the rollup
  sample. Their `zombie` column instead carries the count of endpoints probed
  directly across the whole window, all of which returned a uniform 404 and 525
  respectively and never a 402. Summing `classified` will not equal
  `listed_endpoints`; that gap is the point, and the findings post explains it.
- **This snapshot (2026-08-04T23:04Z) is ~1 hour later than the figures in the
  findings post** (22:01Z), so `serving_402` totals 18,860 here versus 18,678
  there. The prober was still running. Both are correct as of their timestamps.
- **Post-fix data.** These counts come from the corrected prober (GET plus a
  POST retry). Figures derived from GET-only probing understate liveness by
  roughly 2×.
- **Scope:** what three registries listed, not the x402 protocol, its traffic,
  or endpoints agents actually called. Nothing is usage-weighted.
- **"Serving a valid 402" means advertised payability, not delivery.** No
  payment was ever made.

Raw probe rows (7.78M) are not archived — they lived on the prober VM, which
was retired. `scripts/checkpoint_report.py` regenerates this shape from any
preflight402 database.
