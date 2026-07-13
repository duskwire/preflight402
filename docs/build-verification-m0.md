# M0 build-time verification — 2026-07-13

Four external-world assumptions from the build plan, verified against live
sources (all URLs fetched 2026-07-13). Verdicts: **changed** = plan needs
adjustment; **confirmed** = assumption holds.

## 1. CDP Bazaar discovery API — CHANGED

- **URL**: `https://api.cdp.coinbase.com/platform/v2/x402/discovery/resources`
  — note the `/platform` prefix (our earlier notes omitted it). Also
  `/search` (semantic, limit ≤ 20, no offset) and `/merchant` (lookup by payTo).
- **Auth**: none — read-only catalog, verified with bare curl (HTTP 200).
- **Shape**: `{"x402Version": 2, "items": [...], "pagination": {limit, offset, total}}`.
  Catalog total ≈ 25,764 (live index). Per item: `resource` (may be a route
  template with `:param` segments — **not directly probeable**; substitute
  example `pathParams` from `extensions.bazaar.info.input` or probe host
  root), `type`, `lastUpdated`, `serviceName`, `description`, `tags`,
  `quality` (`l30DaysTotalCalls`, `l30DaysUniquePayers`, `lastCalledAt` —
  free liveness prior for the scheduler), `extensions.bazaar`, and
  `accepts[]` holding price/network/payTo.
- **v2 accepts entry** (real, trimmed): `{"scheme": "exact", "network":
  "eip155:8453", "amount": "10000", "asset": "0x8335...2913", "payTo":
  "0xF990...DcA5", "maxTimeoutSeconds": 300}`. **v2 field is `amount`
  (atomic units), not v1's `maxAmountRequired`.** Networks are CAIP-2.
- **Pagination**: limit default 100 / max 1000, but the server normalizes
  odd values (limit=1 → 20, offsets rounded) — iterate in round multiples
  until `offset >= total`. Catalog cached ~10 min.
- **Listing our endpoint (task 4.4)**: `discoverable: true` is the legacy v1
  flag. Current mechanism: `from x402.extensions.bazaar import
  declare_discovery_extension` on the RouteConfig; the CDP facilitator
  indexes the resource on **first settled payment** carrying
  `paymentPayload.resource`. ⚠️ Open bug x402-foundation/x402#2112: indexing
  after settlement can silently fail — verify catalog appearance, budget
  time to escalate.

## 2. x402scan + other seed sources — CHANGED

- **x402scan**: alive and very active (Merit-Systems/x402scan, last commit
  2026-07-13). **ToS §7 prohibits scraping** ("scrape, harvest, or copy the
  Services"). The sanctioned ingest path is their **x402-paid API**:
  `GET https://www.x402scan.com/api/x402/resources` = $0.01/call
  (page_size ≤ 100, `chain=base|solana`), search $0.02. Full sync of a few
  thousand resources ≪ $1, but requires a funded x402 client — **sequence
  the x402scan ingester after the M4 payment client exists; free sources
  first.** License ambiguity: README claims Apache-2.0 but there is **no
  LICENSE file** — do not vendor their code.
- **agentic.market**: ~1,804 services, free API (`GET /v1/services`,
  `/v1/services/search`) — now the best free bulk seed for task 3.1.
- **x402-list**: alive, 110 services, genuinely free REST API
  (`https://x402-list.com/api/v1/services`, 200 req/min; >2,000 req/day
  metered via x402 at $0.01). Rich health fields per service.
- **awesome-x402**: renamed → `Merit-Systems/awesome-agentic-commerce`
  (old URL 301s). Update task 2.3's PR target.
- Their `docs/DISCOVERY.md` spec (openapi.json `x-payment-info`, then
  `/.well-known/x402`) is relevant to making our own endpoints indexable.

## 3. Alchemy + Helius free tiers — CONFIRMED

- **Alchemy**: 30M CU/month free (as assumed), 500 CU/s ≈ 25 rps, 5 apps.
  `alchemy_getAssetTransfers` = **120 CU** (older sources say 150) →
  ~250k calls/month ceiling on the free tier for M6. Still CU-based
  pricing; PAYG replaced Growth/Scale (2025-02-01) but free tier untouched.
  No credit card needed (high confidence).
- **Helius**: 1M credits/month free, **10 rps**, no card ("No credit cards
  or email required"). Billing doc: standard RPC + archival calls
  (incl. `getSignaturesForAddress`, `getTransaction`) = 1 credit; but the
  pricing page still says archival = 10 credits — **budget at 10/call**
  (worst case still 100k lookups/month). `getTransfersByAddress` **errors
  on the free plan** — do not plan around it. Consider
  `getTransactionsForAddress` (10 credits per 100 txs) instead of
  signature+transaction chains for M6.
- Rate limits to encode in config later: Alchemy ~25 rps, Helius 10 rps.

## 4. x402 Python SDK — CHANGED (favorably)

- **Package**: pip name `x402`, v2.15.0 (released 2026-07-10), Python ≥3.10,
  maintained by the x402 Foundation. **Repo moved**: coinbase/x402 →
  `x402-foundation/x402` (update all references).
- **Seller middleware**: `x402[fastapi]` extra ships FastAPI middleware
  (`x402.http.middleware.fastapi`). v2 API surface: `x402ResourceServer` +
  `HTTPFacilitatorClient` + `ExactEvmServerScheme` — the old
  `require_payment` style is under `python/legacy`. Write M4 against v2.
- **CDP facilitator**: works out of the box —
  `FacilitatorConfig(url="https://api.cdp.coinbase.com/platform/v2/x402")`;
  mainnet settle needs `CDP_API_KEY_ID`/`CDP_API_KEY_SECRET`. Still 1,000
  free settlements/month then $0.001/tx.
- **Protocol headers**: v2 uses `PAYMENT-REQUIRED` / `PAYMENT-SIGNATURE` /
  `PAYMENT-RESPONSE`; v1 used `X-PAYMENT` / `X-PAYMENT-RESPONSE` (legacy).
  The M1.2/1.3 parsers must handle both; the prober already captures all
  headers raw.
- **MCP payments in Python now exist**: `x402[mcp]` extra provides
  `x402.mcp` (payment-gated MCP tools via `create_payment_wrapper` +
  auto-paying client). **The plan's M4.3 mini-research flag is moot** —
  build directly on this.

## Plan deltas applied

- 3.1: Bazaar URL/shape as above; seed order = Bazaar + agentic.market +
  x402-list (free) first, x402scan (paid API, post-M4) as supplement.
- 2.3: PR target is awesome-agentic-commerce.
- 4.3: drop the mini-research pass; use `x402.mcp`.
- 4.4: list via v2 Bazaar extension + first settlement; verify indexing
  (bug #2112).
