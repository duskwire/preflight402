# Design: Crowdsourced Delivery Verification (M8-delivery)

_Spec, 2026-07-22; research-validated 2026-07-24 (see §0). **Status: Phase A
SHIPPED + LIVE 2026-07-25** (commit c98571a) — guard reporting + POST
/delivery-reports dark launch, storage only, adversarially reviewed (10 fixes),
deployed to the LXC (db v4). Phases B (on-chain verify + payer clustering),
C (verdict gates), D (seller badge) remain. Decisions locked with the user:
split-default telemetry (anonymous minimal ON by default, tx-anchored verified
tier opt-in); phased build._

---

## 0. Research validation (2026-07-24 landscape sweep)

- **The gap is confirmed open.** No service performs paid test purchases or
  delivery/quality scoring of x402 endpoints as of July 2026; the closest
  (x402scan) is passive probing. Emerging alternatives are STRUCTURAL —
  escrow+evaluator (ERC-8183 "Job" primitive, Feb 2026; Virtuals ACP; x402r
  refund/escrow extension, beta) — not evidence from real purchases. The
  x402 V2 spec still ships no escrow/refund/dispute mechanism.
- **Academic validation + attack catalog:** arXiv 2605.11781 ("Five Attacks
  on x402", May 2026) demonstrates paid-but-denied attacks, **248 HTTP grants
  replayed from a single on-chain payment**, and 60.2% discovery-Sybil gaming
  from 5 registrations — "customers bear losses without recourse". Design
  consequences: the per-(endpoint, tx) UNIQUE replay guard is load-bearing;
  verification must bind tx → payee → endpoint, not just tx-exists.
- **Competitive landscape:** paid probe competitors exist (x402.fuchss.app,
  ~60k endpoints, per-call pricing) and a client-side policy guard competitor
  exists (PolicyLayer, Jan 2026, npm `@policylayer/sdk` — spend caps/allowlists,
  no trust verdict); the seller badge (our Phase D) already shipped
  (x402station $1/30-day, May 2026). **None of them observe DELIVERY.** Our
  moat is the only-one-with-post-hoc-delivery-evidence position — observational,
  needs no seller cooperation, works on today's fire-and-forget x402 (unlike
  the escrow/evaluator approaches that need both sides to adopt a new protocol
  and lock funds). We can't give recourse; we give forewarning.
- **B2A shift confirmed:** Apify exposes 20k Actors at $1 min but its quality
  score is NOT in the 402 challenge ("agents pay blind on quality"); Cloudflare
  (1B+ 402/day) + AWS WAF wire x402 at the edge, both purely seller-side, no
  buyer trust signal. Item-level, buyer-facing delivery evidence is unclaimed.

---

## 1. The gap this fills

preflight402 today answers **"can I reach and parse this endpoint, and who is
the payee?"** It does not answer **"if I pay, do I get what was advertised?"**
Nobody in the x402 ecosystem answers that. x402 is pay-first: no escrow, no
refunds, no disputes. At $0.001 nobody cared; with the B2A shift (Apify's 20k
actors at $1 minimums, Cloudflare serving 1B+ 402/day, business buyers) the
"did I get the goods" question is real money.

**The insight (from the user):** don't fund synthetic test purchases — observe
the purchases users are *already making* through the guard, and crowdsource the
delivery signal. This flips the economics (users fund it), scales with adoption
instead of our wallet, and yields evidence from real payments, which is more
credible than synthetic probes. Waze for the agent payment economy: every user
improves the verdicts that make the guard worth installing.

**Why this is a moat:** it costs adoption + adversarial methodology to build.
Free static scanners (x402scan, Bazaar) can't follow — they have no payment
stream to observe. And it's the honest answer to "what do we add on Apify?":
not "is apify.com up" (worthless — the brand solves that) but **item-level**,
per-actor delivery evidence funded by the buyers themselves.

---

## 2. Threat model (the reason this is hard)

Crowdsourced trust data is **attacker-writable**. The report endpoint is public;
anyone can POST. Two attack classes:

- **Self-promotion (false positive):** a seller reports glowing deliveries for
  their own endpoint to earn a "verified: delivers" verdict.
- **Sabotage (false negative):** a rival reports fake "returned garbage"
  failures to tank a competitor's verdict.

Plus nuisance: replay of a real report, volume flooding, and privacy leakage
(linking wallets to the endpoints they buy from).

### The defense reuses machinery we already shipped in M6

1. **On-chain anchoring (verified tier).** A report may carry the settlement
   `transaction` hash from the x402 `SettleResponse`. We verify it on-chain via
   the existing Alchemy client (`reputation/alchemy.py`): does this tx exist,
   did it move ≥ the claimed amount of the expected asset to the endpoint's
   known payee, recently? Faking a *positive* delivery then costs a **real
   settlement from a funded wallet** — not free.

2. **Sybil clustering over PAYERS (not reviewers).** The M6 first-funder
   union-find (`reputation/sybil.py`) already collapses coordinated wallets:
   it took Captain Dackie's 996 reviewers to 12 independent funding clusters.
   We run the *same* clustering over the `payer` addresses of verified reports.
   **One vote per funding cluster.** A farm that funds 500 payer wallets from
   one root counts once.

3. **Negative reports get the strict treatment (M6.3 gate pattern).** A real
   $0.001 payment proves you *paid*, not that your "it returned garbage" claim
   is true — so a verified tx does NOT by itself make a negative credible.
   Negative delivery evidence: (a) requires ≥ `DELIVERY_MIN_CLUSTERS` (3)
   independent payer clusters reporting failure, (b) is cross-checked against
   our own prober's live view of the endpoint (if WE see it serving fine, a
   lone cluster of failure reports is downweighted), and (c) **caps at
   caution** — crowdsourced negatives can never force `avoid` on their own,
   mirroring M6.3's rule that a hostile reputation campaign can't kill an agent
   through us.

4. **Anonymous (non-tx) reports are HINTS only.** They never move the verdict
   or the delivery success rate; they surface as a soft count and feed
   anomaly detection ("lots of anonymous failure reports on X → prioritize a
   prober re-check"). This is what lets the default-on anonymous tier be
   low-risk: attacker-writable data with zero verdict authority.

---

## 3. Telemetry model (the split default)

| Tier | Default | Carries | Verdict authority |
|---|---|---|---|
| **Anonymous** | **ON** (loud README disclosure + one-line kill switch) | endpoint URL, HTTP status, latency bucket, content-type, response-size bucket, coarse timestamp. **No tx, no payer, no client identity, no bodies/headers.** | none — hints only |
| **Verified** | **OPT-IN** (`report_settlements=True`) | the above **+ settlement tx hash, payer address, network, amount** | full (after on-chain verify + clustering) |

Rationale: the anonymous tier keeps the flywheel turning from day one at
low risk (it can't move verdicts, so poisoning it is pointless), while the
verified tier — which links a wallet to an endpoint, real information even
though the tx is already public — stays strictly opt-in so business users are
never surprised. A trust brand caught quietly phoning home sensitive data is
dead; this split is the defensible line.

**Kill switch:** `Guard(report_outcomes=False)` disables all reporting;
`PREFLIGHT402_GUARD_NO_TELEMETRY=1` env var forces it off process-wide
(honored even if code sets True). Documented at the top of the guard README.

---

## 4. Client side (guard)

The guard already installs a `BeforePaymentCreation` hook. Add an
`on_payment_response` hook — the x402 SDK fires it after a paid HTTP request
with a `PaymentResponseContext` carrying exactly what we need (verified against
x402 2.16):

```
PaymentResponseContext:
  requirements     -> endpoint terms (network, asset, amount, pay_to)
  settle_response  -> SettleResponse(success, payer, transaction, network, amount)
  payment_required -> resource.url (the endpoint)
  error            -> transport/HTTP failure (delivery failed post-payment)
```

- **Delivery outcome** = derived from `error` (transport/HTTP failure after
  paying → `delivered=false`) and, where the transport exposes it, the response
  status/content-type/size. We do **not** read or transmit response bodies.
- **Batched, async, fire-and-forget, best-effort.** Reporting must never add
  latency to or fail the payment path (same never-raises discipline as the
  rest of the guard). A tiny in-process queue flushed on a timer/size to
  `POST {service}/delivery-reports`; drop on any error.
- **New `Guard` params:** `report_outcomes: bool = True` (anonymous tier),
  `report_settlements: bool = False` (verified tier), `report_endpoint`
  (defaults to the service URL). A `GuardDelivery` helper owns the queue.

CLI: `preflight402-guard report <url> --status ok|failed [--tx 0x..]` for
manual/one-off contribution and testing.

---

## 5. Server side

### 5.1 Ingestion — `POST /delivery-reports`

- Accepts a small JSON batch. Rate-limited (reuse `api/ratelimit.py`,
  CF-Connecting-IP keyed) and size-capped. SSRF-guard the reported URL through
  the existing `probe/guard.py` before it can create an endpoint row.
- Hostile input throughout: isinstance guards, URL canonicalization
  (`queries.canonicalize_url`), unknown fields ignored, per-report isolation so
  one bad record can't poison a batch (same posture as the M3 ingesters).
- Writes raw rows; verification + aggregation happen out of band (below), so
  ingestion is cheap and the endpoint can't be used to force expensive RPC.

### 5.2 Storage — migration `0004_delivery.sql`

```sql
CREATE TABLE delivery_reports (
    id            INTEGER PRIMARY KEY,
    endpoint_id   INTEGER NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
    reported_at   TEXT NOT NULL,
    delivered     INTEGER NOT NULL,          -- 1 = got a usable response, 0 = failed
    http_status   INTEGER,
    latency_ms    REAL,
    content_type  TEXT,
    size_bucket   TEXT,                       -- coarse: xs|s|m|l|xl
    tier          TEXT NOT NULL,              -- 'anonymous' | 'verified'
    -- verified tier only:
    tx_hash       TEXT,                       -- lowercased, UNIQUE per endpoint (replay guard)
    payer         TEXT,                       -- lowercased; clustered via reviewer_funding
    chain_id      INTEGER,
    amount        TEXT,                       -- atomic units, as settled
    verify_status TEXT NOT NULL DEFAULT 'unverified',  -- unverified|verified|rejected
    verified_at   TEXT
) STRICT;
CREATE UNIQUE INDEX idx_delivery_tx ON delivery_reports(endpoint_id, tx_hash)
    WHERE tx_hash IS NOT NULL;               -- one report per settlement
CREATE INDEX idx_delivery_endpoint ON delivery_reports(endpoint_id);
```

The `payer` column feeds the **existing** `reviewer_funding` cache and
first-funder clustering — payers are just addresses; M6's union-find doesn't
care whether an address reviewed or paid. No new clustering code.

### 5.3 Verification worker

A background pass (like `db/rollups.py`) over `verify_status='unverified'`
verified-tier rows:
- `alchemy.verify_settlement(tx_hash, chain_id, expected_payee, min_amount)` —
  a new method on the Alchemy client (this IS the build plan's `verify_settlement`
  primitive, arriving as an integrity layer, not a paid tool): fetch the tx
  receipt, confirm a USDC/asset transfer of ≥amount to the endpoint's bound
  payee, mark `verified` or `rejected`.
- Gated on `PREFLIGHT402_ALCHEMY_API_KEY` (same as M6). No key → verified tier
  inert, anonymous tier still flows.
- Cache-friendly: a tx is verified once, ever.

### 5.4 Aggregation → the delivery block

At verdict time (or a rollup), for a bound/known endpoint:
1. Take its **verified** reports, cluster the payers (M6 union-find), one vote
   per cluster.
2. `verified_success_rate` = fraction of clusters whose reports are mostly
   `delivered=1`; `distinct_payer_clusters` = the vote count.
3. Cross-check against our prober's recent health for the same endpoint.

---

## 6. Verdict integration (`authenticity` / new `delivery` block)

Additive to `trust-preview.v1` (additive-only within v1, per the build plan):

```json
"delivery": {
  "status": "no_data | reported | verified",
  "verified_success_rate": 0.98,          // null unless status=verified
  "distinct_payer_clusters": 14,          // one vote per funding cluster
  "sampled_reports": 210,                 // total verified reports behind it
  "anonymous_hint": "mostly_ok | mixed | mostly_failed | null",  // never authoritative
  "last_report_at": "2026-07-22T…Z"
}
```

**Verdict gates (mirror M6.3, honest-status convention):**
- `status` starts `no_data`; becomes `reported` when anonymous hints exist but
  no verified clusters; `verified` at ≥ `DELIVERY_MIN_CLUSTERS` (3) clusters.
- **Strong verified delivery** (`verified_success_rate` ≥ 0.9 across ≥3
  clusters): a positive reason; can nudge a thin-history caution toward proceed
  (same waiver logic as M6.3's reputation vouch). Never manufactures a proceed
  on a broken endpoint.
- **Poor verified delivery** (rate < ~0.5 across ≥3 clusters): a caution
  reason; can demote proceed → caution; **never forces avoid alone** (a
  sabotage campaign must not kill an agent through us).
- **Anonymous hints never move the recommendation** — they only populate
  `anonymous_hint` and trigger prober re-checks.

---

## 7. Cold start & rollout

The block is honestly `no_data` until guard adoption produces reports — fine,
because it ships into the same adoption push the listings started. Phased:

1. **Phase A — client reporting + ingestion (dark launch).** Guard emits
   anonymous reports; server stores raw; **zero verdict impact**. Validates the
   pipe and starts the data pond. (This is the "client side first" option, kept
   as the natural Phase 1.)
2. **Phase B — verification + clustering.** Wire `verify_settlement`, the payer
   clustering, and the aggregation. Delivery block populates but stays
   informational.
3. **Phase C — verdict gates.** Turn on the M6.3-style waiver/demote once real
   verified data exists and thresholds are calibrated against it.
4. **Phase D (later, monetization-friendly, no buyer paywall):** seller-side
   "delivery-tested" badge — in B2A the *sellers* want agent traffic and have
   real willingness-to-pay for a credential, consistent with keeping the buyer
   side free.

---

## 8. What we reuse vs. build

**Reuse (most of it):** Alchemy client, first-funder cache + union-find
clustering (M6), the honest-status verdict convention (M5/M6.3), rate limiting
+ SSRF guard (hardening), migration machinery, rollup-worker pattern, the
guard's never-raises hook discipline.

**Build (small, well-scoped):** `on_payment_response` hook + report queue in
the guard; `alchemy.verify_settlement`; `POST /delivery-reports` + migration
0004 + a verification worker + the aggregation query; the additive `delivery`
block + its gates.

**Open calibration questions (decide with Phase-B data, not now):** the
success-rate thresholds; whether "delivered" can be inferred richly enough from
the SDK's `error`/status without bodies (may need an optional, opt-in
schema-match signal the client computes locally and sends as a single
matched/not-matched bit); minimum time/observation before `verified`.

**Non-goals:** reading or storing response bodies; escrow/refunds/custody
(we're a verdict layer, not a counterparty); competing with AP2/Payman mandate
runtimes (we compose under them — our verdict informs their policy).
