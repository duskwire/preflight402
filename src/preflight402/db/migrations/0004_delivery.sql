-- M8-delivery Phase A: crowdsourced delivery-outcome reports from
-- preflight402-guard (docs/DESIGN-delivery-verification.md). One row per
-- reported payment outcome. Phase A stores raw reports ONLY — verification
-- (Alchemy tx check) and aggregation into the verdict come in Phases B/C, so
-- nothing here moves a verdict yet.
--
-- Trust posture: the report body is ATTACKER-WRITABLE (anyone can POST). The
-- columns that carry weight later (tx_hash, payer) are meaningless until the
-- Phase-B worker verifies them on-chain, which is why verify_status defaults
-- to 'unverified' and the aggregation ignores unverified verified-tier rows.
CREATE TABLE delivery_reports (
    id            INTEGER PRIMARY KEY,
    endpoint_id   INTEGER NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
    reported_at   TEXT NOT NULL,
    delivered     INTEGER NOT NULL,          -- 1 = paid request succeeded, 0 = paid but failed
    tier          TEXT NOT NULL CHECK (tier IN ('anonymous', 'verified')),
    outcome       TEXT,                       -- coarse failure category (no raw error text)
    http_status   INTEGER,                    -- optional, when the client supplied it
    latency_ms    REAL,                       -- optional
    content_type  TEXT,                       -- optional
    -- verified tier only (all NULL for anonymous):
    tx_hash       TEXT,                       -- lowercased settlement tx
    payer         TEXT,                       -- lowercased; clustered via reviewer_funding (M6)
    chain_id      INTEGER,
    amount        TEXT,                       -- atomic units, as settled
    verify_status TEXT NOT NULL DEFAULT 'unverified'
                  CHECK (verify_status IN ('unverified', 'verified', 'rejected')),
    verified_at   TEXT
) STRICT;

-- One report per settlement per endpoint: the "Five Attacks on x402" paper
-- showed a single on-chain payment replayed into 248 HTTP grants, so a tx must
-- not be able to stuff the ballot. Partial index — anonymous rows carry no tx.
CREATE UNIQUE INDEX idx_delivery_tx
    ON delivery_reports(endpoint_id, tx_hash) WHERE tx_hash IS NOT NULL;

CREATE INDEX idx_delivery_endpoint ON delivery_reports(endpoint_id);
-- The Phase-B verification worker scans for pending verified-tier rows.
CREATE INDEX idx_delivery_pending
    ON delivery_reports(verify_status) WHERE tx_hash IS NOT NULL;
