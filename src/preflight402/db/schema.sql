-- preflight402 schema v1 (migration 1).
-- Frozen once shipped: schema changes go in migrations/NNNN_name.sql (NNNN >= 0002),
-- applied in order by preflight402.db.connection.migrate().
--
-- Timestamps are TEXT, UTC, millisecond precision, 'Z' suffix
-- ('%Y-%m-%dT%H:%M:%fZ'), so lexicographic order is chronological. Python-side
-- writes must use preflight402.db.connection.utcnow_iso(), which emits the
-- identical format; the DEFAULTs below are a fallback, not the primary path.

CREATE TABLE endpoints (
    id             INTEGER PRIMARY KEY,
    url            TEXT NOT NULL UNIQUE,        -- canonicalized (queries.canonicalize_url)
    host           TEXT NOT NULL,               -- lowercased hostname, for per-host politeness (M3)
    sources        TEXT NOT NULL DEFAULT '[]',  -- JSON array: bazaar | x402scan | x402-list | ...
    first_seen_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    last_probed_at TEXT,
    enabled        INTEGER NOT NULL DEFAULT 1,
    meta           TEXT                         -- JSON, source-specific extras
) STRICT;

CREATE INDEX idx_endpoints_host ON endpoints(host);
CREATE INDEX idx_endpoints_due ON endpoints(last_probed_at) WHERE enabled = 1;

CREATE TABLE probes (
    id             INTEGER PRIMARY KEY,
    endpoint_id    INTEGER NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
    probed_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    ok             INTEGER NOT NULL,            -- 1 = got an HTTP response
    error          TEXT,                        -- timeout | dns | tls | conn_refused | ... when ok=0
    http_status    INTEGER,
    latency_ms     REAL,
    tls_valid      INTEGER,
    tls_expires_at TEXT,
    tls_issuer     TEXT,
    is_402         INTEGER NOT NULL DEFAULT 0,
    protocol       TEXT,                        -- x402-v1 | x402-v2 | mpp | none
    spec_compliant INTEGER,
    warnings       TEXT,                        -- JSON array of strings
    payment        TEXT                         -- JSON: networks/assets/price/pay_to from parsed 402
) STRICT;

CREATE INDEX idx_probes_endpoint_time ON probes(endpoint_id, probed_at);

CREATE TABLE rollups (
    endpoint_id   INTEGER NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
    period        TEXT NOT NULL CHECK (period IN ('24h', '7d', '30d')),
    computed_at   TEXT NOT NULL,
    probe_count   INTEGER NOT NULL,
    uptime_pct    REAL,
    p50_ms        REAL,
    p90_ms        REAL,
    p99_ms        REAL,
    status_counts TEXT,                         -- JSON {"402": 600, "500": 3}
    PRIMARY KEY (endpoint_id, period)
) STRICT, WITHOUT ROWID;

-- Rowid table on purpose: verdict rows hold multi-KB JSON documents, which are a
-- poor fit for WITHOUT ROWID storage (overflow pages inside the PK b-tree).
CREATE TABLE verdict_cache (
    id           INTEGER PRIMARY KEY,
    endpoint_url TEXT NOT NULL,                 -- canonicalized; URL-keyed because preflight
                                                -- serves URLs not yet in endpoints
    tier         TEXT NOT NULL CHECK (tier IN ('preflight', 'deep_report', 'trust_verdict')),
    verdict      TEXT NOT NULL,                 -- trust-preview.v1 JSON
    generated_at TEXT NOT NULL,
    expires_at   TEXT NOT NULL,
    UNIQUE (endpoint_url, tier)
) STRICT;

CREATE INDEX idx_verdict_cache_expires ON verdict_cache(expires_at);
