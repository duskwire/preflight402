-- Daily usage counters (dashboard: "free preflight calls" and friends).
-- One row per (UTC day, metric); bumped via queries.bump_counter.
CREATE TABLE counters (
    day    TEXT NOT NULL,               -- YYYY-MM-DD, UTC
    metric TEXT NOT NULL,               -- preflight_calls | preflight_cache_hits | ...
    value  INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (day, metric)
) STRICT, WITHOUT ROWID;
