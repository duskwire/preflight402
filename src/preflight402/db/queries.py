"""Thin CRUD layer over the v1 schema.

Every function takes an open connection (see connection.connect) and returns
plain dicts, never sqlite3.Row. JSON columns (endpoints.sources/meta,
probes.warnings/payment, rollups.status_counts, verdict_cache.verdict) are
encoded and decoded at this boundary — callers pass and receive Python
objects. URL arguments are canonicalized on the way in, so spelling variants
of the same endpoint hit the same rows.

Timestamps are canonical-format strings (connection.utcnow_iso). Functions
whose behavior depends on the clock take an injectable `now` string.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from preflight402.db.connection import transaction, utcnow_iso

_DEFAULT_PORTS = {"http": 80, "https": 443}

# Column names are unique across tables, so one flat set suffices.
_JSON_COLS = frozenset({"sources", "meta", "warnings", "payment", "status_counts", "verdict"})


class InvalidURLError(ValueError):
    """The URL cannot be canonicalized: bad port, or missing http(s) scheme or host.

    URLs arrive from untrusted registries and agent callers; ingest loops
    should catch this per record and skip-and-log rather than abort the batch.
    """


def canonicalize_url(url: str) -> str:
    """Normalize a URL so trivial spelling variants compare equal.

    Lowercases scheme and host, strips default ports and the fragment, and
    turns an empty path into '/'. The path is otherwise preserved verbatim
    ('/data' and '/data/' can be different resources), as is the query string.
    Idempotent. Raises InvalidURLError on anything that is not a plausible
    http(s) endpoint; IDN hosts are kept as-is (not punycoded), so encoding
    variants of the same name are distinct endpoints.
    """
    try:
        parts = urlsplit(url.strip())
        hostname = parts.hostname
    except ValueError as exc:
        # urlsplit itself rejects some hostile shapes (unclosed IPv6 brackets,
        # NFKC-invalid netloc characters) with a bare ValueError — that must
        # not escape this function's documented InvalidURLError contract.
        raise InvalidURLError(f"unparseable URL: {url!r}") from exc
    scheme = parts.scheme.lower()
    if scheme not in _DEFAULT_PORTS:
        raise InvalidURLError(f"not an http(s) URL: {url!r}")
    host = (hostname or "").lower()
    if not host:
        raise InvalidURLError(f"missing host: {url!r}")
    try:
        port = parts.port
    except ValueError as exc:
        raise InvalidURLError(f"invalid port in {url!r}") from exc
    if ":" in host:
        host = f"[{host}]"  # re-bracket IPv6 literals (urlsplit strips the brackets)
    netloc = host
    if port is not None and port != _DEFAULT_PORTS[scheme]:
        netloc = f"{host}:{port}"
    if parts.username is not None:
        userinfo = parts.username
        if parts.password is not None:
            userinfo = f"{userinfo}:{parts.password}"
        netloc = f"{userinfo}@{netloc}"
    return urlunsplit((scheme, netloc, parts.path or "/", parts.query, ""))


def _to_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
    if row is None:
        return None
    record = dict(row)
    for key in _JSON_COLS & record.keys():
        if record[key] is not None:
            record[key] = json.loads(record[key])
    return record


def _dump(value: Any) -> str | None:
    return None if value is None else json.dumps(value, ensure_ascii=False)


# --- endpoints ---------------------------------------------------------------


def upsert_endpoint(
    conn: sqlite3.Connection,
    url: str,
    *,
    source: str | None = None,
    meta: dict[str, Any] | None = None,
    source_meta: dict[str, Any] | None = None,
    now: str | None = None,
) -> int:
    """Insert an endpoint or merge into the existing row; return its id.

    On conflict the first-discoverer data wins: first_seen_at and existing
    sources are kept, `source` is appended to sources if new, and meta is
    replaced only when a non-None meta is supplied.

    `source_meta` (requires `source`) instead merges under a per-source
    namespace — meta["bazaar"] = {...} — INSIDE this transaction, so two
    ingest processes upserting the same URL cannot lose each other's
    namespace to a read-modify-write race. Mutually exclusive with `meta`.
    """
    if source_meta is not None:
        if source is None:
            raise ValueError("source_meta requires source")
        if meta is not None:
            raise ValueError("meta and source_meta are mutually exclusive")
    url = canonicalize_url(url)
    host = urlsplit(url).hostname or ""
    with transaction(conn):
        row = conn.execute(
            "SELECT id, sources, meta FROM endpoints WHERE url = ?", (url,)
        ).fetchone()
        if source_meta is not None:
            existing_meta = json.loads(row["meta"]) if row is not None and row["meta"] else None
            meta = dict(existing_meta) if isinstance(existing_meta, dict) else {}
            meta[source] = source_meta
        if row is None:
            cursor = conn.execute(
                "INSERT INTO endpoints (url, host, sources, first_seen_at, meta)"
                " VALUES (?, ?, ?, ?, ?)",
                (url, host, _dump([source] if source else []), now or utcnow_iso(), _dump(meta)),
            )
            return cursor.lastrowid
        sources = json.loads(row["sources"])
        if source is not None and source not in sources:
            sources.append(source)
        conn.execute(
            "UPDATE endpoints SET sources = ?, meta = COALESCE(?, meta) WHERE id = ?",
            (_dump(sources), _dump(meta), row["id"]),
        )
        return row["id"]


def get_endpoint(conn: sqlite3.Connection, url: str) -> dict[str, Any] | None:
    row = conn.execute("SELECT * FROM endpoints WHERE url = ?", (canonicalize_url(url),)).fetchone()
    return _to_dict(row)


def list_endpoints(conn: sqlite3.Connection, *, enabled_only: bool = True) -> list[dict[str, Any]]:
    sql = "SELECT * FROM endpoints"
    if enabled_only:
        sql += " WHERE enabled = 1"
    return [_to_dict(row) for row in conn.execute(sql + " ORDER BY id")]


def endpoints_due(conn: sqlite3.Connection, *, before: str, limit: int) -> list[dict[str, Any]]:
    """Enabled endpoints last probed before `before` (or never), oldest first.

    Never-probed endpoints (last_probed_at IS NULL) sort first.
    """
    rows = conn.execute(
        "SELECT * FROM endpoints"
        " WHERE enabled = 1 AND (last_probed_at IS NULL OR last_probed_at < ?)"
        " ORDER BY last_probed_at ASC NULLS FIRST, id ASC LIMIT ?",
        (before, limit),
    )
    return [_to_dict(row) for row in rows]


def set_endpoint_enabled(conn: sqlite3.Connection, endpoint_id: int, enabled: bool) -> None:
    conn.execute("UPDATE endpoints SET enabled = ? WHERE id = ?", (enabled, endpoint_id))


# --- probes ------------------------------------------------------------------


def record_probe(
    conn: sqlite3.Connection,
    endpoint_id: int,
    *,
    ok: bool,
    error: str | None = None,
    http_status: int | None = None,
    latency_ms: float | None = None,
    tls_valid: bool | None = None,
    tls_expires_at: str | None = None,
    tls_issuer: str | None = None,
    is_402: bool = False,
    protocol: str | None = None,
    spec_compliant: bool | None = None,
    warnings: list[str] | None = None,
    payment: dict[str, Any] | None = None,
    now: str | None = None,
) -> int:
    """Insert a probe row and update the endpoint's last_probed_at atomically.

    Both rows get the identical timestamp, so endpoints.last_probed_at always
    equals the matching probe's probed_at.
    """
    now = now or utcnow_iso()
    with transaction(conn):
        cursor = conn.execute(
            "INSERT INTO probes (endpoint_id, probed_at, ok, error, http_status, latency_ms,"
            " tls_valid, tls_expires_at, tls_issuer, is_402, protocol, spec_compliant,"
            " warnings, payment)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                endpoint_id,
                now,
                ok,
                error,
                http_status,
                latency_ms,
                tls_valid,
                tls_expires_at,
                tls_issuer,
                is_402,
                protocol,
                spec_compliant,
                _dump(warnings),
                _dump(payment),
            ),
        )
        conn.execute("UPDATE endpoints SET last_probed_at = ? WHERE id = ?", (now, endpoint_id))
        return cursor.lastrowid


def latest_probes(
    conn: sqlite3.Connection, endpoint_id: int, *, limit: int = 1
) -> list[dict[str, Any]]:
    """Most recent probes first (id breaks same-millisecond ties)."""
    rows = conn.execute(
        "SELECT * FROM probes WHERE endpoint_id = ? ORDER BY probed_at DESC, id DESC LIMIT ?",
        (endpoint_id, limit),
    )
    return [_to_dict(row) for row in rows]


def probes_since(conn: sqlite3.Connection, endpoint_id: int, since: str) -> list[dict[str, Any]]:
    """Probes with probed_at >= since (inclusive), oldest first."""
    rows = conn.execute(
        "SELECT * FROM probes WHERE endpoint_id = ? AND probed_at >= ?"
        " ORDER BY probed_at ASC, id ASC",
        (endpoint_id, since),
    )
    return [_to_dict(row) for row in rows]


# --- rollups -----------------------------------------------------------------


def upsert_rollup(
    conn: sqlite3.Connection,
    endpoint_id: int,
    period: str,
    *,
    probe_count: int,
    uptime_pct: float | None = None,
    p50_ms: float | None = None,
    p90_ms: float | None = None,
    p99_ms: float | None = None,
    status_counts: dict[str, int] | None = None,
    computed_at: str | None = None,
) -> None:
    conn.execute(
        "INSERT INTO rollups (endpoint_id, period, computed_at, probe_count, uptime_pct,"
        " p50_ms, p90_ms, p99_ms, status_counts)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
        " ON CONFLICT (endpoint_id, period) DO UPDATE SET"
        " computed_at = excluded.computed_at, probe_count = excluded.probe_count,"
        " uptime_pct = excluded.uptime_pct, p50_ms = excluded.p50_ms,"
        " p90_ms = excluded.p90_ms, p99_ms = excluded.p99_ms,"
        " status_counts = excluded.status_counts",
        (
            endpoint_id,
            period,
            computed_at or utcnow_iso(),
            probe_count,
            uptime_pct,
            p50_ms,
            p90_ms,
            p99_ms,
            _dump(status_counts),
        ),
    )


def get_rollups(conn: sqlite3.Connection, endpoint_id: int) -> dict[str, dict[str, Any]]:
    """Rollups for an endpoint, keyed by period ('24h' | '7d' | '30d')."""
    rows = conn.execute("SELECT * FROM rollups WHERE endpoint_id = ?", (endpoint_id,))
    return {row["period"]: _to_dict(row) for row in rows}


# --- verdict cache -----------------------------------------------------------


def put_verdict(
    conn: sqlite3.Connection,
    url: str,
    tier: str,
    verdict: dict[str, Any],
    *,
    ttl_seconds: float,
    now: str | None = None,
) -> None:
    now = now or utcnow_iso()
    expires_at = _iso_add_seconds(now, ttl_seconds)
    conn.execute(
        "INSERT INTO verdict_cache (endpoint_url, tier, verdict, generated_at, expires_at)"
        " VALUES (?, ?, ?, ?, ?)"
        " ON CONFLICT (endpoint_url, tier) DO UPDATE SET"
        " verdict = excluded.verdict, generated_at = excluded.generated_at,"
        " expires_at = excluded.expires_at",
        (canonicalize_url(url), tier, _dump(verdict), now, expires_at),
    )


def get_verdict(
    conn: sqlite3.Connection, url: str, tier: str, *, now: str | None = None
) -> dict[str, Any] | None:
    """The cached verdict row for (url, tier), or None if absent or expired."""
    row = conn.execute(
        "SELECT * FROM verdict_cache WHERE endpoint_url = ? AND tier = ? AND expires_at > ?",
        (canonicalize_url(url), tier, now or utcnow_iso()),
    ).fetchone()
    return _to_dict(row)


def purge_expired_verdicts(conn: sqlite3.Connection, *, now: str | None = None) -> int:
    """Delete expired cache rows; return how many were removed."""
    cursor = conn.execute("DELETE FROM verdict_cache WHERE expires_at <= ?", (now or utcnow_iso(),))
    return cursor.rowcount


def _iso_add_seconds(timestamp: str, seconds: float) -> str:
    result = datetime.fromisoformat(timestamp) + timedelta(seconds=seconds)
    return result.isoformat(timespec="milliseconds").replace("+00:00", "Z")
