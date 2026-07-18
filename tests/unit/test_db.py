import re
import shutil
import sqlite3
import threading
from pathlib import Path

import pytest

from preflight402.db import connect, migrate, transaction, utcnow_iso
from preflight402.db import queries as q
from preflight402.db.connection import _DB_DIR, _migration_files, _statements

CANONICAL_TS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")


@pytest.fixture()
def db_path(tmp_path: Path) -> Path:
    return tmp_path / "test.db"


@pytest.fixture()
def db(db_path: Path):
    conn = connect(db_path)
    migrate(conn)
    yield conn
    conn.close()


# --- connection + migration ---------------------------------------------------


def test_migrate_fresh_db(db) -> None:
    assert db.execute("PRAGMA user_version").fetchone()[0] == 1
    assert db.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    tables = {
        row["name"] for row in db.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
    }
    assert {"endpoints", "probes", "rollups", "verdict_cache"} <= tables


def test_migrate_is_idempotent(db) -> None:
    assert migrate(db) == 1
    assert migrate(db) == 1


def _tmp_db_dir(tmp_path: Path) -> Path:
    """A throwaway db_dir with the real schema.sql and an empty migrations/."""
    db_dir = tmp_path / "dbdir"
    (db_dir / "migrations").mkdir(parents=True)
    shutil.copy(_DB_DIR / "schema.sql", db_dir / "schema.sql")
    return db_dir


def test_failed_migration_rolls_back(db, tmp_path: Path) -> None:
    # A migration that half-succeeds must leave no trace: version unchanged,
    # no partially created objects.
    db_dir = _tmp_db_dir(tmp_path)
    (db_dir / "migrations" / "0002_bad.sql").write_text(
        "CREATE TABLE half_done (id INTEGER PRIMARY KEY) STRICT;\nTHIS IS NOT SQL;\n"
    )
    with pytest.raises(sqlite3.OperationalError):
        migrate(db, db_dir=db_dir)
    assert db.execute("PRAGMA user_version").fetchone()[0] == 1
    assert not db.in_transaction
    row = db.execute("SELECT name FROM sqlite_master WHERE name = 'half_done'").fetchone()
    assert row is None
    # The connection stays usable and a fixed migration applies cleanly.
    (db_dir / "migrations" / "0002_bad.sql").write_text(
        "CREATE TABLE now_good (id INTEGER PRIMARY KEY) STRICT;\n"
    )
    assert migrate(db, db_dir=db_dir) == 2


def test_migration_files_reject_gaps_and_duplicates(tmp_path: Path) -> None:
    db_dir = tmp_path / "dbdir"
    (db_dir / "migrations").mkdir(parents=True)
    (db_dir / "schema.sql").write_text("CREATE TABLE t (id INTEGER PRIMARY KEY);\n")

    (db_dir / "migrations" / "0003_gap.sql").write_text("SELECT 1;\n")
    with pytest.raises(ValueError, match="non-contiguous"):
        _migration_files(db_dir)

    (db_dir / "migrations" / "0003_gap.sql").unlink()
    (db_dir / "migrations" / "0001_dup.sql").write_text("SELECT 1;\n")
    with pytest.raises(ValueError, match="start at 0002"):
        _migration_files(db_dir)

    (db_dir / "migrations" / "0001_dup.sql").unlink()
    (db_dir / "migrations" / "badname.sql").write_text("SELECT 1;\n")
    with pytest.raises(ValueError, match="NNNN_name"):
        _migration_files(db_dir)

    (db_dir / "migrations" / "badname.sql").unlink()
    (db_dir / "migrations" / "0002_a.sql").write_text("SELECT 1;\n")
    (db_dir / "migrations" / "0002_b.sql").write_text("SELECT 1;\n")
    with pytest.raises(ValueError, match="duplicate"):
        _migration_files(db_dir)


def test_migrate_applies_multiple_pending_in_order(db, tmp_path: Path) -> None:
    db_dir = _tmp_db_dir(tmp_path)
    (db_dir / "migrations" / "0002_add_notes.sql").write_text(
        "CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT) STRICT;\n"
    )
    # 0003 depends on 0002 having run, so out-of-order application would fail.
    (db_dir / "migrations" / "0003_extend_notes.sql").write_text(
        "ALTER TABLE notes ADD COLUMN created_at TEXT;\n"
    )
    assert migrate(db, db_dir=db_dir) == 3
    columns = {row["name"] for row in db.execute("PRAGMA table_info(notes)")}
    assert {"id", "body", "created_at"} <= columns


def test_migration_table_rebuild_preserves_child_rows(db, tmp_path: Path) -> None:
    # The SQLite-documented rebuild recipe drops and renames the parent table.
    # migrate() must run it with foreign keys off, or DROP TABLE endpoints
    # would cascade-delete every probe.
    endpoint_id = q.upsert_endpoint(db, "https://api.example.com/")
    q.record_probe(db, endpoint_id, ok=True)
    db_dir = _tmp_db_dir(tmp_path)
    (db_dir / "migrations" / "0002_rebuild_endpoints.sql").write_text(
        "CREATE TABLE endpoints_new (\n"
        "    id             INTEGER PRIMARY KEY,\n"
        "    url            TEXT NOT NULL UNIQUE,\n"
        "    host           TEXT NOT NULL,\n"
        "    sources        TEXT NOT NULL DEFAULT '[]',\n"
        "    first_seen_at  TEXT NOT NULL,\n"
        "    last_probed_at TEXT,\n"
        "    enabled        INTEGER NOT NULL DEFAULT 1,\n"
        "    meta           TEXT,\n"
        "    notes          TEXT\n"
        ") STRICT;\n"
        "INSERT INTO endpoints_new (id, url, host, sources, first_seen_at,"
        " last_probed_at, enabled, meta)\n"
        "    SELECT id, url, host, sources, first_seen_at, last_probed_at,"
        " enabled, meta FROM endpoints;\n"
        "DROP TABLE endpoints;\n"
        "ALTER TABLE endpoints_new RENAME TO endpoints;\n"
    )
    assert migrate(db, db_dir=db_dir) == 2
    assert len(q.latest_probes(db, endpoint_id)) == 1  # cascade did not fire
    assert q.get_endpoint(db, "https://api.example.com/")["id"] == endpoint_id
    # Enforcement is back on after the migration.
    assert db.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    with pytest.raises(sqlite3.IntegrityError):
        q.record_probe(db, 99999, ok=True)


def test_migration_leaving_fk_violations_is_rejected(db, tmp_path: Path) -> None:
    db_dir = _tmp_db_dir(tmp_path)
    (db_dir / "migrations" / "0002_orphan.sql").write_text(
        "INSERT INTO probes (endpoint_id, ok) VALUES (12345, 1);\n"
    )
    with pytest.raises(sqlite3.IntegrityError, match="foreign key"):
        migrate(db, db_dir=db_dir)
    assert db.execute("PRAGMA user_version").fetchone()[0] == 1
    assert db.execute("SELECT COUNT(*) FROM probes").fetchone()[0] == 0  # rolled back


def test_statements_splits_and_rejects_unterminated() -> None:
    script = (
        "-- header comment\nCREATE TABLE a (x TEXT);\n\n"
        "CREATE TABLE b (\n  y TEXT\n);\n-- trailing comment\n"
    )
    statements = _statements(script)
    assert len(statements) == 2
    assert statements[1].startswith("CREATE TABLE b")
    with pytest.raises(ValueError, match="unterminated"):
        _statements("CREATE TABLE a (x TEXT)")  # no semicolon


def test_utcnow_iso_matches_sql_default_format(db) -> None:
    assert CANONICAL_TS.match(utcnow_iso())
    # The SQL DEFAULT fallback emits the identical shape.
    endpoint_id = db.execute(
        "INSERT INTO endpoints (url, host) VALUES ('https://x.example/', 'x.example')"
    ).lastrowid
    row = db.execute("SELECT first_seen_at FROM endpoints WHERE id = ?", (endpoint_id,)).fetchone()
    assert CANONICAL_TS.match(row["first_seen_at"])


def test_foreign_keys_enforced(db) -> None:
    with pytest.raises(sqlite3.IntegrityError):
        q.record_probe(db, 99999, ok=True)


def test_concurrent_writer_waits_out_busy(db, db_path: Path) -> None:
    # Writer B must succeed (within busy_timeout) once writer A commits,
    # instead of raising 'database is locked'.
    q.upsert_endpoint(db, "https://a.example/")
    other = connect(db_path)
    try:
        other.execute("BEGIN IMMEDIATE")
        other.execute(
            "INSERT INTO endpoints (url, host) VALUES ('https://b.example/', 'b.example')"
        )

        result: dict[str, int] = {}

        def contender() -> None:
            conn = connect(db_path)
            try:
                result["id"] = q.upsert_endpoint(conn, "https://c.example/")
            finally:
                conn.close()

        thread = threading.Thread(target=contender)
        thread.start()
        thread.join(timeout=0.3)
        assert thread.is_alive()  # blocked on A's write lock, not erroring
        other.execute("COMMIT")
        thread.join(timeout=5)
        assert not thread.is_alive()
        assert result["id"] > 0
    finally:
        other.close()


# --- endpoints ------------------------------------------------------------


def test_canonicalize_url() -> None:
    assert q.canonicalize_url("HTTPS://API.Example.COM:443/Data?b=2#frag") == (
        "https://api.example.com/Data?b=2"
    )
    assert q.canonicalize_url("http://example.com:8080") == "http://example.com:8080/"
    assert q.canonicalize_url("https://example.com") == "https://example.com/"
    # Path and query are preserved verbatim.
    assert q.canonicalize_url("https://example.com/data/") == "https://example.com/data/"
    # IDN hosts stay as-is (lowercased), not punycoded — pinned so a later
    # "fix" doesn't silently change stored keys.
    assert q.canonicalize_url("https://BÜCHER.example/") == "https://bücher.example/"


def test_canonicalize_url_ipv6() -> None:
    assert q.canonicalize_url("https://[2001:DB8::1]:8443/pay") == "https://[2001:db8::1]:8443/pay"
    assert q.canonicalize_url("https://[::1]:443/x") == "https://[::1]/x"  # default port stripped
    canonical = q.canonicalize_url("https://[2001:db8::1]:8443/pay")
    assert q.canonicalize_url(canonical) == canonical  # idempotent


def test_canonicalize_url_rejects_garbage() -> None:
    for bad in [
        "https://example.com:99999/",  # port out of range
        "https://example.com:banana/",  # non-numeric port
        "example.com/api",  # no scheme
        "ftp://example.com/x",  # non-http(s) scheme
        "https:///path",  # no host
        "",
        # urlsplit raises bare ValueError on these; the InvalidURLError
        # contract must hold anyway (registries and public callers send them)
        "https://[::1/broken",  # unclosed IPv6 bracket
        "https://℀.example/",  # NFKC-invalid netloc character (℀ -> a/c)
    ]:
        with pytest.raises(q.InvalidURLError):
            q.canonicalize_url(bad)


def test_upsert_endpoint_rejects_invalid_url(db) -> None:
    with pytest.raises(q.InvalidURLError):
        q.upsert_endpoint(db, "example.com/api")
    assert q.list_endpoints(db, enabled_only=False) == []


def test_ipv6_endpoint_roundtrip(db) -> None:
    endpoint_id = q.upsert_endpoint(db, "https://[2001:DB8::1]:8443/pay")
    endpoint = q.get_endpoint(db, "https://[2001:db8::1]:8443/pay")
    assert endpoint["id"] == endpoint_id
    assert endpoint["url"] == "https://[2001:db8::1]:8443/pay"
    assert endpoint["host"] == "2001:db8::1"  # unbracketed, for per-host grouping


def test_upsert_endpoint_dedupes_url_variants(db) -> None:
    first = q.upsert_endpoint(db, "https://api.example.com/data", source="bazaar")
    second = q.upsert_endpoint(db, "HTTPS://api.EXAMPLE.com:443/data#top", source="x402scan")
    assert first == second
    assert len(list(db.execute("SELECT id FROM endpoints"))) == 1


def test_upsert_endpoint_merge_semantics(db) -> None:
    endpoint_id = q.upsert_endpoint(
        db,
        "https://api.example.com/",
        source="bazaar",
        meta={"a": 1},
        now="2026-07-08T00:00:00.000Z",
    )
    q.upsert_endpoint(
        db, "https://api.example.com/", source="x402scan", now="2026-07-09T00:00:00.000Z"
    )
    q.upsert_endpoint(db, "https://api.example.com/", source="bazaar")  # duplicate source
    endpoint = q.get_endpoint(db, "https://api.example.com/")
    assert endpoint["id"] == endpoint_id
    assert endpoint["sources"] == ["bazaar", "x402scan"]
    assert endpoint["first_seen_at"] == "2026-07-08T00:00:00.000Z"  # first-discoverer wins
    assert endpoint["meta"] == {"a": 1}  # None meta does not clobber
    q.upsert_endpoint(db, "https://api.example.com/", meta={"b": 2})
    assert q.get_endpoint(db, "https://api.example.com/")["meta"] == {"b": 2}


def test_upsert_endpoint_source_meta_merges_namespaces(db) -> None:
    q.upsert_endpoint(db, "https://api.example.com/", source="bazaar", source_meta={"n": "A"})
    q.upsert_endpoint(db, "https://api.example.com/", source="x402-list", source_meta={"n": "B"})
    # replacing one namespace leaves the others intact
    q.upsert_endpoint(db, "https://api.example.com/", source="bazaar", source_meta={"n": "A2"})
    # a plain upsert with no meta clobbers nothing
    q.upsert_endpoint(db, "https://api.example.com/", source="preflight")
    endpoint = q.get_endpoint(db, "https://api.example.com/")
    assert endpoint["meta"] == {"bazaar": {"n": "A2"}, "x402-list": {"n": "B"}}
    assert endpoint["sources"] == ["bazaar", "x402-list", "preflight"]


def test_upsert_endpoint_source_meta_survives_non_dict_meta(db) -> None:
    q.upsert_endpoint(db, "https://api.example.com/", meta={"legacy": True})
    q.upsert_endpoint(db, "https://api.example.com/", source="bazaar", source_meta={"n": "A"})
    # namespaced merge starts from the existing dict, keeping foreign keys
    assert q.get_endpoint(db, "https://api.example.com/")["meta"] == {
        "legacy": True,
        "bazaar": {"n": "A"},
    }


def test_upsert_endpoint_source_meta_argument_contract(db) -> None:
    with pytest.raises(ValueError, match="requires source"):
        q.upsert_endpoint(db, "https://api.example.com/", source_meta={"n": "A"})
    with pytest.raises(ValueError, match="mutually exclusive"):
        q.upsert_endpoint(
            db, "https://api.example.com/", source="bazaar", meta={"a": 1}, source_meta={"n": "A"}
        )
    assert q.list_endpoints(db, enabled_only=False) == []


def test_endpoints_due_by_host_caps_each_hosts_share(db) -> None:
    for i in range(4):
        q.upsert_endpoint(db, f"https://big.example/e{i}")
    q.upsert_endpoint(db, "https://small.example/only")
    due = q.endpoints_due_by_host(
        db, before="2026-07-17T00:00:00.000Z", per_host_limit=2, limit=100
    )
    hosts = [row["host"] for row in due]
    assert hosts.count("big.example") == 2
    assert hosts.count("small.example") == 1
    assert all("rn" not in row for row in due)


def test_endpoints_due_by_host_prefers_never_probed_then_oldest(db) -> None:
    fresh = q.upsert_endpoint(db, "https://h.example/fresh")
    stale = q.upsert_endpoint(db, "https://h.example/stale")
    never = q.upsert_endpoint(db, "https://h.example/never")
    q.record_probe(db, fresh, ok=True, now="2026-07-17T09:00:00.000Z")
    q.record_probe(db, stale, ok=True, now="2026-07-16T09:00:00.000Z")
    due = q.endpoints_due_by_host(
        db, before="2026-07-17T08:00:00.000Z", per_host_limit=1, limit=100
    )
    # per-host winner is the never-probed endpoint; the freshly-probed one is
    # not due at all
    assert [row["id"] for row in due] == [never]
    due_two = q.endpoints_due_by_host(
        db, before="2026-07-17T08:00:00.000Z", per_host_limit=2, limit=100
    )
    assert [row["id"] for row in due_two] == [never, stale]


def test_endpoints_due_by_host_excludes_disabled(db) -> None:
    endpoint_id = q.upsert_endpoint(db, "https://off.example/x")
    q.set_endpoint_enabled(db, endpoint_id, False)
    assert (
        q.endpoints_due_by_host(db, before="2026-07-17T00:00:00.000Z", per_host_limit=5, limit=100)
        == []
    )


def test_get_endpoint_missing_returns_none(db) -> None:
    assert q.get_endpoint(db, "https://nowhere.example/") is None


def test_endpoints_due_ordering_and_filters(db) -> None:
    never = q.upsert_endpoint(db, "https://never.example/")
    stale = q.upsert_endpoint(db, "https://stale.example/")
    fresh = q.upsert_endpoint(db, "https://fresh.example/")
    disabled = q.upsert_endpoint(db, "https://disabled.example/")
    q.record_probe(db, stale, ok=True, now="2026-07-08T00:00:00.000Z")
    q.record_probe(db, fresh, ok=True, now="2026-07-08T12:00:00.000Z")
    q.set_endpoint_enabled(db, disabled, False)

    due = q.endpoints_due(db, before="2026-07-08T06:00:00.000Z", limit=10)
    assert [e["id"] for e in due] == [never, stale]  # never-probed first, fresh/disabled excluded
    assert [e["id"] for e in q.endpoints_due(db, before="2026-07-08T06:00:00.000Z", limit=1)] == [
        never
    ]


def test_set_endpoint_enabled(db) -> None:
    endpoint_id = q.upsert_endpoint(db, "https://api.example.com/")
    q.set_endpoint_enabled(db, endpoint_id, False)
    assert q.list_endpoints(db) == []
    assert q.list_endpoints(db, enabled_only=False)[0]["enabled"] == 0
    q.set_endpoint_enabled(db, endpoint_id, True)
    assert len(q.list_endpoints(db)) == 1


# --- probes ---------------------------------------------------------------


def test_record_probe_roundtrip(db) -> None:
    endpoint_id = q.upsert_endpoint(db, "https://api.example.com/")
    payment = {"pay_to": "0xABC", "price": {"amount": "1000", "décimals": 6}, "note": "ünïcodé"}
    probe_id = q.record_probe(
        db,
        endpoint_id,
        ok=True,
        http_status=402,
        latency_ms=234.5,
        tls_valid=True,
        tls_expires_at="2026-09-01T00:00:00.000Z",
        tls_issuer="Let's Encrypt",
        is_402=True,
        protocol="x402-v2",
        spec_compliant=True,
        warnings=[],
        payment=payment,
    )
    (probe,) = q.latest_probes(db, endpoint_id)
    assert probe["id"] == probe_id
    assert probe["ok"] == 1
    assert probe["http_status"] == 402
    assert probe["payment"] == payment  # nested unicode survives the JSON boundary
    assert probe["warnings"] == []  # [] round-trips as [], distinct from None
    assert probe["error"] is None

    failed = q.record_probe(db, endpoint_id, ok=False, error="timeout")
    probe = q.latest_probes(db, endpoint_id)[0]
    assert probe["id"] == failed
    assert probe["warnings"] is None


def test_record_probe_updates_last_probed_at_atomically(db, monkeypatch) -> None:
    endpoint_id = q.upsert_endpoint(db, "https://api.example.com/")
    # A strictly-increasing fake clock: if record_probe read the clock twice
    # (once per statement) instead of once, the timestamps would differ every
    # run — the real clock only catches that when the reads straddle a
    # millisecond boundary.
    ticks = (f"2026-07-08T00:00:00.{i:03d}Z" for i in range(1000))
    monkeypatch.setattr(q, "utcnow_iso", lambda: next(ticks))
    q.record_probe(db, endpoint_id, ok=True)
    (probe,) = q.latest_probes(db, endpoint_id)
    endpoint = q.get_endpoint(db, "https://api.example.com/")
    assert endpoint["last_probed_at"] == probe["probed_at"]  # exact match, single timestamp


def test_latest_probes_and_probes_since(db) -> None:
    endpoint_id = q.upsert_endpoint(db, "https://api.example.com/")
    times = [
        "2026-07-08T00:00:00.000Z",
        "2026-07-08T01:00:00.000Z",
        "2026-07-08T02:00:00.000Z",
    ]
    ids = [q.record_probe(db, endpoint_id, ok=True, now=t) for t in times]

    latest = q.latest_probes(db, endpoint_id, limit=2)
    assert [p["id"] for p in latest] == [ids[2], ids[1]]

    since = q.probes_since(db, endpoint_id, "2026-07-08T01:00:00.000Z")
    assert [p["id"] for p in since] == [ids[1], ids[2]]  # inclusive lower bound


def test_delete_endpoint_cascades(db) -> None:
    endpoint_id = q.upsert_endpoint(db, "https://api.example.com/")
    q.record_probe(db, endpoint_id, ok=True)
    q.upsert_rollup(db, endpoint_id, "24h", probe_count=1)
    db.execute("DELETE FROM endpoints WHERE id = ?", (endpoint_id,))
    assert q.latest_probes(db, endpoint_id) == []
    assert q.get_rollups(db, endpoint_id) == {}


# --- rollups ----------------------------------------------------------------


def test_rollup_upsert_overwrites(db) -> None:
    endpoint_id = q.upsert_endpoint(db, "https://api.example.com/")
    q.upsert_rollup(
        db,
        endpoint_id,
        "7d",
        probe_count=100,
        uptime_pct=99.0,
        p50_ms=210.0,
        p90_ms=800.0,
        p99_ms=1450.0,
        status_counts={"402": 99, "500": 1},
        computed_at="2026-07-08T00:00:00.000Z",
    )
    q.upsert_rollup(
        db,
        endpoint_id,
        "7d",
        probe_count=101,
        uptime_pct=99.2,
        status_counts={"402": 101},
        computed_at="2026-07-08T01:00:00.000Z",
    )
    rollups = q.get_rollups(db, endpoint_id)
    assert set(rollups) == {"7d"}
    assert rollups["7d"]["probe_count"] == 101
    assert rollups["7d"]["status_counts"] == {"402": 101}
    assert rollups["7d"]["p50_ms"] is None  # overwrite, not merge


def test_rollup_rejects_unknown_period(db) -> None:
    endpoint_id = q.upsert_endpoint(db, "https://api.example.com/")
    with pytest.raises(sqlite3.IntegrityError):
        q.upsert_rollup(db, endpoint_id, "90d", probe_count=1)


# --- verdict cache -----------------------------------------------------------


def test_verdict_roundtrip_and_expiry(db) -> None:
    verdict = {"schema": "trust-preview.v1", "verdict": {"recommendation": "proceed"}}
    # put with a non-canonical spelling, get with the canonical one — both
    # sides must canonicalize for variants to share a cache entry.
    q.put_verdict(
        db,
        "HTTPS://api.EXAMPLE.com:443/",
        "preflight",
        verdict,
        ttl_seconds=300,
        now="2026-07-08T00:00:00.000Z",
    )
    hit = q.get_verdict(db, "https://api.example.com/", "preflight", now="2026-07-08T00:04:59.000Z")
    assert hit["verdict"] == verdict
    assert hit["expires_at"] == "2026-07-08T00:05:00.000Z"
    q.put_verdict(
        db,
        "https://API.example.com/",
        "preflight",
        {"v": 2},
        ttl_seconds=300,
        now="2026-07-08T00:01:00.000Z",
    )
    assert db.execute("SELECT COUNT(*) FROM verdict_cache").fetchone()[0] == 1  # upsert, not add
    assert (
        q.get_verdict(db, "https://api.example.com/", "preflight", now="2026-07-08T00:06:00.000Z")
        is None
    )  # expires_at itself is expired
    # An unexpired row for another tier must not leak through the tier filter.
    assert (
        q.get_verdict(db, "https://api.example.com/", "deep_report", now="2026-07-08T00:02:00.000Z")
        is None
    )


def test_verdict_tiers_are_independent_and_upsert_overwrites(db) -> None:
    url = "https://api.example.com/"
    q.put_verdict(db, url, "preflight", {"v": 1}, ttl_seconds=300, now="2026-07-08T00:00:00.000Z")
    q.put_verdict(db, url, "deep_report", {"v": 2}, ttl_seconds=300, now="2026-07-08T00:00:00.000Z")
    q.put_verdict(db, url, "preflight", {"v": 3}, ttl_seconds=300, now="2026-07-08T00:01:00.000Z")
    at = "2026-07-08T00:02:00.000Z"
    assert q.get_verdict(db, url, "preflight", now=at)["verdict"] == {"v": 3}
    assert q.get_verdict(db, url, "deep_report", now=at)["verdict"] == {"v": 2}
    assert db.execute("SELECT COUNT(*) FROM verdict_cache").fetchone()[0] == 2


def test_verdict_rejects_unknown_tier(db) -> None:
    with pytest.raises(sqlite3.IntegrityError):
        q.put_verdict(db, "https://api.example.com/", "free", {}, ttl_seconds=1)


def test_purge_expired_verdicts(db) -> None:
    q.put_verdict(
        db, "https://a.example/", "preflight", {}, ttl_seconds=300, now="2026-07-08T00:00:00.000Z"
    )
    q.put_verdict(
        db, "https://b.example/", "preflight", {}, ttl_seconds=300, now="2026-07-08T01:00:00.000Z"
    )
    assert q.purge_expired_verdicts(db, now="2026-07-08T00:30:00.000Z") == 1
    remaining = [
        row["endpoint_url"] for row in db.execute("SELECT endpoint_url FROM verdict_cache")
    ]
    assert remaining == ["https://b.example/"]


# --- transaction helper --------------------------------------------------------


def test_transaction_rolls_back_on_error(db) -> None:
    q.upsert_endpoint(db, "https://api.example.com/")
    with pytest.raises(RuntimeError), transaction(db):
        db.execute("UPDATE endpoints SET host = 'changed'")
        raise RuntimeError("boom")
    assert not db.in_transaction
    assert q.get_endpoint(db, "https://api.example.com/")["host"] == "api.example.com"
