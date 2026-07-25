"""Delivery-report ingestion (M8 Phase A): hostile-input hardening, tiers,
replay guard, SSRF reject."""

from __future__ import annotations

from pathlib import Path

import pytest

from preflight402.config import Settings
from preflight402.db import connect, migrate
from preflight402.db import queries as q
from preflight402.delivery import ingest_reports

TX = "0x" + "ab" * 32  # 64 hex chars
PAYER = "0x" + "cd" * 20


@pytest.fixture()
def db(tmp_path: Path):
    conn = connect(tmp_path / "test.db")
    migrate(conn)
    yield conn
    conn.close()


def settings(**over) -> Settings:
    return Settings(_env_file=None, **over)


def _rows(db) -> list:
    return db.execute("SELECT * FROM delivery_reports ORDER BY id").fetchall()


def test_anonymous_report_stored_without_settlement_fields(db) -> None:
    result = ingest_reports(
        db, [{"url": "https://api.example.com/x", "delivered": True}], settings()
    )
    assert (result.accepted, result.skipped) == (1, 0)
    row = _rows(db)[0]
    assert row["delivered"] == 1
    assert row["tier"] == "anonymous"
    assert row["tx_hash"] is None and row["payer"] is None


def test_verified_report_carries_settlement(db) -> None:
    result = ingest_reports(
        db,
        [
            {
                "url": "https://api.example.com/x",
                "delivered": False,
                "outcome": "post_payment_error:ConnectError",
                "tx_hash": TX.upper(),  # normalized to lowercase
                "payer": PAYER.upper(),
                "network": "eip155:8453",
                "amount": "10000",
            }
        ],
        settings(),
    )
    assert result.accepted == 1
    row = _rows(db)[0]
    assert row["tier"] == "verified"
    assert row["tx_hash"] == TX  # lowercased
    assert row["payer"] == PAYER
    assert row["chain_id"] == 8453
    assert row["outcome"] == "post_payment_error:ConnectError"
    assert row["verify_status"] == "unverified"  # Phase B verifies later


def test_tier_is_decided_by_tx_not_client_claim(db) -> None:
    # A report claiming tier=verified but with no valid tx must be stored
    # anonymous — it cannot smuggle weight it hasn't earned.
    ingest_reports(
        db,
        [{"url": "https://a.test/x", "delivered": True, "tier": "verified", "tx_hash": "not-hex"}],
        settings(),
    )
    row = _rows(db)[0]
    assert row["tier"] == "anonymous" and row["tx_hash"] is None


def test_replay_guard_dedupes_same_tx(db) -> None:
    report = {"url": "https://a.test/x", "delivered": True, "tx_hash": TX}
    first = ingest_reports(db, [report], settings())
    second = ingest_reports(db, [report], settings())
    assert first.accepted == 1
    assert second.accepted == 0 and second.skipped == 1  # replay blocked
    assert len(_rows(db)) == 1


def test_malformed_reports_are_skipped_not_fatal(db) -> None:
    result = ingest_reports(
        db,
        [
            "not a dict",
            {"delivered": True},  # no url
            {"url": "https://a.test/x"},  # no delivered
            {"url": "https://a.test/y", "delivered": "yes"},  # wrong type
            {"url": "not a url", "delivered": True},  # unparseable url
            {"url": "https://a.test/z", "delivered": True},  # the one good report
        ],
        settings(),
    )
    assert result.accepted == 1
    assert result.skipped == 5
    assert _rows(db)[0]["endpoint_id"] is not None


def test_ssrf_literal_private_targets_are_rejected(db) -> None:
    for url in (
        "http://169.254.169.254/latest/meta-data/",
        "http://127.0.0.1/x",
        "http://192.168.1.10/x",
        "http://localhost/x",
        "http://[::1]/x",
    ):
        result = ingest_reports(db, [{"url": url, "delivered": True}], settings())
        assert result.accepted == 0, url
    assert _rows(db) == []
    # ...but allowed in dev mode
    dev = ingest_reports(
        db, [{"url": "http://127.0.0.1/x", "delivered": True}], settings(allow_private_targets=True)
    )
    assert dev.accepted == 1


def test_batch_cap_and_field_clamping(db) -> None:
    # oversized batch truncated; overlong strings clamped; bad numerics dropped
    big = [{"url": f"https://a.test/{i}", "delivered": True} for i in range(80)]
    result = ingest_reports(db, big, settings())
    assert result.accepted == 50  # MAX_REPORTS_PER_BATCH
    ingest_reports(
        db,
        [
            {
                "url": "https://a.test/clamp",
                "delivered": False,
                "outcome": "x" * 500,
                "http_status": 99999,  # out of range -> dropped
                "latency_ms": -5,  # out of range -> dropped
            }
        ],
        settings(),
    )
    clamped = db.execute(
        "SELECT outcome, http_status, latency_ms FROM delivery_reports WHERE outcome IS NOT NULL"
    ).fetchone()
    assert len(clamped["outcome"]) == 64
    assert clamped["http_status"] is None and clamped["latency_ms"] is None


def test_counter_bumped_only_on_accept(db) -> None:
    ingest_reports(
        db,
        [{"url": "https://a.test/x", "delivered": True}, {"bad": "report"}],
        settings(),
    )
    counters = q.counters_since(db, "1970-01-01")
    assert sum(counters["delivery_reports"].values()) == 1


def test_non_list_body_is_a_noop(db) -> None:
    assert ingest_reports(db, None, settings()).accepted == 0
    assert ingest_reports(db, {"reports": []}, settings()).accepted == 0
    assert _rows(db) == []


def test_endpoints_from_reports_are_created_disabled(db) -> None:
    # A report must not enqueue an attacker-chosen URL into the prober.
    ingest_reports(db, [{"url": "https://attacker.example.com/x", "delivered": True}], settings())
    row = db.execute("SELECT enabled FROM endpoints WHERE host = 'attacker.example.com'").fetchone()
    assert row["enabled"] == 0  # recorded, but never scheduled


def test_server_strips_url_secrets_before_persisting(db) -> None:
    ingest_reports(
        db,
        [
            {"url": "https://api.example.com/d?api_key=SECRET", "delivered": True},
            {"url": "https://user:pw@creds.example.com/d", "delivered": True},
        ],
        settings(),
    )
    urls = [r["url"] for r in db.execute("SELECT url FROM endpoints ORDER BY url")]
    assert "https://api.example.com/d" in urls
    assert not any("SECRET" in u or "pw@" in u for u in urls)


def test_oversized_chain_id_drops_field_not_report(db) -> None:
    # A huge network number must not OverflowError and drop the whole report.
    result = ingest_reports(
        db,
        [
            {
                "url": "https://a.test/x",
                "delivered": True,
                "tx_hash": "0x" + "ab" * 32,
                "network": "eip155:" + "9" * 30,
            }
        ],
        settings(),
    )
    assert result.accepted == 1  # report kept
    row = db.execute("SELECT chain_id, tx_hash FROM delivery_reports").fetchone()
    assert row["chain_id"] is None and row["tx_hash"] is not None  # field dropped, report kept


def test_counter_failure_does_not_poison_batch(db, monkeypatch) -> None:
    # bump_counter now shares the per-report try; a counter hiccup skips the
    # row rather than 500-ing the whole batch.
    import preflight402.delivery as delivery_mod

    real = q.bump_counter
    calls = {"n": 0}

    def flaky(*a, **k):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("counter down")
        return real(*a, **k)

    monkeypatch.setattr(delivery_mod.queries, "bump_counter", flaky)
    result = ingest_reports(
        db,
        [
            {"url": "https://a.test/1", "delivered": True},
            {"url": "https://a.test/2", "delivered": True},
        ],
        settings(),
    )
    # first report's counter fails -> skipped; second succeeds -> accepted
    assert result.accepted == 1 and result.skipped == 1
