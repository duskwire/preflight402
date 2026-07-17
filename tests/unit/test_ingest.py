"""Seed ingesters: source pagination/filtering and shared runner policy."""

from __future__ import annotations

from types import SimpleNamespace

import httpx
import pytest
import respx

from preflight402.config import Settings
from preflight402.db import connect, queries
from preflight402.ingest import agentic_market, bazaar, run_ingest, x402_list
from preflight402.ingest.types import SeedRecord

pytestmark = pytest.mark.anyio


@pytest.fixture
def settings(tmp_path) -> Settings:
    return Settings(db_path=tmp_path / "ingest-test.db")


@pytest.fixture(autouse=True)
def _no_crawl_delays(monkeypatch) -> None:
    """Politeness sleeps are real-network behavior; tests must not pay them."""
    monkeypatch.setattr(bazaar, "PAGE_DELAY_S", 0)
    monkeypatch.setattr(agentic_market, "PAGE_DELAY_S", 0)
    monkeypatch.setattr(x402_list, "PAGE_DELAY_S", 0)
    monkeypatch.setattr(x402_list, "DETAIL_DELAY_S", 0)


def fake_source(name: str, *records_or_exc):
    """A stand-in source module yielding the given records, raising exceptions."""

    async def records(client, *, max_records=None):
        for item in records_or_exc:
            if isinstance(item, BaseException):
                raise item
            yield item

    return SimpleNamespace(SOURCE=name, records=records)


def stored_urls(settings) -> list[str]:
    conn = connect(settings.db_path)
    try:
        return sorted(row["url"] for row in queries.list_endpoints(conn))
    finally:
        conn.close()


def bazaar_item(url, *, type_: str = "http", name: str | None = "svc") -> dict:
    item = {"resource": url, "type": type_, "accepts": []}
    if name:
        item["serviceName"] = name
    return item


def mock_bazaar(pages: list[list], total) -> None:
    def respond(request: httpx.Request) -> httpx.Response:
        offset = int(request.url.params["offset"])
        served = 0
        for page in pages:
            if offset == served:
                return httpx.Response(
                    200,
                    json={
                        "items": page,
                        "pagination": {"limit": 100, "offset": offset, "total": total},
                    },
                )
            served += len(page)
        return httpx.Response(200, json={"items": [], "pagination": {"total": total}})

    respx.get(bazaar.BASE_URL).mock(side_effect=respond)


# --- bazaar ------------------------------------------------------------------


@respx.mock
async def test_bazaar_paginates_and_filters(settings) -> None:
    mock_bazaar(
        [
            [
                bazaar_item("https://a.example/pay"),
                bazaar_item("https://mcp.example/tool", type_="mcp"),
                bazaar_item("ipfs://bafy-not-http"),  # http type, non-http URL
                bazaar_item("https://t.example/u/:id/data"),
            ],
            [bazaar_item("https://b.example/{slot}/x"), bazaar_item("https://a.example/pay/")],
        ],
        total=6,
    )
    report = await run_ingest(settings, sources=(bazaar,))

    (source_report,) = report.sources
    assert source_report.error is None
    # the mcp-typed and non-http-URL items are never yielded; both template
    # shapes are skipped downstream
    assert source_report.fetched == 4
    assert source_report.skipped_template == 2
    assert source_report.skipped_invalid == 0
    assert source_report.seeded == 2
    # trailing slash makes /pay/ a distinct resource from /pay
    assert report.new_endpoints == 2

    conn = connect(settings.db_path)
    try:
        row = queries.get_endpoint(conn, "https://a.example/pay")
        assert row["sources"] == ["bazaar"]
        assert row["meta"] == {"bazaar": {"serviceName": "svc"}}
    finally:
        conn.close()


@respx.mock
async def test_bazaar_skips_junk_item_shapes(settings) -> None:
    mock_bazaar(
        [["not-a-dict", bazaar_item(123), bazaar_item(None), bazaar_item("https://ok.example/p")]],
        total=4,
    )
    report = await run_ingest(settings, sources=(bazaar,))
    (source_report,) = report.sources
    assert source_report.error is None
    assert source_report.fetched == 1
    assert source_report.seeded == 1


@respx.mock
async def test_bazaar_terminates_on_repeating_page_with_junk_total(settings, monkeypatch) -> None:
    monkeypatch.setattr(bazaar, "MAX_PAGES", 3)
    calls = 0

    def same_page_forever(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(
            200,
            json={
                "items": [bazaar_item("https://loop.example/p")],
                "pagination": {"total": "junk"},
            },
        )

    respx.get(bazaar.BASE_URL).mock(side_effect=same_page_forever)
    report = await run_ingest(settings, sources=(bazaar,))
    (source_report,) = report.sources
    assert source_report.error is None
    assert calls == 3  # hard page cap, not an infinite loop
    assert source_report.fetched == 3


# --- agentic.market ----------------------------------------------------------


@respx.mock
async def test_agentic_market_flattens_service_endpoints(settings) -> None:
    respx.get(agentic_market.BASE_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "services": [
                    {
                        "id": "svc-a",
                        "name": "Svc A",
                        "category": "Search",
                        "endpoints": [
                            {"url": "https://a.example/one"},
                            {"url": "https://a.example/two"},
                            {"url": "ipfs://not-http"},
                            {"url": 42},
                            "junk-endpoint",
                        ],
                    },
                    {"id": "svc-b", "name": "No Endpoints"},
                    {"id": "svc-c", "name": "Junk Endpoints", "endpoints": "nope"},
                ],
                "total": 3,
                "limit": 100,
                "offset": 0,
            },
        )
    )
    report = await run_ingest(settings, sources=(agentic_market,))

    (source_report,) = report.sources
    assert source_report.error is None
    assert source_report.fetched == 2
    assert source_report.seeded == 2
    conn = connect(settings.db_path)
    try:
        row = queries.get_endpoint(conn, "https://a.example/one")
        assert row["meta"] == {"agentic.market": {"service": "Svc A", "category": "Search"}}
    finally:
        conn.close()


# --- x402-list ---------------------------------------------------------------


@respx.mock
async def test_x402_list_joins_detail_paths_and_falls_back(settings, monkeypatch) -> None:
    monkeypatch.setattr(x402_list, "DETAIL_DELAY_S", 0)
    respx.get(x402_list.BASE_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "data": [
                    {"slug": "good", "name": "Good", "base_url": "https://g.example/api/"},
                    {"slug": "flaky", "name": "Flaky", "base_url": "https://f.example"},
                    {"slug": "no-base", "name": "Junk", "base_url": 42},
                ],
                "meta": {"total": 3, "page": 1, "per_page": 100, "total_pages": 1},
            },
        )
    )
    respx.get(f"{x402_list.BASE_URL}/good").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {
                    "endpoints": [
                        {"path": "/quote", "is_active": True},
                        {"path": "trade", "is_active": False},
                        {"path": 7},
                        "junk",
                    ]
                }
            },
        )
    )
    respx.get(f"{x402_list.BASE_URL}/flaky").mock(return_value=httpx.Response(500))
    report = await run_ingest(settings, sources=(x402_list,))

    (source_report,) = report.sources
    assert source_report.error is None
    assert source_report.seeded == 3
    assert source_report.seeded_fallback == 1  # flaky's base URL
    # '/'-anchored detail paths are root-relative; bare ones join under the
    # base; junk-base services are skipped without a detail fetch (an
    # unmocked detail route would fail this test); inactive endpoints are
    # still seeded (zombie detection wants them); detail failure falls back
    # to the base URL
    assert stored_urls(settings) == [
        "https://f.example/",
        "https://g.example/api/trade",
        "https://g.example/quote",
    ]
    conn = connect(settings.db_path)
    try:
        fallback_row = queries.get_endpoint(conn, "https://f.example")
        assert fallback_row["meta"]["x402-list"]["detail_fallback"] is True
    finally:
        conn.close()


@respx.mock
async def test_x402_list_no_doubling_when_base_url_repeats_in_paths(settings, monkeypatch) -> None:
    """Live shape: base_url carries a full file path, detail paths repeat it."""
    monkeypatch.setattr(x402_list, "DETAIL_DELAY_S", 0)
    respx.get(x402_list.BASE_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "data": [
                    {"slug": "hub", "name": "Hub", "base_url": "https://cat.example/scan.php"}
                ],
                "meta": {"total_pages": 1},
            },
        )
    )
    respx.get(f"{x402_list.BASE_URL}/hub").mock(
        return_value=httpx.Response(
            200,
            json={"data": {"endpoints": [{"path": "/scan.php"}, {"path": "/audit.php"}]}},
        )
    )
    report = await run_ingest(settings, sources=(x402_list,))
    assert report.sources[0].error is None
    assert stored_urls(settings) == [
        "https://cat.example/audit.php",
        "https://cat.example/scan.php",
    ]


@respx.mock
async def test_x402_list_junk_detail_shape_falls_back(settings, monkeypatch) -> None:
    monkeypatch.setattr(x402_list, "DETAIL_DELAY_S", 0)
    respx.get(x402_list.BASE_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "data": [{"slug": "odd", "name": "Odd", "base_url": "https://o.example"}],
                "meta": {"total_pages": 1},
            },
        )
    )
    # endpoints as bare strings — a junk shape must degrade to the fallback,
    # not raise
    respx.get(f"{x402_list.BASE_URL}/odd").mock(
        return_value=httpx.Response(200, json={"data": {"endpoints": "junk"}})
    )
    report = await run_ingest(settings, sources=(x402_list,))
    (source_report,) = report.sources
    assert source_report.error is None
    assert source_report.seeded == 1
    assert source_report.seeded_fallback == 1
    assert stored_urls(settings) == ["https://o.example/"]


@respx.mock
async def test_x402_list_quotes_hostile_slugs(settings, monkeypatch) -> None:
    monkeypatch.setattr(x402_list, "DETAIL_DELAY_S", 0)
    respx.get(x402_list.BASE_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "data": [{"slug": "a/../b c", "name": "Hostile", "base_url": "https://h.example"}],
                "meta": {"total_pages": 1},
            },
        )
    )
    detail = respx.get(f"{x402_list.BASE_URL}/a%2F..%2Fb%20c").mock(
        return_value=httpx.Response(404)
    )
    report = await run_ingest(settings, sources=(x402_list,))
    (source_report,) = report.sources
    assert source_report.error is None
    assert detail.called  # the slug was percent-encoded, not spliced raw
    assert source_report.seeded_fallback == 1


# --- shared runner policy ----------------------------------------------------


@pytest.mark.parametrize("module", [bazaar, agentic_market, x402_list], ids=lambda m: m.SOURCE)
@respx.mock
async def test_max_records_caps_every_source(settings, monkeypatch, module) -> None:
    mock_bazaar([[bazaar_item(f"https://s{i}.example/p") for i in range(3)]], total=3)
    respx.get(agentic_market.BASE_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "services": [
                    {
                        "id": "s",
                        "name": "S",
                        "endpoints": [{"url": f"https://s{i}.example/p"} for i in range(3)],
                    }
                ],
                "total": 1,
            },
        )
    )
    monkeypatch.setattr(x402_list, "DETAIL_DELAY_S", 0)
    respx.get(x402_list.BASE_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "data": [
                    {"slug": f"s{i}", "base_url": f"https://s{i}.example", "name": f"S{i}"}
                    for i in range(3)
                ],
                "meta": {"total_pages": 1},
            },
        )
    )
    for i in range(3):
        respx.get(f"{x402_list.BASE_URL}/s{i}").mock(
            return_value=httpx.Response(200, json={"data": {"endpoints": [{"path": "/p"}]}})
        )

    report = await run_ingest(settings, sources=(module,), max_records=2)
    assert report.sources[0].fetched == 2
    assert report.new_endpoints == 2


async def test_runner_isolates_a_failing_source(settings) -> None:
    broken = fake_source(
        "broken",
        SeedRecord(url="https://ok.example/pay", source="broken"),
        httpx.ConnectError("bang"),
    )
    good = fake_source("good", SeedRecord(url="https://good.example/pay", source="good"))
    report = await run_ingest(settings, sources=(broken, good))

    broken_report, good_report = report.sources
    assert broken_report.error == "ConnectError: bang"
    assert broken_report.seeded == 1  # partial crawl is recorded
    assert good_report.error is None
    assert good_report.seeded == 1
    assert report.new_endpoints == 2


@pytest.mark.parametrize(
    "exc",
    [AttributeError("'list' object has no attribute 'get'"), TypeError("junk"), KeyError("x")],
    ids=lambda e: type(e).__name__,
)
async def test_runner_isolates_any_exception_shape(settings, exc) -> None:
    """Junk registry JSON raises arbitrary exception types; none may escape."""
    broken = fake_source("broken", exc)
    good = fake_source("good", SeedRecord(url="https://good.example/pay", source="good"))
    report = await run_ingest(settings, sources=(broken, good))

    broken_report, good_report = report.sources
    assert broken_report.error is not None
    assert type(exc).__name__ in broken_report.error
    assert good_report.seeded == 1


@respx.mock
async def test_junk_page_shape_isolates_to_its_source(settings) -> None:
    """A registry answering with a top-level array must not kill the batch."""
    respx.get(bazaar.BASE_URL).mock(return_value=httpx.Response(200, json=[1, 2, 3]))
    respx.get(agentic_market.BASE_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "services": [{"id": "s", "endpoints": [{"url": "https://ok.example/p"}]}],
                "total": 1,
            },
        )
    )
    report = await run_ingest(settings, sources=(bazaar, agentic_market))
    bazaar_report, agentic_report = report.sources
    assert bazaar_report.error is not None
    assert "ValueError" in bazaar_report.error
    assert agentic_report.error is None
    assert agentic_report.seeded == 1


async def test_runner_skips_uncanonicalizable_urls(settings) -> None:
    junky = fake_source(
        "junky",
        SeedRecord(url="https://bad.example:999999/x", source="junky"),
        SeedRecord(url="https://[::1/broken", source="junky"),  # bare urlsplit ValueError shape
        SeedRecord(url="https://fine.example/x", source="junky"),
    )
    report = await run_ingest(settings, sources=(junky,))
    (source_report,) = report.sources
    assert source_report.error is None
    assert source_report.skipped_invalid == 2
    assert source_report.seeded == 1


async def test_template_check_applies_to_path_not_query(settings) -> None:
    src = fake_source(
        "q",
        SeedRecord(url="https://h.example/p?next=/:redirect", source="q"),
        SeedRecord(url="https://h.example/u/:id", source="q"),
    )
    report = await run_ingest(settings, sources=(src,))
    (source_report,) = report.sources
    assert source_report.seeded == 1  # the query-string '/:' is not a template
    assert source_report.skipped_template == 1
    assert stored_urls(settings) == ["https://h.example/p?next=/:redirect"]


async def test_meta_merges_across_sources(settings) -> None:
    url = "https://shared.example/pay"
    report = await run_ingest(
        settings,
        sources=(
            fake_source("first", SeedRecord(url=url, source="first", meta={"service": "A"})),
            fake_source("second", SeedRecord(url=url, source="second", meta={"service": "B"})),
            fake_source("third", SeedRecord(url=url, source="third")),  # no meta: must not clobber
        ),
    )
    assert report.new_endpoints == 1
    conn = connect(settings.db_path)
    try:
        row = queries.get_endpoint(conn, url)
    finally:
        conn.close()
    assert row["sources"] == ["first", "second", "third"]
    assert row["meta"] == {"first": {"service": "A"}, "second": {"service": "B"}}


# --- CLI ---------------------------------------------------------------------


@pytest.fixture
def cli_settings(monkeypatch, tmp_path):
    from preflight402.config import get_settings

    monkeypatch.setenv("PREFLIGHT402_DB_PATH", str(tmp_path / "cli.db"))
    get_settings.cache_clear()
    yield tmp_path / "cli.db"
    get_settings.cache_clear()


@respx.mock
def test_cli_runs_and_reports(cli_settings, capsys) -> None:
    from preflight402.ingest import __main__ as cli

    mock_bazaar([[bazaar_item("https://cli.example/pay")]], total=1)
    exit_code = cli.main(["--source", "bazaar"])

    out = capsys.readouterr().out
    assert exit_code == 0
    assert "bazaar: fetched=1 seeded=1" in out
    assert "endpoints: 0 -> 1 (+1)" in out
    assert cli_settings.stat().st_size > 0


@respx.mock
def test_cli_exits_nonzero_when_every_source_fails(cli_settings, capsys) -> None:
    from preflight402.ingest import __main__ as cli

    respx.get(bazaar.BASE_URL).mock(return_value=httpx.Response(500))
    exit_code = cli.main(["--source", "bazaar"])

    out = capsys.readouterr().out
    assert exit_code == 1
    assert "ERROR=HTTPStatusError" in out


@respx.mock
def test_cli_partial_failure_still_exits_zero(cli_settings, capsys) -> None:
    from preflight402.ingest import __main__ as cli

    respx.get(bazaar.BASE_URL).mock(return_value=httpx.Response(500))
    respx.get(agentic_market.BASE_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "services": [{"id": "s", "endpoints": [{"url": "https://ok.example/p"}]}],
                "total": 1,
            },
        )
    )
    exit_code = cli.main(["--source", "bazaar", "--source", "agentic.market"])

    out = capsys.readouterr().out
    assert exit_code == 0
    assert "ERROR=HTTPStatusError" in out
    assert "agentic.market: fetched=1 seeded=1" in out
