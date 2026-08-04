import pytest
from fastapi.testclient import TestClient
from starlette.requests import Request

from preflight402 import service
from preflight402.api import rest
from preflight402.api.ratelimit import RateLimiter, client_ip
from preflight402.config import Settings
from preflight402.probe.prober import ProbeResult
from preflight402.probe.tls import TLSInfo

# --- token bucket logic ---------------------------------------------------


def test_burst_then_limited() -> None:
    limiter = RateLimiter(per_minute=60, burst=5)
    t = 1000.0
    allowed = [limiter.allow("ip", now=t) for _ in range(7)]
    assert allowed == [True, True, True, True, True, False, False]


def test_refills_over_time() -> None:
    limiter = RateLimiter(per_minute=60, burst=5)  # 1 token/sec
    t = 0.0
    for _ in range(5):
        assert limiter.allow("ip", now=t)
    assert not limiter.allow("ip", now=t)
    assert not limiter.allow("ip", now=t + 0.5)  # <1 token refilled
    assert limiter.allow("ip", now=t + 1.0)  # one second -> one token
    assert not limiter.allow("ip", now=t + 1.0)


def test_never_exceeds_capacity() -> None:
    limiter = RateLimiter(per_minute=60, burst=5)
    # idle a long time — tokens cap at capacity, not unbounded
    assert all(limiter.allow("ip", now=10_000.0) for _ in range(5))
    assert not limiter.allow("ip", now=10_000.0)


def test_keys_are_independent() -> None:
    limiter = RateLimiter(per_minute=60, burst=2)
    assert limiter.allow("a", now=0) and limiter.allow("a", now=0)
    assert not limiter.allow("a", now=0)
    assert limiter.allow("b", now=0)  # b has its own bucket


def test_idle_buckets_are_swept() -> None:
    from preflight402.api import ratelimit

    limiter = RateLimiter(per_minute=6000, burst=1)  # refills fast
    # drive past the sweep threshold with distinct idle keys
    for i in range(ratelimit._SWEEP_THRESHOLD + 100):
        limiter.allow(f"ip{i}", now=1.0)
    # by the time we add the last, earlier full buckets get dropped
    assert len(limiter._buckets) <= ratelimit._SWEEP_THRESHOLD


def test_disabled_when_zero_is_handled_by_caller() -> None:
    # The limiter itself always limits; the 0-disables policy lives in the
    # rate_limit dependency (tested below).
    limiter = RateLimiter(per_minute=1, burst=1)
    assert limiter.allow("x", now=0)
    assert not limiter.allow("x", now=0)


# --- client IP extraction --------------------------------------------------


def _request(headers: dict[str, str], peer: str | None = "9.9.9.9") -> Request:
    scope = {
        "type": "http",
        "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()],
        "client": (peer, 12345) if peer else None,
    }
    return Request(scope)


def test_client_ip_prefers_cf_connecting_ip() -> None:
    assert client_ip(_request({"cf-connecting-ip": "1.2.3.4"})) == "1.2.3.4"


def test_client_ip_takes_first_of_list() -> None:
    assert client_ip(_request({"cf-connecting-ip": "1.2.3.4, 5.6.7.8"})) == "1.2.3.4"


def test_client_ip_falls_back_to_peer() -> None:
    assert client_ip(_request({}, peer="8.8.8.8")) == "8.8.8.8"
    assert client_ip(_request({}, peer=None)) == "unknown"


# --- endpoint integration --------------------------------------------------


GOOD_TLS = TLSInfo(valid=True, expires_at="2027-01-01T00:00:00.000Z", issuer="LE")


@pytest.fixture
def limited_client(tmp_path, monkeypatch):
    monkeypatch.setattr(
        rest,
        "settings",
        Settings(
            _env_file=None,
            db_path=tmp_path / "rl.db",
            allow_private_targets=True,
            rate_limit_per_minute=180,  # burst = 180... override with a small limiter
        ),
    )
    monkeypatch.setattr(rest, "_limiter", RateLimiter(per_minute=60, burst=3))
    service.ensure_migrated.cache_clear()

    async def fake_probe(url, *, timeout_s=10.0, pinned_ip=None, enforce_pin=False, **_):
        return ProbeResult(
            url=url,
            ok=True,
            http_status=200,
            headers={},
            body="hi",
            latency_ms=10.0,
            tls=GOOD_TLS,
        )

    monkeypatch.setattr(service, "probe", fake_probe)
    return TestClient(rest.app)


def test_preflight_429_after_burst(limited_client) -> None:
    ok = [
        limited_client.get("/preflight", params={"url": f"https://ex{i}.example/"}).status_code
        for i in range(3)
    ]
    assert ok == [200, 200, 200]
    limited = limited_client.get("/preflight", params={"url": "https://ex9.example/"})
    assert limited.status_code == 429
    assert limited.headers["retry-after"] == "60"


def test_rate_limit_is_per_client_ip(limited_client) -> None:
    # exhaust one IP
    for i in range(3):
        limited_client.get(
            "/preflight",
            params={"url": f"https://a{i}.example/"},
            headers={"cf-connecting-ip": "1.1.1.1"},
        )
    assert (
        limited_client.get(
            "/preflight",
            params={"url": "https://a.example/"},
            headers={"cf-connecting-ip": "1.1.1.1"},
        ).status_code
        == 429
    )
    # a different IP is unaffected
    assert (
        limited_client.get(
            "/preflight",
            params={"url": "https://b.example/"},
            headers={"cf-connecting-ip": "2.2.2.2"},
        ).status_code
        == 200
    )


def test_healthz_is_not_rate_limited(limited_client) -> None:
    for _ in range(10):
        assert limited_client.get("/healthz").status_code == 200


def test_rate_limit_zero_disables(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(
        rest,
        "settings",
        Settings(
            _env_file=None,
            db_path=tmp_path / "off.db",
            allow_private_targets=True,
            rate_limit_per_minute=0,  # disabled
        ),
    )
    monkeypatch.setattr(rest, "_limiter", RateLimiter(per_minute=60, burst=1))

    async def fake_probe(url, *, timeout_s=10.0, pinned_ip=None, enforce_pin=False, **_):
        return ProbeResult(
            url=url,
            ok=True,
            http_status=200,
            headers={},
            body="hi",
            latency_ms=10.0,
            tls=GOOD_TLS,
        )

    monkeypatch.setattr(service, "probe", fake_probe)
    service.ensure_migrated.cache_clear()
    client = TestClient(rest.app)
    # even well past burst=1, nothing is limited when the rate is 0
    codes = [
        client.get("/preflight", params={"url": f"https://z{i}.example/"}).status_code
        for i in range(5)
    ]
    assert codes == [200, 200, 200, 200, 200]
