import ipaddress

import pytest

from preflight402.probe import guard
from preflight402.probe.guard import BlockedTargetError, is_public_ip, resolve_and_validate

pytestmark = pytest.mark.anyio

BLOCKED = [
    "127.0.0.1",  # loopback
    "10.0.0.5",  # RFC1918
    "172.16.9.9",  # RFC1918
    "192.168.50.1",  # RFC1918 (the LAN gateway)
    "169.254.169.254",  # link-local / cloud metadata
    "0.0.0.0",  # unspecified
    "::1",  # IPv6 loopback
    "fc00::1",  # IPv6 unique-local
    "fe80::1",  # IPv6 link-local
    "::ffff:10.0.0.1",  # IPv4-mapped private — must not smuggle past
]
PUBLIC = ["8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700:4700::1111"]


@pytest.mark.parametrize("addr", BLOCKED)
def test_blocked_addresses_are_not_public(addr: str) -> None:
    assert is_public_ip(ipaddress.ip_address(addr)) is False


@pytest.mark.parametrize("addr", PUBLIC)
def test_public_addresses_are_public(addr: str) -> None:
    assert is_public_ip(ipaddress.ip_address(addr)) is True


@pytest.mark.parametrize("addr", BLOCKED)
async def test_resolve_and_validate_blocks_literal_ips(addr: str) -> None:
    # Literal IPs need no DNS; getaddrinfo returns the address itself.
    with pytest.raises(BlockedTargetError):
        await resolve_and_validate(addr, 443, allow_private=False)


async def test_resolve_and_validate_returns_the_pin_ip() -> None:
    # A public literal validates and comes back as the address to pin to.
    assert await resolve_and_validate("1.1.1.1", 443, allow_private=False) == "1.1.1.1"


async def test_allow_private_bypasses_the_guard() -> None:
    # No pin in dev mode (connection resolves normally).
    assert await resolve_and_validate("127.0.0.1", 443, allow_private=True) is None


async def test_unresolvable_host_is_left_to_the_prober() -> None:
    # A name that doesn't resolve is a DNS error the prober classifies, not a
    # block — the guard must not raise, and returns no pin.
    assert await resolve_and_validate("nonexistent.invalid", 443, allow_private=False) is None


async def test_hostname_resolving_to_private_is_blocked(monkeypatch) -> None:
    # DNS-rebinding-style: a public-looking name that resolves to a LAN IP.
    async def fake_getaddrinfo(host, port, **kwargs):
        return [(2, 1, 6, "", ("192.168.50.10", port))]

    monkeypatch.setattr(guard.asyncio.get_running_loop(), "getaddrinfo", fake_getaddrinfo)
    with pytest.raises(BlockedTargetError):
        await resolve_and_validate("internal.evil.example", 443, allow_private=False)


async def test_any_private_record_blocks_even_beside_a_public_one(monkeypatch) -> None:
    async def fake_getaddrinfo(host, port, **kwargs):
        return [
            (2, 1, 6, "", ("8.8.8.8", port)),
            (2, 1, 6, "", ("127.0.0.1", port)),
        ]

    monkeypatch.setattr(guard.asyncio.get_running_loop(), "getaddrinfo", fake_getaddrinfo)
    with pytest.raises(BlockedTargetError):
        await resolve_and_validate("mixed.example", 443, allow_private=False)
