"""SSRF guard: refuse to probe non-public targets.

`/preflight` fetches any URL the caller supplies and returns liveness, headers,
and body-derived signals. Once the service is reachable from the internet that
is an SSRF primitive — a caller could point it at the host's own LAN
(192.168.x.x), loopback, or the cloud-metadata endpoint (169.254.169.254) and
read the response. This module blocks that at the untrusted-input boundary
(service.get_preflight); local development can opt back in with
PREFLIGHT402_ALLOW_PRIVATE_TARGETS=true.

DNS rebinding is closed by returning the validated IP so the caller can pin
the actual connection to it (probe(pinned_ip=...)): the address we checked is
the address we connect to, with no second resolution a hostile DNS server
could swap for a private target between check and connect.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket


class BlockedTargetError(ValueError):
    """The URL resolves to a non-public address we refuse to probe."""


def is_public_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """True only for globally-routable addresses.

    is_global already excludes loopback, RFC1918 private, link-local (incl.
    169.254.169.254 metadata), unique-local, reserved, multicast, and
    unspecified ranges. IPv4-mapped IPv6 (::ffff:10.0.0.1) is unwrapped first
    so it can't smuggle a private v4 address past the check.
    """
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip.is_global


async def resolve_and_validate(host: str, port: int, *, allow_private: bool = False) -> str | None:
    """Resolve `host`, reject any non-public address, return the IP to pin to.

    Every resolved address must be public — a host that resolves to both a
    public and a private address is rejected (the private one is the danger).
    Returns the first resolved address so the caller can pin the connection to
    it, closing DNS rebinding. Returns None when pinning does not apply:
    allow_private is set (dev), or the host did not resolve (left for the
    prober to classify as a DNS error). Only raises for the block case.
    """
    if allow_private:
        return None
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return None  # not resolvable — the prober will report this as a dns error
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if not is_public_ip(ip):
            raise BlockedTargetError(
                f"refusing to probe {host!r}: resolves to non-public address {ip}"
            )
    # Pin to the first address — the same one getaddrinfo/the OS would prefer.
    return infos[0][4][0] if infos else None
