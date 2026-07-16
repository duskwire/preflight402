"""SSRF guard: refuse to probe non-public targets.

`/preflight` fetches any URL the caller supplies and returns liveness, headers,
and body-derived signals. Once the service is reachable from the internet that
is an SSRF primitive — a caller could point it at the host's own LAN
(192.168.x.x), loopback, or the cloud-metadata endpoint (169.254.169.254) and
read the response. This module blocks that at the untrusted-input boundary
(service.get_preflight); local development can opt back in with
PREFLIGHT402_ALLOW_PRIVATE_TARGETS=true.

Scope note: this validates the addresses a host resolves to *now*. A hostname
that resolves to a public IP here but a private one microseconds later at
connect time (DNS rebinding) is not fully closed — pinning the probe to the
validated IP is a tracked hardening follow-up. The common case (a caller
naming a private IP or an internal hostname directly) is closed.
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


async def assert_public_host(host: str, port: int, *, allow_private: bool = False) -> None:
    """Resolve `host` and raise BlockedTargetError if any address is non-public.

    Every resolved address must be public — a host that resolves to both a
    public and a private address is rejected (the private one is the danger).
    Resolution failures are left to the prober to classify as a normal DNS
    error, so this only raises for the block case.
    """
    if allow_private:
        return
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(
            host, port, type=socket.SOCK_STREAM
        )
    except socket.gaierror:
        return  # not resolvable — the prober will report this as a dns error
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if not is_public_ip(ip):
            raise BlockedTargetError(
                f"refusing to probe {host!r}: resolves to non-public address {ip}"
            )
