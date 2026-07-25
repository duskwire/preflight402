"""Delivery-report ingestion (M8-delivery Phase A, dark launch).

Accepts crowdsourced delivery outcomes from preflight402-guard and stores them
raw. NOTHING here moves a verdict — Phase A only fills the data pond;
verification (on-chain tx check) and aggregation come in Phases B/C.

The batch body is ATTACKER-WRITABLE (a public POST). Every field is validated
and clamped; a bad report is skipped, never fatal to the batch; the reported
URL is SSRF-guarded before it can create an endpoint row (a report must not be
usable to make us probe a private target, same threat as the M3 ingesters);
verified-tier tx replays collapse via the DB's UNIQUE(endpoint, tx) index.
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from preflight402.db import queries
from preflight402.probe.guard import is_public_ip

logger = logging.getLogger(__name__)

MAX_REPORTS_PER_BATCH = 50
_HEX = set("0123456789abcdef")


def _host_obviously_private(host: str) -> bool:
    """Cheap, resolution-free reject for literal private/loopback/localhost
    hosts. We deliberately do NOT DNS-resolve here — a report ingest must not
    become a 50-lookups-per-batch amplifier. The real backstop is the
    scheduler's probe-time SSRF guard (resolve_and_validate), which pins every
    probe to a validated public IP and writes a 'blocked' row otherwise, so a
    private hostname that slips into the endpoints table is never probed."""
    if not host or host.lower() == "localhost" or host.lower().endswith(".localhost"):
        return True
    literal = host[1:-1] if host.startswith("[") and host.endswith("]") else host
    try:
        ip = ipaddress.ip_address(literal)
    except ValueError:
        return False  # a hostname, not a literal IP — leave to the probe-time guard
    return not is_public_ip(ip)


@dataclass(slots=True)
class IngestResult:
    accepted: int
    skipped: int


def _clean_hex(value: Any, *, length: int | None = None) -> str | None:
    """A 0x-prefixed lowercase hex string, or None. `length` counts hex chars
    after 0x (40 for an address, 64 for a tx hash)."""
    if not isinstance(value, str):
        return None
    text = value.strip().lower()
    if not text.startswith("0x"):
        return None
    body = text[2:]
    if not body or any(c not in _HEX for c in body):
        return None
    if length is not None and len(body) != length:
        return None
    return text


def _clean_str(value: Any, *, maxlen: int) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    return text[:maxlen] if text else None


def _valid_report(report: Any) -> dict[str, Any] | None:
    """Validate + normalize one report dict; None to skip it.

    Anonymous vs verified is decided by the presence of a well-formed tx_hash,
    NOT by the client-asserted `tier` — an anonymous report claiming to be
    verified must not smuggle a tx into the weighted set, and a verified report
    is only ever as trustworthy as its (later-verified) tx.
    """
    if not isinstance(report, dict):
        return None
    url = report.get("url")
    if not isinstance(url, str) or not url:
        return None
    if "delivered" not in report or not isinstance(report["delivered"], bool):
        return None

    tx_hash = _clean_hex(report.get("tx_hash"), length=64)
    fields: dict[str, Any] = {
        "url": url,
        "delivered": report["delivered"],
        "tier": "verified" if tx_hash else "anonymous",
        "outcome": _clean_str(report.get("outcome"), maxlen=64),
        "content_type": _clean_str(report.get("content_type"), maxlen=128),
        "tx_hash": tx_hash,
    }
    status = report.get("http_status")
    if isinstance(status, int) and 100 <= status <= 599:
        fields["http_status"] = status
    latency = report.get("latency_ms")
    if isinstance(latency, (int, float)) and 0 <= latency <= 600_000:
        fields["latency_ms"] = round(float(latency), 1)
    if tx_hash:
        fields["payer"] = _clean_hex(report.get("payer"), length=40)
        fields["amount"] = _clean_str(report.get("amount"), maxlen=80)
        network = _clean_str(report.get("network"), maxlen=64)
        fields["chain_id"] = _chain_id_from_network(network)
    return fields


def _chain_id_from_network(network: str | None) -> int | None:
    """Best-effort CAIP-2 -> EVM chain id (eip155:<n>); None otherwise.

    Range-clamped to a signed 64-bit int: the network string is
    attacker-controlled, and an oversized value would raise OverflowError at
    INSERT into the STRICT INTEGER column and silently drop the whole report.
    """
    if not network:
        return None
    prefix = "eip155:"
    if network.startswith(prefix):
        try:
            value = int(network[len(prefix) :])
        except ValueError:
            return None
        return value if 0 <= value <= 2**63 - 1 else None
    return None


def _strip_url_secrets(url: str) -> str:
    """Drop the query string and any user:pass@ userinfo from a URL, keeping
    scheme+host+path. The client already strips these before reporting, but the
    ingest body is untrusted, so we strip again server-side before persisting —
    a report must never durably record a caller's ?api_key= or basic-auth
    credentials in the shared endpoints table."""
    parts = urlsplit(url)
    host = parts.hostname or ""
    if ":" in host:
        host = f"[{host}]"  # re-bracket IPv6
    if parts.port is not None:
        host = f"{host}:{parts.port}"
    return urlunsplit((parts.scheme, host, parts.path or "/", "", ""))


def ingest_reports(conn, reports: Any, settings) -> IngestResult:
    """Persist a batch of delivery reports. Per-report isolation: one bad or
    hostile report is skipped and logged, never aborts the batch."""
    if not isinstance(reports, list):
        return IngestResult(accepted=0, skipped=0)
    accepted = 0
    skipped = 0
    for raw in reports[:MAX_REPORTS_PER_BATCH]:
        fields = _valid_report(raw)
        if fields is None:
            skipped += 1
            continue
        try:
            # Strip URL secrets BEFORE canonicalizing/persisting (defense in
            # depth; the client strips too), then canonicalize.
            canonical = queries.canonicalize_url(_strip_url_secrets(fields["url"]))
        except (queries.InvalidURLError, ValueError):
            skipped += 1
            continue
        # SSRF guard (cheap, resolution-free): keep an obviously-private literal
        # target out of the endpoints table. Hostname targets are left to the
        # scheduler's probe-time guard, which never probes a non-public host.
        host = urlsplit(canonical).hostname or ""
        if not settings.allow_private_targets and _host_obviously_private(host):
            skipped += 1
            continue
        # A report is pure user assertion (unlike a preflight, we did not probe
        # it). Record the endpoint DISABLED (enabled=False) so an attacker
        # cannot use unauthenticated reports to enqueue arbitrary URLs into the
        # prober — the row exists for the delivery flywheel but never enters the
        # probe queue. Counter + report write share the per-report try so a
        # counter hiccup can't 500 the whole batch.
        try:
            endpoint_id = queries.upsert_endpoint(
                conn, canonical, source="delivery_report", enabled=False
            )
            recorded = queries.record_delivery_report(
                conn,
                endpoint_id,
                delivered=fields["delivered"],
                tier=fields["tier"],
                outcome=fields.get("outcome"),
                http_status=fields.get("http_status"),
                latency_ms=fields.get("latency_ms"),
                content_type=fields.get("content_type"),
                tx_hash=fields.get("tx_hash"),
                payer=fields.get("payer"),
                chain_id=fields.get("chain_id"),
                amount=fields.get("amount"),
            )
            if recorded:
                queries.bump_counter(conn, "delivery_reports")
        except Exception as exc:  # one bad row must not poison the batch
            logger.warning("delivery report ingest failed: %s", exc)
            skipped += 1
            continue
        if recorded:
            accepted += 1
        else:
            skipped += 1  # duplicate tx (replay guard)
    return IngestResult(accepted=accepted, skipped=skipped)
