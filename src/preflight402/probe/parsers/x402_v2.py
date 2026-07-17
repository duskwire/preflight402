"""Parser for x402 v2 payment-required responses.

Spec (specs/x402-specification-v2.md in x402-foundation/x402): the canonical
wire location is the base64-encoded PAYMENT-REQUIRED response header carrying
{x402Version: 2, resource: ResourceInfo, accepts: PaymentRequirements[]}.
Reality (see tests/golden/x402/): bodies range from faithful duplicates to
'{}' to human-facing prose, some servers still use v1's maxAmountRequired
field name or non-CAIP-2 network ids. The parser is liberal in what it
accepts and records every spec deviation in `warnings`; `spec_compliant`
is simply "no warnings".
"""

from __future__ import annotations

import base64
import binascii
import json
import math
import re
from collections.abc import Mapping
from typing import Any

from preflight402.probe.parsers.types import (
    ATOMIC_AMOUNT,
    ParsedPaymentRequired,
    PaymentOption,
    required_str,
)

HEADER = "payment-required"
KNOWN_SCHEMES = frozenset({"exact", "upto", "batch-settlement"})
# CAIP-2: namespace 3-8 chars [-a-z0-9], reference 1-32 chars [-_a-zA-Z0-9]
_CAIP2 = re.compile(r"^[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}$")


def parse_payment_required(
    headers: Mapping[str, str], body: str | None
) -> ParsedPaymentRequired | None:
    """Parse a v2 payment-required payload from a 402 response.

    Returns None when there is no v2 evidence at all: no PAYMENT-REQUIRED
    header and no v2-shaped JSON body. (v1 bodies and MPP WWW-Authenticate
    challenges are the sibling parsers' jobs.) Never raises on hostile input.
    """
    lowered = {key.lower(): value for key, value in headers.items()}
    warnings: list[str] = []

    header_raw = lowered.get(HEADER)
    payload = _payload_from_header(header_raw, warnings) if header_raw is not None else None
    source = "header"
    if payload is None:
        body_payload = _payload_from_body(body)
        if body_payload is None:
            if header_raw is not None:
                # The header itself is v2 evidence; report it broken rather
                # than pretending the endpoint isn't speaking x402 at all.
                return ParsedPaymentRequired(
                    version=None,
                    source="header",
                    resource_url=None,
                    error=None,
                    warnings=warnings,
                )
            return None
        if body_payload.get("x402Version") == 1:
            # x402 v1 — the sibling parser's job, even when an undecodable
            # PAYMENT-REQUIRED header exists: grading a valid v1 body against
            # v2 rules would spray spurious warnings (detect() re-attaches
            # the broken-header evidence on the v1 result).
            return None
        payload = body_payload
        source = "body"
        if header_raw is None:
            warnings.append("v2 payload in body only; PAYMENT-REQUIRED header missing")

    version = payload.get("x402Version")
    if version is None:
        warnings.append("x402Version missing (required)")
    elif isinstance(version, bool) or version != 2:
        warnings.append(f"x402Version is {version!r}, expected 2")

    resource_url = _resource_url(payload, warnings)
    error = payload.get("error") if isinstance(payload.get("error"), str) else None

    raw_accepts = payload.get("accepts")
    accepts: list[PaymentOption] = []
    if not isinstance(raw_accepts, list) or not raw_accepts:
        warnings.append("accepts missing or empty (required)")
    else:
        for index, entry in enumerate(raw_accepts):
            if not isinstance(entry, dict):
                warnings.append(f"accepts[{index}] is not an object")
                continue
            accepts.append(_parse_accept(entry, index, warnings))

    return ParsedPaymentRequired(
        version=_normalized_version(version),
        source=source,
        resource_url=resource_url,
        error=error,
        accepts=accepts,
        warnings=warnings,
    )


def _normalized_version(version: Any) -> int | None:
    """The spec types x402Version as 'number': accept 2.0, refuse bools."""
    if isinstance(version, bool):
        return None
    if isinstance(version, int):
        return version
    if isinstance(version, float) and version.is_integer():
        return int(version)
    return None


def _payload_from_header(raw: str | None, warnings: list[str]) -> dict[str, Any] | None:
    if raw is None:
        return None
    payload: Any = None
    try:
        payload = json.loads(base64.b64decode(raw, validate=True))
    except (binascii.Error, ValueError, UnicodeDecodeError):
        # Seen in the wild (tests/golden/x402/voidfeed.ai.json): base64 with
        # the trailing '=' padding stripped.
        try:
            padded = raw + "=" * (-len(raw) % 4)
            payload = json.loads(base64.b64decode(padded, validate=True))
            warnings.append("PAYMENT-REQUIRED header base64 lacks padding")
        except (binascii.Error, ValueError, UnicodeDecodeError):
            try:
                payload = json.loads(raw)
                warnings.append("PAYMENT-REQUIRED header is plain JSON; spec requires base64")
            except ValueError:
                warnings.append("PAYMENT-REQUIRED header is not decodable (base64 JSON expected)")
                return None
    if not isinstance(payload, dict):
        warnings.append("PAYMENT-REQUIRED header decodes to a non-object")
        return None
    return payload


def _payload_from_body(body: str | None) -> dict[str, Any] | None:
    if not body:
        return None
    try:
        payload = json.loads(body)
    except ValueError:
        return None
    if not isinstance(payload, dict) or "x402Version" not in payload:
        return None
    return payload


def _resource_url(payload: dict[str, Any], warnings: list[str]) -> str | None:
    resource = payload.get("resource")
    if resource is None:
        warnings.append("resource missing (required)")
        return None
    if isinstance(resource, str):
        warnings.append("resource is a string; spec requires a ResourceInfo object")
        return resource
    if isinstance(resource, dict):
        url = resource.get("url")
        if isinstance(url, str):
            return url
        warnings.append("resource.url missing (required)")
        return None
    warnings.append("resource is neither object nor string")
    return None


def _parse_accept(entry: dict[str, Any], index: int, warnings: list[str]) -> PaymentOption:
    # Every required field warns when absent AND when present but mistyped
    # (null included) — a nulled-out field with no warning would grade a
    # garbage entry as spec-compliant.
    scheme = required_str(entry, index, "scheme", warnings)
    if scheme is not None and scheme not in KNOWN_SCHEMES:
        warnings.append(f"accepts[{index}].scheme {scheme!r} is not a known scheme")

    network = required_str(entry, index, "network", warnings)
    if network is not None and not _CAIP2.match(network):
        warnings.append(f"accepts[{index}].network {network!r} is not CAIP-2")

    asset = required_str(entry, index, "asset", warnings)
    pay_to = required_str(entry, index, "payTo", warnings)
    amount = _parse_amount(entry, index, warnings)

    timeout: Any = None
    if "maxTimeoutSeconds" not in entry:
        warnings.append(f"accepts[{index}].maxTimeoutSeconds missing (required)")
    else:
        timeout = entry["maxTimeoutSeconds"]
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, int | float)
            or not math.isfinite(timeout)
            or timeout <= 0
        ):
            warnings.append(
                f"accepts[{index}].maxTimeoutSeconds {timeout!r} is not a positive finite number"
            )
            timeout = None

    extra = entry.get("extra")
    if extra is not None and not isinstance(extra, dict):
        warnings.append(f"accepts[{index}].extra is not an object")
        extra = None

    return PaymentOption(
        scheme=scheme,
        network=network,
        amount=amount,
        asset=asset,
        pay_to=pay_to,
        max_timeout_seconds=float(timeout) if timeout is not None else None,
        extra=extra,
    )


def _parse_amount(entry: dict[str, Any], index: int, warnings: list[str]) -> str | None:
    raw = entry.get("amount")
    if raw is None and entry.get("maxAmountRequired") is not None:
        raw = entry["maxAmountRequired"]
        warnings.append(f"accepts[{index}] uses legacy maxAmountRequired instead of amount")
    if raw is None:
        warnings.append(f"accepts[{index}].amount missing (required)")
        return None
    if isinstance(raw, bool):
        warnings.append(f"accepts[{index}].amount {raw!r} is not an atomic-units string")
        return None
    if isinstance(raw, int | float):
        warnings.append(f"accepts[{index}].amount is a number; spec requires a string")
        # Coerce only what maps losslessly onto atomic units: non-negative
        # finite integral values. format(x, 'f') would silently turn 1e-7
        # into '0' — a nonzero price recorded as free.
        if math.isfinite(raw) and raw >= 0 and float(raw).is_integer():
            return str(int(raw))
        warnings.append(f"accepts[{index}].amount {raw!r} does not coerce to atomic units")
        return None
    if not isinstance(raw, str):
        warnings.append(f"accepts[{index}].amount {raw!r} is not an atomic-units string")
        return None
    if not ATOMIC_AMOUNT.match(raw):
        # Malformed strings are preserved (warn-and-keep) so downstream can
        # still show what the server asked for.
        warnings.append(f"accepts[{index}].amount {raw!r} is not an atomic-units string")
    return raw
