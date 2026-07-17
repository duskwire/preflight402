"""Parser for x402 v1 (legacy) payment-required responses.

Spec (specs/x402-specification-v1.md in x402-foundation/x402): v1 carries the
payload in the 402 response body as JSON — {x402Version: 1, error, accepts}.
accepts[] entries require scheme (only "exact" was ever documented), network
(slug names like "base", NOT CAIP-2 — a slug is correct v1, never warned),
maxAmountRequired (atomic-units string), asset, payTo, resource (a URL
string), description, and maxTimeoutSeconds; mimeType/outputSchema/extra are
optional. Clients paid via the X-PAYMENT request header.

Same philosophy as the v2 parser: liberal parse, every deviation recorded in
warnings, never raises. Returns None when the body is not a v1 payload.
"""

from __future__ import annotations

import json
import math
from typing import Any

from preflight402.probe.parsers.types import (
    ATOMIC_AMOUNT,
    ParsedPaymentRequired,
    PaymentOption,
    required_str,
)

V1_KNOWN_SCHEMES = frozenset({"exact"})


def parse_x402_v1(body: str | None) -> ParsedPaymentRequired | None:
    """Parse a v1 payment-required body; None unless x402Version == 1."""
    if not body:
        return None
    try:
        payload = json.loads(body)
    except ValueError:
        return None
    if not isinstance(payload, dict) or payload.get("x402Version") != 1:
        return None

    warnings: list[str] = []
    error = payload.get("error")
    if error is None:
        warnings.append("error missing (required in v1)")
        error_str = None
    elif not isinstance(error, str):
        warnings.append("error is not a string")
        error_str = None
    else:
        error_str = error

    raw_accepts = payload.get("accepts")
    accepts: list[PaymentOption] = []
    resource_url: str | None = None
    if not isinstance(raw_accepts, list) or not raw_accepts:
        warnings.append("accepts missing or empty (required)")
    else:
        for index, entry in enumerate(raw_accepts):
            if not isinstance(entry, dict):
                warnings.append(f"accepts[{index}] is not an object")
                continue
            option, resource = _parse_accept(entry, index, warnings)
            accepts.append(option)
            if resource_url is None and resource:
                resource_url = resource  # v1 has no top-level resource

    return ParsedPaymentRequired(
        version=1,
        source="body",
        resource_url=resource_url,
        error=error_str,
        accepts=accepts,
        warnings=warnings,
    )


def _parse_accept(
    entry: dict[str, Any], index: int, warnings: list[str]
) -> tuple[PaymentOption, str | None]:
    scheme = required_str(entry, index, "scheme", warnings)
    if scheme is not None and scheme not in V1_KNOWN_SCHEMES:
        warnings.append(f"accepts[{index}].scheme {scheme!r} is not a known v1 scheme")

    # v1 networks are slug names ("base", "base-sepolia") — any non-empty
    # string is fine; CAIP-2 checks would be wrong here.
    network = required_str(entry, index, "network", warnings)
    asset = required_str(entry, index, "asset", warnings)
    pay_to = required_str(entry, index, "payTo", warnings)
    resource = required_str(entry, index, "resource", warnings)
    required_str(entry, index, "description", warnings)

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

    option = PaymentOption(
        scheme=scheme,
        network=network,
        amount=amount,
        asset=asset,
        pay_to=pay_to,
        max_timeout_seconds=float(timeout) if timeout is not None else None,
        extra=extra,
    )
    return option, resource


def _parse_amount(entry: dict[str, Any], index: int, warnings: list[str]) -> str | None:
    raw = entry.get("maxAmountRequired")
    if raw is None and entry.get("amount") is not None:
        raw = entry["amount"]
        warnings.append(f"accepts[{index}] uses v2's amount field in a v1 payload")
    if raw is None:
        warnings.append(f"accepts[{index}].maxAmountRequired missing (required)")
        return None
    if isinstance(raw, bool):
        warnings.append(f"accepts[{index}].maxAmountRequired {raw!r} is not a string")
        return None
    if isinstance(raw, int | float):
        # Same lossless-only coercion as the v2 parser — a numeric price is
        # the same server sloppiness on either path and must not vanish.
        warnings.append(f"accepts[{index}].maxAmountRequired is a number; spec requires a string")
        if math.isfinite(raw) and raw >= 0 and float(raw).is_integer():
            return str(int(raw))
        warnings.append(
            f"accepts[{index}].maxAmountRequired {raw!r} does not coerce to atomic units"
        )
        return None
    if not isinstance(raw, str):
        warnings.append(f"accepts[{index}].maxAmountRequired {raw!r} is not a string")
        return None
    if not ATOMIC_AMOUNT.match(raw):
        warnings.append(f"accepts[{index}].maxAmountRequired {raw!r} is not an atomic-units string")
    return raw
