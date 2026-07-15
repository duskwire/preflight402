"""Shared result types and helpers for the 402 payment parsers."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

# Atomic token units: a decimal-digit string.
ATOMIC_AMOUNT = re.compile(r"^[0-9]+$")


@dataclass(slots=True)
class PaymentOption:
    """One accepts[] entry, normalized across x402 versions."""

    scheme: str | None
    network: str | None
    amount: str | None  # atomic units, decimal string
    asset: str | None
    pay_to: str | None
    max_timeout_seconds: float | None
    extra: dict[str, Any] | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "scheme": self.scheme,
            "network": self.network,
            "amount": self.amount,
            "asset": self.asset,
            "pay_to": self.pay_to,
            "max_timeout_seconds": self.max_timeout_seconds,
            "extra": self.extra,
        }


@dataclass(slots=True)
class ParsedPaymentRequired:
    """An x402 payment-required payload plus every spec deviation seen."""

    version: int | None
    source: str  # "header" | "body"
    resource_url: str | None
    error: str | None
    accepts: list[PaymentOption] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def spec_compliant(self) -> bool:
        return not self.warnings

    @property
    def networks(self) -> list[str]:
        seen: list[str] = []
        for option in self.accepts:
            if option.network and option.network not in seen:
                seen.append(option.network)
        return seen

    def as_db_payment(self) -> dict[str, Any]:
        """The probes.payment JSON column value."""
        protocol = f"x402-v{self.version}" if self.version in (1, 2) else "x402"
        return {
            "protocol": protocol,
            "source": self.source,
            "resource": self.resource_url,
            "networks": self.networks,
            "accepts": [option.as_dict() for option in self.accepts],
        }


def required_str(
    entry: dict[str, Any], index: int, name: str, warnings: list[str]
) -> str | None:
    """Fetch a required string field, warning on absence AND wrong type."""
    if name not in entry:
        warnings.append(f"accepts[{index}].{name} missing (required)")
        return None
    value = entry[name]
    if not isinstance(value, str) or not value:
        warnings.append(f"accepts[{index}].{name} {value!r} is not a non-empty string")
        return None
    return value
