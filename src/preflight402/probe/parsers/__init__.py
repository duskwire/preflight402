"""402 response parsers: x402 v2 (header-canonical), x402 v1 (legacy body),
and detection-only MPP — plus detect(), the one entry point callers use.

Endpoints in the wild are frequently multi-protocol (several goldens serve
an x402 v2 header AND an MPP WWW-Authenticate challenge on the same 402), so
detection is not either/or: `protocol` labels the primary x402 flavor and
`mpp` carries the MPP side independently.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from preflight402.probe.parsers.mpp import MPPChallenge, MPPResult, parse_mpp
from preflight402.probe.parsers.types import ParsedPaymentRequired, PaymentOption
from preflight402.probe.parsers.x402_v1 import parse_x402_v1
from preflight402.probe.parsers.x402_v2 import parse_payment_required

__all__ = [
    "Detection",
    "MPPChallenge",
    "MPPResult",
    "ParsedPaymentRequired",
    "PaymentOption",
    "detect",
    "parse_mpp",
    "parse_payment_required",
    "parse_x402_v1",
]


@dataclass(slots=True)
class Detection:
    protocol: str  # "x402-v2" | "x402-v1" | "mpp" | "none"
    payment: ParsedPaymentRequired | None
    mpp: MPPResult

    @property
    def is_payment_endpoint(self) -> bool:
        return self.protocol != "none"

    @property
    def mpp_capable(self) -> bool:
        return self.mpp.mpp_capable

    @property
    def warnings(self) -> list[str]:
        combined = list(self.payment.warnings) if self.payment else []
        combined.extend(self.mpp.warnings)
        return combined

    @property
    def spec_compliant(self) -> bool | None:
        """Compliance of the primary x402 payload; None when there isn't one."""
        return self.payment.spec_compliant if self.payment else None

    def as_db_payment(self) -> dict[str, Any] | None:
        """The probes.payment JSON column value; None for non-payment URLs."""
        if self.protocol == "none":
            return None
        record: dict[str, Any] = self.payment.as_db_payment() if self.payment else {}
        # The persisted protocol must be the same stable enum as
        # Detection.protocol — never a payload-version-derived variant that
        # could contradict it (e.g. a v2 header whose payload claims v1).
        record["protocol"] = self.protocol
        if self.mpp.mpp_capable:
            record["mpp"] = [challenge.as_dict() for challenge in self.mpp.challenges]
        return record


def detect(headers: Mapping[str, str], body: str | None) -> Detection:
    """Classify a 402 response: x402 v2, x402 v1, MPP, in any combination.

    v2 wins the primary-protocol label when both x402 flavors are present
    (matching the wire, where a v2 PAYMENT-REQUIRED header outranks a stale
    v1 body). MPP is detected independently. Never raises.
    """
    mpp = parse_mpp(headers)
    payment = parse_payment_required(headers, body)
    if payment is not None:
        protocol = "x402-v2"
    else:
        payment = parse_x402_v1(body)
        protocol = "x402-v1" if payment is not None else ("mpp" if mpp.mpp_capable else "none")
        if payment is not None and any(k.lower() == "payment-required" for k in headers):
            # Reaching the v1 parser with that header present means the v2
            # side was undecodable — evidence the verdict engine needs.
            payment.warnings.append(
                "PAYMENT-REQUIRED header present but undecodable; classified from v1 body"
            )
    return Detection(protocol=protocol, payment=payment, mpp=mpp)
