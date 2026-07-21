"""preflight402-guard: validate x402 payment endpoints before paying.

    from preflight402_guard import Guard, PaymentBlocked

    guard = Guard()
    await guard.assert_allowed("https://api.example.com/data")

    # or guard every payment an x402 SDK client makes:
    guard.install(x402_client)

See Guard's docstring for the policy knobs (block/warn tiers, max_price_usd,
identity/reputation floors, fail-open semantics).
"""

from preflight402_guard.guard import (
    DEFAULT_SERVICE_URL,
    Guard,
    GuardDecision,
    PaymentBlocked,
)

__version__ = "0.1.0"
__all__ = ["DEFAULT_SERVICE_URL", "Guard", "GuardDecision", "PaymentBlocked", "__version__"]
