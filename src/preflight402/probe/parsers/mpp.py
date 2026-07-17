"""Detection-only parser for MPP (Machine Payment Protocol) challenges.

MPP (Stripe/Tempo, spec at tempoxyz.github.io/payment-auth-spec, IETF
draft-ryan-httpauth-payment) signals payment terms via one or more
`WWW-Authenticate: Payment` challenges on a 402. Challenge params: id,
realm, method (tempo|stripe|card|lightning), intent
(charge|session|subscription), request (base64url JSON with amount in base
units, currency as a code like 'usd' or a token address, recipient), plus
optional expires, description, opaque, digest.

Per the build plan MPP is detection-only for now — this module produces the
"MPP-capable" flag plus the decoded terms, no settlement logic. Servers may
emit several Payment challenges (one per method); proxies and our prober's
dict-of-headers fold them into one comma-joined value, so the splitter here
is quote-aware and multi-challenge.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

KNOWN_METHODS = frozenset({"tempo", "stripe", "card", "lightning"})
KNOWN_INTENTS = frozenset({"charge", "session", "subscription"})

_SCHEME_TOKEN = re.compile(r"^\s*([A-Za-z][A-Za-z0-9._~+/-]*)\s*(.*)$", re.S)
_AUTH_PARAM = re.compile(r'^\s*([A-Za-z0-9_-]+)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|([^\s",]*))\s*$')


@dataclass(slots=True)
class MPPChallenge:
    """One WWW-Authenticate: Payment challenge, normalized."""

    method: str | None
    intent: str | None
    amount: str | None  # base units, from the header param or the request payload
    currency: str | None  # 'usd'-style code or a token address
    recipient: str | None
    realm: str | None = None
    challenge_id: str | None = None
    expires: str | None = None
    description: str | None = None
    request: dict[str, Any] | None = None  # decoded request payload, verbatim

    def as_dict(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "intent": self.intent,
            "amount": self.amount,
            "currency": self.currency,
            "recipient": self.recipient,
            "realm": self.realm,
            "expires": self.expires,
            "description": self.description,
        }


@dataclass(slots=True)
class MPPResult:
    challenges: list[MPPChallenge] = field(default_factory=list)
    other_schemes: list[str] = field(default_factory=list)  # non-Payment WWW-Authenticate schemes
    warnings: list[str] = field(default_factory=list)

    @property
    def mpp_capable(self) -> bool:
        return bool(self.challenges)


def parse_mpp(headers: Mapping[str, str]) -> MPPResult:
    """Extract Payment challenges from WWW-Authenticate. Never raises."""
    result = MPPResult()
    value = next((v for k, v in headers.items() if k.lower() == "www-authenticate"), None)
    if not value:
        return result
    for scheme, params_raw in _split_challenges(value, result.warnings):
        if scheme.lower() != "payment":
            if scheme not in result.other_schemes:
                result.other_schemes.append(scheme)
            continue
        result.challenges.append(_parse_challenge(params_raw, result.warnings))
    return result


def _split_challenges(value: str, warnings: list[str]) -> list[tuple[str, str]]:
    """Split a WWW-Authenticate value into (scheme, raw-params) pairs.

    Handles the comma-joined multi-challenge form ('Payment a=1, Basic
    realm=x') that header folding produces. A new challenge starts at any
    comma-separated part shaped like a scheme token followed by something
    that is not '=...' — this deliberately loose test also nets RFC 7235
    token68 challenges ('Negotiate YII+ab==') and space-separated-param
    malformations, which then parse liberally with per-param warnings
    instead of being silently dropped or misattributed. A bare 'key=value'
    part continues the current challenge.
    """
    challenges: list[tuple[str, str]] = []
    scheme: str | None = None
    parts: list[str] = []
    for part in _split_outside_quotes(value):
        stripped = part.strip()
        if not stripped:
            continue
        match = _SCHEME_TOKEN.match(stripped)
        starts_new = bool(
            match and "=" not in match.group(1) and not match.group(2).startswith("=")
        )
        if starts_new:
            if scheme is not None:
                challenges.append((scheme, ",".join(parts)))
            scheme = match.group(1)
            parts = [match.group(2)] if match.group(2) else []
        elif scheme is not None:
            parts.append(part)
        else:
            warnings.append(f"WWW-Authenticate part before any scheme ignored: {stripped[:60]!r}")
    if scheme is not None:
        challenges.append((scheme, ",".join(parts)))
    return challenges


def _split_outside_quotes(value: str) -> list[str]:
    parts: list[str] = []
    current: list[str] = []
    in_quotes = False
    escaped = False
    for char in value:
        if escaped:
            current.append(char)
            escaped = False
        elif char == "\\" and in_quotes:
            current.append(char)
            escaped = True
        elif char == '"':
            current.append(char)
            in_quotes = not in_quotes
        elif char == "," and not in_quotes:
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
    parts.append("".join(current))
    return parts


def _parse_challenge(params_raw: str, warnings: list[str]) -> MPPChallenge:
    params: dict[str, str] = {}
    for part in _split_outside_quotes(params_raw):
        if not part.strip():
            continue
        match = _AUTH_PARAM.match(part)
        if match is None:
            warnings.append(f"unparseable Payment challenge param: {part.strip()[:60]!r}")
            continue
        key = match.group(1).lower()
        if match.group(2) is not None:
            # RFC 7230 quoted-pair: backslash + any char decodes to the char.
            value = re.sub(r"\\(.)", r"\1", match.group(2))
        else:
            value = match.group(3)
        if key in params and params[key] != value:
            # RFC 7235: params MUST NOT occur more than once per challenge.
            # Last-wins silently would hide amount-ambiguity from the verdict.
            warnings.append(f"duplicate Payment challenge param {key!r}")
        params[key] = value

    request = _decode_request(params.get("request"), warnings)

    method = params.get("method")
    if method is None:
        warnings.append("Payment challenge missing method")
    elif method not in KNOWN_METHODS:
        warnings.append(f"Payment challenge method {method!r} is not a known method")

    intent = params.get("intent")
    if intent is None:
        warnings.append("Payment challenge missing intent")
    elif intent not in KNOWN_INTENTS:
        warnings.append(f"Payment challenge intent {intent!r} is not a known intent")

    def resolved(header_key: str, request_key: str) -> str | None:
        value = params.get(header_key)
        if value is not None:
            return value
        if request is None:
            return None
        payload_value = request.get(request_key)
        if isinstance(payload_value, str):
            return payload_value
        if isinstance(payload_value, int) and not isinstance(payload_value, bool):
            warnings.append(f"Payment challenge request {request_key} is a number, not a string")
            return str(payload_value)
        return None

    amount = resolved("amount", "amount")
    recipient = resolved("recipient", "recipient")
    if amount is None:
        warnings.append("Payment challenge has no amount (header or request payload)")
    if recipient is None:
        warnings.append("Payment challenge has no recipient (header or request payload)")

    return MPPChallenge(
        method=method,
        intent=intent,
        amount=amount,
        currency=resolved("currency", "currency"),
        recipient=recipient,
        realm=params.get("realm"),
        challenge_id=params.get("id"),
        expires=params.get("expires"),
        description=resolved("description", "description"),
        request=request,
    )


def _decode_request(raw: str | None, warnings: list[str]) -> dict[str, Any] | None:
    if raw is None:
        return None
    padded = raw + "=" * (-len(raw) % 4)
    for decoder in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            payload = json.loads(decoder(padded))
        except (binascii.Error, ValueError, UnicodeDecodeError):
            continue
        if isinstance(payload, dict):
            return payload
        warnings.append("Payment challenge request decodes to a non-object")
        return None
    warnings.append("Payment challenge request is not decodable (base64url JSON expected)")
    return None
