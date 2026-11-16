"""Strict JWKS parsing.

A fetched document is all-or-nothing: every key must be a usable RS256
verification key, every ``kid`` must be unique, and every hard size limit must
hold.  Only after the entire document passes is a :class:`KeySnapshot` built.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Mapping

from cryptography.hazmat.primitives.asymmetric import rsa

from .config import JwksLimits
from .errors import JwksDocumentError, TokenValidationError
from .strict_json import b64url_decode_strict, strict_json_loads

_PRIVATE_MEMBERS = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth"})

# Absolute ceiling for a base64urlUInt before it is even converted to an int.
# The configured ``max_rsa_bits`` is enforced afterwards, on the bit length.
_MAX_INTEGER_BYTES = 2048


@dataclass(frozen=True, slots=True)
class ParsedJwk:
    kid: str
    public_key: rsa.RSAPublicKey


@dataclass(frozen=True, slots=True)
class KeySnapshot:
    """An immutable, fully validated JWKS snapshot for one issuer."""

    issuer: str
    seq: int
    keys: Mapping[str, rsa.RSAPublicKey]
    fetched_at: int
    expires_at: int
    digest: str
    raw_bytes: int

    def get(self, kid: str) -> rsa.RSAPublicKey | None:
        return self.keys.get(kid)

    def is_fresh(self, now: int) -> bool:
        return now < self.expires_at


def _decode_uint(value: Any, name: str, kid: str) -> int:
    if not isinstance(value, str) or not value:
        raise JwksDocumentError(
            "jwk_bad_integer", f"key {kid!r}: {name} must be a non-empty string"
        )
    try:
        raw = b64url_decode_strict(value, what=f"JWK {kid!r} {name}")
    except TokenValidationError as exc:
        raise JwksDocumentError(exc.code, f"key {kid!r}: {name}: {exc.message}") from exc
    if not raw:
        raise JwksDocumentError("jwk_bad_integer", f"key {kid!r}: {name} is empty")
    if len(raw) > _MAX_INTEGER_BYTES:
        raise JwksDocumentError("jwk_bad_integer", f"key {kid!r}: {name} is too long")
    if raw[0] == 0:
        raise JwksDocumentError(
            "jwk_non_minimal_integer",
            f"key {kid!r}: {name} is not a minimal base64urlUInt",
        )
    return int.from_bytes(raw, "big")


def _parse_one(entry: Any, limits: JwksLimits, index: int) -> ParsedJwk:
    if type(entry) is not dict:
        raise JwksDocumentError("jwk_not_object", f"keys[{index}] is not an object")

    kid = entry.get("kid")
    if not isinstance(kid, str) or not kid:
        raise JwksDocumentError("jwk_bad_kid", f"keys[{index}] has no string kid")
    if len(kid) > limits.max_kid_length:
        raise JwksDocumentError("jwk_bad_kid", f"keys[{index}] kid is too long")
    if any(ord(ch) < 0x20 for ch in kid):
        raise JwksDocumentError(
            "jwk_bad_kid", f"keys[{index}] kid contains control characters"
        )

    present_private = _PRIVATE_MEMBERS.intersection(entry)
    if present_private:
        raise JwksDocumentError(
            "jwk_private_material",
            f"key {kid!r}: document contains private key material",
        )

    if entry.get("kty") != "RSA":
        raise JwksDocumentError("jwk_not_rsa", f"key {kid!r}: kty must be RSA")
    if "use" in entry and entry["use"] != "sig":
        raise JwksDocumentError("jwk_wrong_use", f"key {kid!r}: use must be sig")
    if "alg" in entry and entry["alg"] != "RS256":
        raise JwksDocumentError("jwk_wrong_alg", f"key {kid!r}: alg must be RS256")
    key_ops = entry.get("key_ops")
    if key_ops is not None:
        if type(key_ops) is not list or not all(isinstance(op, str) for op in key_ops):
            raise JwksDocumentError(
                "jwk_bad_key_ops", f"key {kid!r}: key_ops must be an array of strings"
            )
        if "verify" not in key_ops or "sign" in key_ops:
            raise JwksDocumentError(
                "jwk_bad_key_ops",
                f"key {kid!r}: key_ops must allow verify and must not allow sign",
            )

    n = _decode_uint(entry.get("n"), "n", kid)
    e = _decode_uint(entry.get("e"), "e", kid)

    if n.bit_length() < limits.min_rsa_bits:
        raise JwksDocumentError(
            "jwk_modulus_too_small",
            f"key {kid!r}: modulus is {n.bit_length()} bits, "
            f"minimum is {limits.min_rsa_bits}",
        )
    if n.bit_length() > limits.max_rsa_bits:
        raise JwksDocumentError(
            "jwk_modulus_too_large",
            f"key {kid!r}: modulus exceeds {limits.max_rsa_bits} bits",
        )
    if n % 2 == 0:
        raise JwksDocumentError("jwk_bad_modulus", f"key {kid!r}: modulus is even")
    if e < 3 or e % 2 == 0:
        raise JwksDocumentError("jwk_bad_exponent", f"key {kid!r}: exponent is invalid")
    if e >= 1 << 64:
        raise JwksDocumentError("jwk_bad_exponent", f"key {kid!r}: exponent is too large")

    try:
        public_key = rsa.RSAPublicNumbers(e, n).public_key()
    except (ValueError, TypeError) as exc:
        raise JwksDocumentError(
            "jwk_bad_key", f"key {kid!r}: cannot build an RSA public key"
        ) from exc
    if not isinstance(public_key, rsa.RSAPublicKey):  # defensive
        raise JwksDocumentError("jwk_not_rsa", f"key {kid!r}: not an RSA public key")
    if public_key.key_size < limits.min_rsa_bits:
        raise JwksDocumentError(
            "jwk_modulus_too_small", f"key {kid!r}: RSA key is too small"
        )
    return ParsedJwk(kid=kid, public_key=public_key)


def parse_jwks_document(
    body: bytes,
    *,
    issuer: str,
    seq: int,
    fetched_at: int,
    ttl_seconds: int,
    limits: JwksLimits,
) -> KeySnapshot:
    """Validate an entire JWKS body or raise :class:`JwksDocumentError`."""
    if not isinstance(body, bytes):
        raise TypeError("body must be bytes")
    if len(body) == 0:
        raise JwksDocumentError("jwks_empty", "JWKS body is empty")
    if len(body) > limits.max_bytes:
        raise JwksDocumentError(
            "jwks_too_large",
            f"JWKS body is {len(body)} bytes, limit is {limits.max_bytes}",
        )
    try:
        document = strict_json_loads(body)
    except TokenValidationError as exc:
        # Preserve the precise reason (e.g. duplicate members) but expose it
        # under the JWKS error family.
        raise JwksDocumentError(
            exc.code, f"JWKS JSON is invalid: {exc.message}"
        ) from exc
    except Exception as exc:
        raise JwksDocumentError("jwks_invalid_json", "JWKS JSON is invalid") from exc
    if type(document) is not dict:
        raise JwksDocumentError("jwks_not_object", "JWKS root must be a JSON object")
    keys = document.get("keys")
    if type(keys) is not list:
        raise JwksDocumentError("jwks_bad_keys", "JWKS keys must be an array")
    if not keys:
        raise JwksDocumentError("jwks_no_keys", "JWKS must contain at least one key")
    if len(keys) > limits.max_keys:
        raise JwksDocumentError(
            "jwks_too_many_keys",
            f"JWKS has {len(keys)} keys, limit is {limits.max_keys}",
        )

    parsed: dict[str, rsa.RSAPublicKey] = {}
    for index, entry in enumerate(keys):
        jwk = _parse_one(entry, limits, index)
        if jwk.kid in parsed:
            raise JwksDocumentError(
                "jwks_duplicate_kid", f"duplicate kid {jwk.kid!r} in JWKS"
            )
        parsed[jwk.kid] = jwk.public_key

    return KeySnapshot(
        issuer=issuer,
        seq=seq,
        keys=MappingProxyType(parsed),
        fetched_at=fetched_at,
        expires_at=fetched_at + ttl_seconds,
        digest=hashlib.sha256(body).hexdigest(),
        raw_bytes=len(body),
    )


def public_jwk(kid: str, public_key: rsa.RSAPublicKey, *, alg: str = "RS256") -> dict[str, Any]:
    """Encode an RSA public key as a JWK (used by the simulator and CLI tools)."""

    def encode_uint(value: int) -> str:
        from .strict_json import b64url_encode

        raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
        return b64url_encode(raw)

    numbers = public_key.public_numbers()
    return {
        "kty": "RSA",
        "kid": kid,
        "use": "sig",
        "alg": alg,
        "n": encode_uint(numbers.n),
        "e": encode_uint(numbers.e),
    }
