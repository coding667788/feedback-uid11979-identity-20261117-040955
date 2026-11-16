"""Strict compact-JWS (JWT) parsing and claim validation.

Only ``RS256`` is accepted.  The header is never allowed to influence *where*
keys come from: ``jku``/``x5u``/``x5c``/``jwk`` are ignored, and keys are only
ever taken from the pre-configured JWKS snapshot for the ``iss`` in the
payload.  No verification result is cached; every call re-resolves the key
against the current snapshot.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from .clock import Clock
from .config import IssuerConfig
from .errors import TokenValidationError, UnknownKidError
from .jwks import KeySnapshot
from .strict_json import (
    b64url_decode_strict,
    parse_json_object,
    strict_int_member,
)

MAX_TOKEN_CHARS = 16 * 1024
MAX_HEADER_SEGMENT_CHARS = 8 * 1024
MAX_PAYLOAD_SEGMENT_CHARS = 12 * 1024
MAX_SUB_LENGTH = 512
MAX_AUDIENCE_ITEMS = 16
MAX_ISSUER_LENGTH = 512


class KeyResolver(Protocol):
    def resolve(self, kid: str, now: int) -> "ResolvedKey": ...


def _json_safe(value: Any) -> Any:
    """Copy decoded JSON into plain dict/list/scalars for safe re-serialisation."""
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_json_safe(v) for v in value]
    return value


@dataclass(frozen=True, slots=True)
class ResolvedKey:
    public_key: rsa.RSAPublicKey
    snapshot: KeySnapshot
    refreshed: bool = False


@dataclass(frozen=True, slots=True)
class VerifiedToken:
    issuer: str
    subject: str
    audience: tuple[str, ...]
    kid: str
    claims: Mapping[str, Any]
    header: Mapping[str, Any]
    snapshot_seq: int
    snapshot_digest: str

    def public_view(self) -> dict[str, Any]:
        return {
            "valid": True,
            "issuer": self.issuer,
            "subject": self.subject,
            "audience": list(self.audience),
            "kid": self.kid,
            "claims": _json_safe(dict(self.claims)),
            "snapshot_seq": self.snapshot_seq,
            "snapshot_digest": self.snapshot_digest,
        }


@dataclass(frozen=True, slots=True)
class _Parsed:
    header: dict[str, Any]
    claims: dict[str, Any]
    signing_input: bytes
    signature: bytes


def _split(token: str) -> _Parsed:
    if not isinstance(token, str):
        raise TokenValidationError("token_not_string", "token must be a string")
    if not token:
        raise TokenValidationError("token_empty", "token is empty")
    if len(token) > MAX_TOKEN_CHARS:
        raise TokenValidationError("token_too_large", "token is too long")
    if any(ch.isspace() for ch in token):
        raise TokenValidationError("token_whitespace", "token contains whitespace")
    parts = token.split(".")
    if len(parts) != 3:
        raise TokenValidationError(
            "token_bad_segments", "token must have exactly three segments"
        )
    header_b64, payload_b64, signature_b64 = parts
    if not header_b64 or not payload_b64 or not signature_b64:
        raise TokenValidationError("token_empty_segment", "token has an empty segment")
    if len(header_b64) > MAX_HEADER_SEGMENT_CHARS:
        raise TokenValidationError("token_too_large", "header segment is too long")
    if len(payload_b64) > MAX_PAYLOAD_SEGMENT_CHARS:
        raise TokenValidationError("token_too_large", "payload segment is too long")

    header = parse_json_object(
        b64url_decode_strict(header_b64, what="header"), "JWT header"
    )
    claims = parse_json_object(
        b64url_decode_strict(payload_b64, what="payload"), "JWT payload"
    )
    signature = b64url_decode_strict(signature_b64, what="signature")
    if not signature:
        raise TokenValidationError("signature_empty", "signature is empty")
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    return _Parsed(
        header=header,
        claims=claims,
        signing_input=signing_input,
        signature=signature,
    )


def _validate_header(header: dict[str, Any], max_kid_length: int) -> str:
    alg = header.get("alg")
    if type(alg) is not str or alg != "RS256":
        raise TokenValidationError(
            "algorithm_not_allowed", "only the RS256 algorithm is accepted"
        )
    if "crit" in header:
        # We implement no JWS extensions, so any critical header parameter is
        # by definition unsupported.  This also rejects RFC 7797 ``b64=false``.
        raise TokenValidationError(
            "unsupported_crit", "critical header parameters are not supported"
        )
    if header.get("b64") is False:
        raise TokenValidationError("unsupported_b64", "unencoded payloads are not supported")

    kid = header.get("kid")
    if type(kid) is not str or not kid:
        raise TokenValidationError("missing_kid", "header must contain a string kid")
    if len(kid) > max_kid_length:
        raise TokenValidationError("invalid_kid", "kid is too long")
    if any(ord(ch) < 0x20 for ch in kid):
        raise TokenValidationError("invalid_kid", "kid contains control characters")
    return kid


def _validate_claims(claims: dict[str, Any]) -> tuple[str, str, tuple[str, ...], int, int]:
    iss = claims.get("iss")
    if type(iss) is not str or not iss:
        raise TokenValidationError("invalid_iss", "iss must be a non-empty string")
    if len(iss) > MAX_ISSUER_LENGTH:
        raise TokenValidationError("invalid_iss", "iss is too long")

    sub = claims.get("sub")
    if type(sub) is not str or not sub:
        raise TokenValidationError("invalid_sub", "sub must be a non-empty string")
    if len(sub) > MAX_SUB_LENGTH:
        raise TokenValidationError("invalid_sub", "sub is too long")
    if any(ord(ch) < 0x20 for ch in sub):
        raise TokenValidationError("invalid_sub", "sub contains control characters")

    if "aud" not in claims:
        raise TokenValidationError("invalid_aud", "aud is required")
    raw_aud = claims["aud"]
    if type(raw_aud) is str:
        if not raw_aud:
            raise TokenValidationError("invalid_aud", "aud must not be empty")
        audiences = (raw_aud,)
    elif type(raw_aud) is list:
        if not raw_aud or len(raw_aud) > MAX_AUDIENCE_ITEMS:
            raise TokenValidationError("invalid_aud", "aud array has an invalid size")
        for item in raw_aud:
            if type(item) is not str or not item:
                raise TokenValidationError(
                    "invalid_aud", "aud array must contain non-empty strings"
                )
            if len(item) > 512:
                raise TokenValidationError("invalid_aud", "aud value is too long")
        audiences = tuple(raw_aud)
    else:
        raise TokenValidationError("invalid_aud", "aud must be a string or string array")

    exp = strict_int_member(claims, "exp", "claims")
    if exp is None:
        raise TokenValidationError("missing_exp", "exp is required")
    nbf = strict_int_member(claims, "nbf", "claims")
    if nbf is None:
        raise TokenValidationError("missing_nbf", "nbf is required")
    if "iat" in claims:
        strict_int_member(claims, "iat", "claims")
    return iss, sub, audiences, exp, nbf


class JwtVerifier:
    def __init__(
        self,
        *,
        issuers: Mapping[str, IssuerConfig],
        resolvers: Mapping[str, KeyResolver],
        clock: Clock,
        max_kid_length: int = 256,
    ) -> None:
        self._issuers = dict(issuers)
        self._resolvers = dict(resolvers)
        self._clock = clock
        self._max_kid_length = max_kid_length

    def verify(self, token: str, *, now: int | None = None) -> VerifiedToken:
        # One timestamp for the whole verification: key freshness, nbf and exp
        # all use the same instant, so a slow refresh cannot silently move the
        # accepted window.
        if now is None:
            now = self._clock.now()
        if type(now) is bool or not isinstance(now, int):
            raise TypeError("now must be an int")

        parsed = _split(token)
        kid = _validate_header(parsed.header, self._max_kid_length)
        iss, sub, audiences, exp, nbf = _validate_claims(parsed.claims)

        issuer_config = self._issuers.get(iss)
        if issuer_config is None:
            raise TokenValidationError("unknown_issuer", "iss is not a configured issuer")
        if iss != issuer_config.issuer:
            raise TokenValidationError("unknown_issuer", "iss is not a configured issuer")
        if issuer_config.audience not in audiences:
            raise TokenValidationError("invalid_aud", "aud does not contain the trusted audience")

        # No implicit leeway: nbf <= now < exp.
        if now < nbf:
            raise TokenValidationError("token_not_yet_valid", "nbf is in the future")
        if now >= exp:
            raise TokenValidationError("token_expired", "exp is not after now")

        resolver = self._resolvers.get(iss)
        if resolver is None:
            raise TokenValidationError("unknown_issuer", "no key resolver for issuer")
        resolved = resolver.resolve(kid, now)

        try:
            resolved.public_key.verify(
                parsed.signature,
                parsed.signing_input,
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
        except InvalidSignature as exc:
            raise TokenValidationError(
                "signature_invalid", "signature verification failed"
            ) from exc
        except (ValueError, TypeError) as exc:
            raise TokenValidationError(
                "signature_invalid", "signature could not be verified"
            ) from exc

        return VerifiedToken(
            issuer=iss,
            subject=sub,
            audience=audiences,
            kid=kid,
            claims=parsed.claims,
            header=parsed.header,
            snapshot_seq=resolved.snapshot.seq,
            snapshot_digest=resolved.snapshot.digest,
        )


__all__ = [
    "JwtVerifier",
    "KeyResolver",
    "ResolvedKey",
    "VerifiedToken",
    "UnknownKidError",
    "MAX_TOKEN_CHARS",
]
