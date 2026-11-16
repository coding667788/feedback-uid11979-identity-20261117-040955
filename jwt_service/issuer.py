"""Local test-token issuer (independent of the verification service).

Produces RS256 compact JWTs with ``iss``/``sub``/``aud``/``exp``/``nbf``, and
a matching JWKS document.  Everything is test material; keys live only in
memory unless the caller asks to write them to disk.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from .jwks import public_jwk
from .strict_json import b64url_encode


def generate_rsa_key(bits: int = 2048) -> rsa.RSAPrivateKey:
    """Generate a test RSA key.

    Keys below 2048 bits are allowed here *only* so tests can prove that the
    verifier rejects them; the verifier itself enforces its own minimum.
    """
    if bits < 512:
        raise ValueError("test keys must be at least 512 bits")
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


@dataclass(frozen=True, slots=True)
class TokenSpec:
    issuer: str
    subject: str
    audience: str
    kid: str
    exp: int
    nbf: int
    iat: int | None = None
    extra_claims: dict[str, Any] | None = None
    extra_header: dict[str, Any] | None = None
    alg: str = "RS256"


def encode_segment(value: Any) -> str:
    raw = json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return b64url_encode(raw)


def _segment(value: Any) -> str:
    if isinstance(value, _RawSegment):
        return b64url_encode(value.text.encode("utf-8"))
    return encode_segment(value)


def sign_jwt(
    spec: TokenSpec,
    private_key: rsa.RSAPrivateKey,
    *,
    header_override: Any = None,
    payload_override: Any = None,
) -> str:
    """Sign a compact JWS.

    ``header_override``/``payload_override`` may be a dict (encoded normally),
    a :class:`_RawSegment` (literal JSON text, still base64url-encoded, used
    for malformed-input tests such as duplicate members) or ``None``.
    """
    header: Any = {"alg": spec.alg, "typ": "JWT", "kid": spec.kid}
    if spec.extra_header:
        header.update(spec.extra_header)
    if header_override is not None:
        header = header_override

    if payload_override is not None:
        payload: Any = payload_override
    else:
        payload = {
            "iss": spec.issuer,
            "sub": spec.subject,
            "aud": spec.audience,
            "exp": spec.exp,
            "nbf": spec.nbf,
        }
        if spec.iat is not None:
            payload["iat"] = spec.iat
        if spec.extra_claims:
            payload.update(spec.extra_claims)

    header_b64 = _segment(header)
    payload_b64 = _segment(payload)
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    signature = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return f"{header_b64}.{payload_b64}.{b64url_encode(signature)}"


class _RawSegment:
    """Wrapper for literal JSON text, base64url-encoded as a whole segment."""

    __slots__ = ("text",)

    def __init__(self, text: str) -> None:
        self.text = text


def raw_segment(text: str) -> _RawSegment:
    return _RawSegment(text)


def jwks_for(keys: list[tuple[str, rsa.RSAPublicKey]]) -> dict[str, Any]:
    return {"keys": [public_jwk(kid, key) for kid, key in keys]}


def jwks_bytes(keys: list[tuple[str, rsa.RSAPublicKey]]) -> bytes:
    return json.dumps(jwks_for(keys), separators=(",", ":")).encode("utf-8")


class LocalIssuer:
    """Convenience holder: one issuer identity plus its active signing key."""

    def __init__(self, issuer: str, audience: str) -> None:
        self.issuer = issuer
        self.audience = audience
        self.private_key = generate_rsa_key()
        self.kid = "key-1"

    def rotate(
        self, kid: str | None = None, *, bits: int = 2048
    ) -> rsa.RSAPrivateKey:
        """Replace the active signing key; returns the new private key.

        ``kid`` defaults to the previous kid, which models the "same kid, new
        public key" rotation the verifier must pick up.
        """
        self.private_key = generate_rsa_key(bits)
        if kid is not None:
            self.kid = kid
        return self.private_key

    def jwks(self) -> dict[str, Any]:
        return jwks_for([(self.kid, self.private_key.public_key())])

    def mint(
        self,
        *,
        now: int,
        ttl: int = 300,
        nbf: int | None = None,
        sub: str = "user-1",
        kid: str | None = None,
        key: rsa.RSAPrivateKey | None = None,
        audience: str | None = None,
        **kwargs: Any,
    ) -> str:
        spec = TokenSpec(
            issuer=self.issuer,
            subject=sub,
            audience=audience or self.audience,
            kid=kid or self.kid,
            exp=now + ttl,
            nbf=now if nbf is None else nbf,
            iat=now,
        )
        return sign_jwt(spec, key or self.private_key, **kwargs)
