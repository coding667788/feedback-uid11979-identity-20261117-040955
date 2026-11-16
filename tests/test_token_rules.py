"""Strict token-format tests: JSON, base64url, header, claims, boundaries."""

from __future__ import annotations

import base64
import json

import pytest

from conftest import AUD_A, AUD_B, ISSUER_A, ISSUER_B
from jwt_service.errors import TokenValidationError
from jwt_service.issuer import TokenSpec, encode_segment, raw_segment, sign_jwt
from jwt_service.strict_json import b64url_decode_strict, b64url_encode, strict_json_loads


# ---------------------------------------------------------------- strict json

def test_strict_json_rejects_duplicate_top_level_member():
    with pytest.raises(TokenValidationError) as info:
        strict_json_loads('{"iss":"a","iss":"b"}')
    assert info.value.code == "json_duplicate_member"


def test_strict_json_rejects_duplicate_nested_member():
    with pytest.raises(TokenValidationError) as info:
        strict_json_loads('{"iss":"a","sub":"s","extra":{"x":1,"x":2}}')
    assert info.value.code == "json_duplicate_member"


def test_strict_json_accepts_normal_documents():
    assert strict_json_loads('{"a":[1,2.5,true,null,"x"],"b":{"c":-3}}') == {
        "a": [1, 2.5, True, None, "x"],
        "b": {"c": -3},
    }
    with pytest.raises(TokenValidationError):
        strict_json_loads('{"a":1} trailing')


def test_strict_json_rejects_bad_utf8():
    with pytest.raises(TokenValidationError):
        strict_json_loads(b'{"a":"\xff"}')


# ---------------------------------------------------------------- b64url

def test_b64url_rejects_padding():
    with pytest.raises(TokenValidationError) as info:
        b64url_decode_strict("QQ==")
    assert info.value.code == "b64url_bad_charset"


@pytest.mark.parametrize(
    "bad,code",
    [
        ("QR", "b64url_not_canonical"),  # non-zero pad bits: "QR" -> 0x41 + pad 0001
        ("A", "b64url_bad_length"),
        ("ab+/", "b64url_bad_charset"),
        ("ab c", "b64url_bad_charset"),
    ],
)
def test_b64url_rejects_noncanonical_or_illegal(bad, code):
    with pytest.raises(TokenValidationError) as info:
        b64url_decode_strict(bad)
    assert info.value.code == code


def test_b64url_rejects_reencoded_difference():
    # canonical round trip must hold
    assert b64url_decode_strict(b64url_encode(b"\x00\xff")) == b"\x00\xff"


# ---------------------------------------------------------------- header shape

def _token_with_raw_header(h, header_text: str, signer=None) -> str:
    spec = TokenSpec(
        issuer=ISSUER_A, subject="u", audience=AUD_A, kid="key-1",
        exp=h.clock.now() + 60, nbf=h.clock.now(),
    )
    return sign_jwt(
        spec,
        signer or h.a.private_key,
        header_override=raw_segment(header_text),
    )


def test_alg_none_rejected(harness):
    header = encode_segment({"alg": "none", "typ": "JWT", "kid": "key-1"})
    payload = encode_segment(
        {
            "iss": ISSUER_A, "sub": "u", "aud": AUD_A,
            "exp": harness.clock.now() + 60, "nbf": harness.clock.now(),
        }
    )
    token = f"{header}.{payload}."
    with pytest.raises(TokenValidationError) as info:
        harness.verify(token)
    assert info.value.code == "token_empty_segment"


def test_alg_hs256_confusion_rejected(harness):
    header = encode_segment({"alg": "HS256", "typ": "JWT", "kid": harness.a.kid})
    payload = encode_segment(
        {
            "iss": ISSUER_A, "sub": "u", "aud": AUD_A,
            "exp": harness.clock.now() + 60, "nbf": harness.clock.now(),
        }
    )
    # Sign with HMAC using the RSA public key bytes, the classic confusion attack.
    import hashlib, hmac
    from jwt_service.jwks import public_jwk
    jwk = public_jwk(harness.a.kid, harness.a.private_key.public_key())
    fake_key = json.dumps(jwk).encode()
    sig = hmac.new(fake_key, f"{header}.{payload}".encode(), hashlib.sha256).digest()
    token = f"{header}.{payload}.{b64url_encode(sig)}"
    with pytest.raises(TokenValidationError) as info:
        harness.verify(token)
    assert info.value.code == "algorithm_not_allowed"


def test_alg_rs512_rejected(harness):
    spec = TokenSpec(
        issuer=ISSUER_A, subject="u", audience=AUD_A, kid=harness.a.kid,
        exp=harness.clock.now() + 60, nbf=harness.clock.now(), alg="RS512",
    )
    token = sign_jwt(spec, harness.a.private_key)
    with pytest.raises(TokenValidationError) as info:
        harness.verify(token)
    assert info.value.code == "algorithm_not_allowed"


def test_crit_header_rejected(harness):
    spec = TokenSpec(
        issuer=ISSUER_A, subject="u", audience=AUD_A, kid=harness.a.kid,
        exp=harness.clock.now() + 60, nbf=harness.clock.now(),
        extra_header={"crit": ["exp"]},
    )
    token = sign_jwt(spec, harness.a.private_key)
    with pytest.raises(TokenValidationError) as info:
        harness.verify(token)
    assert info.value.code == "unsupported_crit"


@pytest.mark.parametrize("member", ["jku", "x5u", "x5c", "jwk"])
def test_never_fetches_from_header_supplied_urls(harness, member):
    harness.verify(harness.mint_a())
    before = harness.sim.request_count()
    spec = TokenSpec(
        issuer=ISSUER_A, subject="u", audience=AUD_A, kid=harness.a.kid,
        exp=harness.clock.now() + 60, nbf=harness.clock.now(),
        extra_header={member: harness.sim.url("/attacker/jwks.json")},
    )
    token = sign_jwt(spec, harness.a.private_key)
    # Header is ignored, so a correctly signed token still verifies and no
    # request goes to the attacker URL.
    harness.verify(token)
    assert harness.sim.request_count() == before
    assert not harness.sim.requests("/attacker/jwks.json")


def test_header_duplicate_member_rejected(harness):
    text = '{"alg":"RS256","typ":"JWT","kid":"key-1","kid":"key-2"}'
    with pytest.raises(TokenValidationError) as info:
        harness.verify(_token_with_raw_header(harness, text))
    assert info.value.code == "json_duplicate_member"


def test_payload_duplicate_member_rejected(harness):
    now = harness.clock.now()
    text = (
        '{"iss":"%s","sub":"u","aud":"%s","exp":%d,"nbf":%d,"exp":%d}'
        % (ISSUER_A, AUD_A, now + 60, now, now + 600)
    )
    spec = TokenSpec(
        issuer=ISSUER_A, subject="u", audience=AUD_A, kid=harness.a.kid,
        exp=now + 60, nbf=now,
    )
    token = sign_jwt(spec, harness.a.private_key, payload_override=raw_segment(text))
    with pytest.raises(TokenValidationError) as info:
        harness.verify(token)
    assert info.value.code == "json_duplicate_member"


def test_noncanonical_base64url_in_header_rejected(harness):
    now = harness.clock.now()
    header = encode_segment({"alg": "RS256", "typ": "JWT", "kid": harness.a.kid})
    payload = encode_segment(
        {"iss": ISSUER_A, "sub": "u", "aud": AUD_A, "exp": now + 60, "nbf": now}
    )
    signing_input = f"{header}.{payload}".encode()
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    sig = harness.a.private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    # Re-encode payload with a non-canonical suffix: swap last char for one with
    # non-zero pad bits but the same decoded bytes.
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    last = payload[-1]
    # Replace with a variant that differs only in pad bits.
    raw = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
    variant = None
    for ch in alphabet:
        candidate = payload[:-1] + ch
        try:
            if base64.urlsafe_b64decode(candidate + "=" * (-len(candidate) % 4)) == raw:
                variant = candidate
                break
        except Exception:
            continue
    assert variant is not None, "could not construct a non-canonical variant"
    if variant == payload:
        variant = payload[:-1] + ("B" if payload[-1] != "B" else "C")
    token = f"{header}.{variant}.{b64url_encode(sig)}"
    with pytest.raises(TokenValidationError) as info:
        harness.verify(token)
    assert info.value.code == "b64url_not_canonical"


# ---------------------------------------------------------------- claims

def test_missing_sub_rejected(harness):
    token = harness.mint_a()
    parts = token.split(".")
    payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
    del payload["sub"]
    # Re-sign a payload that lacks sub.
    token = sign_jwt(
        TokenSpec(
            issuer=ISSUER_A, subject="", audience=AUD_A, kid=harness.a.kid,
            exp=harness.clock.now() + 60, nbf=harness.clock.now(),
        ),
        harness.a.private_key,
        payload_override={k: v for k, v in payload.items()},
    )
    with pytest.raises(TokenValidationError) as info:
        harness.verify(token)
    assert info.value.code == "invalid_sub"


@pytest.mark.parametrize("field,value", [
    ("exp", "1800000060"),
    ("nbf", "1800000000"),
    ("exp", 1800000060.0),
    ("nbf", 1800000000.5),
    ("exp", True),
    ("nbf", False),
    ("iat", True),
])
def test_non_integer_time_fields_rejected(harness, field, value):
    now = harness.clock.now()
    payload = {"iss": ISSUER_A, "sub": "u", "aud": AUD_A, "exp": now + 60, "nbf": now}
    payload[field] = value
    token = sign_jwt(
        TokenSpec(
            issuer=ISSUER_A, subject="u", audience=AUD_A, kid=harness.a.kid,
            exp=now + 60, nbf=now,
        ),
        harness.a.private_key,
        payload_override=payload,
    )
    with pytest.raises(TokenValidationError) as info:
        harness.verify(token)
    assert info.value.code == "json_member_not_integer"


def test_missing_exp_and_nbf_rejected(harness):
    now = harness.clock.now()
    base = {"iss": ISSUER_A, "sub": "u", "aud": AUD_A, "exp": now + 60, "nbf": now}
    for missing in ("exp", "nbf"):
        payload = {k: v for k, v in base.items() if k != missing}
        token = sign_jwt(
            TokenSpec(
                issuer=ISSUER_A, subject="u", audience=AUD_A, kid=harness.a.kid,
                exp=now + 60, nbf=now,
            ),
            harness.a.private_key,
            payload_override=payload,
        )
        with pytest.raises(TokenValidationError) as info:
            harness.verify(token)
        assert info.value.code == f"missing_{missing}"


def test_nbf_boundary_is_inclusive(harness):
    now = harness.clock.now()
    token = harness.mint_a(now=now, nbf=now, ttl=60)
    assert harness.verify(token).subject == "user-1"
    harness.clock.advance(-1)
    with pytest.raises(TokenValidationError) as info:
        harness.verify(token)
    assert info.value.code == "token_not_yet_valid"


def test_exp_boundary_is_exclusive(harness):
    now = harness.clock.now()
    token = harness.mint_a(now=now, ttl=60)  # exp = now + 60
    harness.clock.set(now + 59)
    assert harness.verify(token).subject == "user-1"
    harness.clock.set(now + 60)
    with pytest.raises(TokenValidationError) as info:
        harness.verify(token)
    assert info.value.code == "token_expired"


def test_audience_must_match(harness):
    token = harness.mint_a(audience=AUD_B)
    with pytest.raises(TokenValidationError) as info:
        harness.verify(token)
    assert info.value.code == "invalid_aud"


def test_audience_array_containing_trusted_value_accepted(harness):
    now = harness.clock.now()
    payload = {"iss": ISSUER_A, "sub": "u", "aud": [AUD_B, AUD_A], "exp": now + 60, "nbf": now}
    token = sign_jwt(
        TokenSpec(
            issuer=ISSUER_A, subject="u", audience=AUD_A, kid=harness.a.kid,
            exp=now + 60, nbf=now,
        ),
        harness.a.private_key,
        payload_override=payload,
    )
    assert harness.verify(token).audience == (AUD_B, AUD_A)


def test_unconfigured_issuer_rejected(harness):
    token = harness.mint_a(issuer="https://evil.test") if False else sign_jwt(
        TokenSpec(
            issuer="https://evil.test", subject="u", audience=AUD_A,
            kid=harness.a.kid, exp=harness.clock.now() + 60, nbf=harness.clock.now(),
        ),
        harness.a.private_key,
    )
    with pytest.raises(TokenValidationError) as info:
        harness.verify(token)
    assert info.value.code == "unknown_issuer"


def test_signature_is_actually_checked(harness):
    other = __import__("jwt_service.issuer", fromlist=["generate_rsa_key"]).generate_rsa_key()
    token = harness.mint_a(key=other, kid=harness.a.kid)
    with pytest.raises(TokenValidationError) as info:
        harness.verify(token)
    assert info.value.code == "signature_invalid"


def test_tampered_payload_rejected(harness):
    token = harness.mint_a()
    header, payload, sig = token.split(".")
    payload_obj = json.loads(base64.urlsafe_b64decode(payload + "=="))
    payload_obj["sub"] = "attacker"
    forged = encode_segment(payload_obj)
    with pytest.raises(TokenValidationError) as info:
        harness.verify(f"{header}.{forged}.{sig}")
    assert info.value.code == "signature_invalid"
