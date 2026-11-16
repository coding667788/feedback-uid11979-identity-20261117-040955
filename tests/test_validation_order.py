"""Ordering of validation steps: cheap rejects must happen before any I/O."""

from __future__ import annotations

import pytest

from conftest import AUD_A, AUD_B, ISSUER_A, ISSUER_B
from jwt_service.errors import TokenValidationError
from jwt_service.issuer import TokenSpec, sign_jwt


def _token(h, **overrides) -> str:
    now = h.clock.now()
    spec = TokenSpec(
        issuer=overrides.get("iss", ISSUER_A),
        subject=overrides.get("sub", "u"),
        audience=overrides.get("aud", AUD_A),
        kid=overrides.get("kid", h.a.kid),
        exp=overrides.get("exp", now + 60),
        nbf=overrides.get("nbf", now),
    )
    return sign_jwt(spec, overrides.get("key", h.a.private_key))


def test_unknown_issuer_causes_no_fetch(harness):
    token = _token(harness, iss="https://not-configured.test")
    with pytest.raises(TokenValidationError) as info:
        harness.verify(token)
    assert info.value.code == "unknown_issuer"
    assert harness.sim.request_count() == 0


def test_wrong_audience_causes_no_fetch(harness):
    token = _token(harness, aud=AUD_B)  # B's audience, A's issuer
    with pytest.raises(TokenValidationError) as info:
        harness.verify(token)
    assert info.value.code == "invalid_aud"
    assert harness.sim.request_count() == 0


def test_expired_token_causes_no_fetch(harness):
    now = harness.clock.now()
    token = _token(harness, exp=now - 1, nbf=now - 100)
    with pytest.raises(TokenValidationError) as info:
        harness.verify(token)
    assert info.value.code == "token_expired"
    assert harness.sim.request_count() == 0


def test_not_yet_valid_token_causes_no_fetch(harness):
    now = harness.clock.now()
    token = _token(harness, nbf=now + 1, exp=now + 60)
    with pytest.raises(TokenValidationError) as info:
        harness.verify(token)
    assert info.value.code == "token_not_yet_valid"
    assert harness.sim.request_count() == 0


def test_bad_algorithm_causes_no_fetch(harness):
    now = harness.clock.now()
    token = sign_jwt(
        TokenSpec(
            issuer=ISSUER_A, subject="u", audience=AUD_A, kid="key-1",
            exp=now + 60, nbf=now, alg="RS384",
        ),
        harness.a.private_key,
    )
    with pytest.raises(TokenValidationError) as info:
        harness.verify(token)
    assert info.value.code == "algorithm_not_allowed"
    assert harness.sim.request_count() == 0


def test_unknown_issuer_token_signed_by_trusted_key_still_rejected(harness):
    """Trust is keyed on iss, not on who happens to hold a trusted key."""
    harness.verify(harness.mint_b(ttl=300))  # populate B
    token = harness.mint_b(ttl=300)
    parts = token.split(".")
    import json
    from jwt_service.strict_json import b64url_decode_strict
    payload = json.loads(b64url_decode_strict(parts[1]))
    payload["iss"] = "https://issuer-b.test.evil"
    from jwt_service.issuer import encode_segment

    # Re-sign with B's key so the signature is genuinely valid for B.
    forged = sign_jwt(
        TokenSpec(
            issuer="https://issuer-b.test.evil", subject=payload["sub"],
            audience=payload["aud"], kid="key-1",
            exp=payload["exp"], nbf=payload["nbf"],
        ),
        harness.b.private_key,
    )
    with pytest.raises(TokenValidationError) as info:
        harness.verify(forged)
    assert info.value.code == "unknown_issuer"
    assert harness.sim.request_count() == 1  # only the earlier legitimate fetch
