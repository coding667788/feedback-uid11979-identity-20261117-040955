"""JWKS document validation: all-or-nothing publication and hard limits."""

from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from conftest import AUD_A, ISSUER_A, make_harness
from jwt_service.config import JwksLimits
from jwt_service.errors import JwksDocumentError, KeyUnavailableError
from jwt_service.issuer import generate_rsa_key
from jwt_service.jwks import parse_jwks_document, public_jwk


def _parse(document, *, limits=None, ttl=60):
    body = document if isinstance(document, bytes) else json.dumps(document).encode()
    return parse_jwks_document(
        body,
        issuer="https://unit.test",
        seq=1,
        fetched_at=1000,
        ttl_seconds=ttl,
        limits=limits or JwksLimits(),
    )


def _doc(*keys):
    return {"keys": list(keys)}


def test_valid_document_parses_and_is_immutable():
    key = generate_rsa_key()
    snapshot = _parse(_doc(public_jwk("k1", key.public_key())))
    assert snapshot.get("k1").key_size == 2048
    assert snapshot.digest and snapshot.expires_at == 1060
    with pytest.raises(TypeError):
        snapshot.keys["x"] = key.public_key()  # type: ignore[index]


@pytest.mark.parametrize(
    "document,code",
    [
        (_doc(), "jwks_no_keys"),
        ({"keys": {}}, "jwks_bad_keys"),
        ({"notkeys": []}, "jwks_bad_keys"),
        ([], "jwks_not_object"),
        (b"{", "json_invalid"),
        (b'{"keys":[],"keys":[]}', "json_duplicate_member"),
    ],
)
def test_structurally_invalid_documents_rejected(document, code):
    with pytest.raises(JwksDocumentError) as info:
        _parse(document)
    assert info.value.code == code


def test_duplicate_kid_rejects_whole_document():
    key1 = generate_rsa_key()
    key2 = generate_rsa_key()
    doc = _doc(
        public_jwk("dup", key1.public_key()),
        public_jwk("dup", key2.public_key()),
    )
    with pytest.raises(JwksDocumentError) as info:
        _parse(doc)
    assert info.value.code == "jwks_duplicate_kid"


def test_private_key_material_rejected():
    key = generate_rsa_key()
    jwk = public_jwk("k1", key.public_key())
    numbers = key.private_numbers()
    jwk["d"] = "AAAA"
    with pytest.raises(JwksDocumentError) as info:
        _parse(_doc(jwk))
    assert info.value.code == "jwk_private_material"
    assert numbers is not None


@pytest.mark.parametrize(
    "mutate,code",
    [
        (lambda j: j.update(kty="EC"), "jwk_not_rsa"),
        (lambda j: j.update(kty="oct"), "jwk_not_rsa"),
        (lambda j: j.update(use="enc"), "jwk_wrong_use"),
        (lambda j: j.update(alg="RS512"), "jwk_wrong_alg"),
        (lambda j: j.update(key_ops=["sign"]), "jwk_bad_key_ops"),
        (lambda j: j.update(kid=None), "jwk_bad_kid"),
        (lambda j: j.pop("kid"), "jwk_bad_kid"),
        (lambda j: j.update(e="AQAB="), "b64url_bad_charset"),
        (lambda j: j.update(n="!!notbase64!!"), "b64url_bad_charset"),
        (lambda j: j.update(e="AAEAAQ"), "jwk_non_minimal_integer"),
        (lambda j: j.update(n="AAAA"), "jwk_non_minimal_integer"),
    ],
)
def test_malformed_key_members_rejected(mutate, code):
    key = generate_rsa_key()
    jwk = public_jwk("k1", key.public_key())
    mutate(jwk)
    with pytest.raises(JwksDocumentError) as info:
        _parse(_doc(jwk))
    assert info.value.code == code


def test_modulus_below_2048_rejected():
    small = generate_rsa_key(bits=1024)
    with pytest.raises(JwksDocumentError) as info:
        _parse(_doc(public_jwk("k1", small.public_key())))
    assert info.value.code == "jwk_modulus_too_small"


def test_ec_public_key_cannot_be_smuggled():
    ec_key = ec.generate_private_key(ec.SECP256R1())
    numbers = ec_key.public_key().public_numbers()
    import base64

    def enc(i, size):
        return base64.urlsafe_b64encode(i.to_bytes(size, "big")).rstrip(b"=").decode()

    jwk = {
        "kty": "EC",
        "kid": "ec1",
        "crv": "P-256",
        "x": enc(numbers.x, 32),
        "y": enc(numbers.y, 32),
    }
    with pytest.raises(JwksDocumentError) as info:
        _parse(_doc(jwk))
    assert info.value.code == "jwk_not_rsa"


def test_key_count_limit():
    keys = [public_jwk(f"k{i}", generate_rsa_key().public_key()) for i in range(3)]
    limits = JwksLimits(max_keys=2)
    with pytest.raises(JwksDocumentError) as info:
        _parse(_doc(*keys), limits=limits)
    assert info.value.code == "jwks_too_many_keys"


def test_byte_limit():
    key = public_jwk("k1", generate_rsa_key().public_key())
    key["padding"] = "A" * 4096
    limits = JwksLimits(max_bytes=1024)
    with pytest.raises(JwksDocumentError) as info:
        _parse(_doc(key), limits=limits)
    assert info.value.code == "jwks_too_large"


def test_modulus_too_large_for_configured_limit():
    big = generate_rsa_key(bits=4096)
    limits = JwksLimits(max_rsa_bits=3072)
    with pytest.raises(JwksDocumentError) as info:
        _parse(_doc(public_jwk("k1", big.public_key())), limits=limits)
    assert info.value.code == "jwk_modulus_too_large"


# ----------------------------------------------------- atomicity in the cache

def test_malformed_document_never_replaces_good_snapshot():
    h = make_harness()
    try:
        assert h.verify(h.mint_a()).subject == "user-1"
        good = h.cache_a.snapshot()
        # A document that is valid JSON but has a bad key must be rejected whole.
        bad = {"keys": [public_jwk("key-1", h.a.private_key.public_key())]}
        bad["keys"].append({"kty": "RSA", "kid": "bad", "n": "AAAA", "e": "AQAB"})
        h.sim.set_jwks(h.paths[ISSUER_A], bad)
        h.clock.advance(60)  # allow automatic refresh
        with pytest.raises(Exception):
            h.cache_a.force_refresh()
        after = h.cache_a.snapshot()
        assert after is good, "snapshot object must not be mutated or replaced"
        assert h.cache_a.stats()["last_error"] == "jwk_non_minimal_integer"
    finally:
        h.sim.stop()


def test_refresh_failure_keeps_unexpired_snapshot_serving():
    h = make_harness()
    try:
        token = h.mint_a(ttl=300)
        assert h.verify(token).subject == "user-1"
        h.sim.set_raw(h.paths[ISSUER_A], b"server error", status=500)
        h.clock.advance(30)  # snapshot still fresh (60s TTL)
        with pytest.raises(Exception):
            h.cache_a.force_refresh()
        # Old snapshot is still valid and must serve.
        assert h.verify(token).subject == "user-1"
    finally:
        h.sim.stop()


def test_expired_snapshot_with_failed_refresh_fails_closed():
    h = make_harness()
    try:
        token = h.mint_a(ttl=600)
        assert h.verify(token).subject == "user-1"
        h.sim.set_raw(h.paths[ISSUER_A], b"down", status=503)
        h.clock.advance(60)  # expires_at == fetched_at + 60, now == expires_at
        with pytest.raises(KeyUnavailableError) as info:
            h.verify(token)
        assert info.value.code == "keys_unavailable"
        # Repeated attempts cannot extend the old snapshot's lifetime.
        before = h.cache_a.snapshot()
        with pytest.raises(KeyUnavailableError):
            h.verify(token)
        assert h.cache_a.snapshot() is before
        assert before.expires_at == before.fetched_at + 60
    finally:
        h.sim.stop()


def test_empty_document_rejected():
    with pytest.raises(JwksDocumentError) as info:
        _parse(b"{}")
    assert info.value.code == "jwks_bad_keys"


def test_oversized_kid_rejected():
    key = generate_rsa_key()
    jwk = public_jwk("x" * 300, key.public_key())
    with pytest.raises(JwksDocumentError) as info:
        _parse(_doc(jwk))
    assert info.value.code == "jwk_bad_kid"


def test_even_modulus_rejected():
    key = generate_rsa_key()
    jwk = public_jwk("k1", key.public_key())
    # Clear the low bit of n to make it even.  RSA moduli are odd, so this is
    # structurally invalid and must be rejected before any key is constructed.
    import base64

    raw = bytearray(base64.urlsafe_b64decode(jwk["n"] + "=" * (-len(jwk["n"]) % 4)))
    raw[-1] &= 0xFE
    jwk["n"] = base64.urlsafe_b64encode(bytes(raw)).rstrip(b"=").decode()
    with pytest.raises(JwksDocumentError) as info:
        _parse(_doc(jwk))
    assert info.value.code in ("jwk_bad_modulus", "jwk_bad_key")


def test_two_issuers_allow_same_document_independently():
    # Sanity: identical bytes under a different issuer are still self-contained.
    key = generate_rsa_key()
    body = json.dumps(_doc(public_jwk("k1", key.public_key()))).encode()
    one = parse_jwks_document(
        body, issuer="https://one", seq=3, fetched_at=10, ttl_seconds=60,
        limits=JwksLimits(),
    )
    two = parse_jwks_document(
        body, issuer="https://two", seq=9, fetched_at=10, ttl_seconds=60,
        limits=JwksLimits(),
    )
    assert one.keys["k1"] is not two.keys["k1"]
    assert one.issuer != two.issuer
