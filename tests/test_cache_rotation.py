"""Snapshot lifecycle: rotation, atomicity, expiry, late-response ordering."""

from __future__ import annotations

import threading
import time

import pytest

from conftest import AUD_A, AUD_B, ISSUER_A, ISSUER_B, make_harness
from jwt_service.errors import KeyUnavailableError, TokenValidationError, UnknownKidError
from jwt_service.issuer import generate_rsa_key


def test_initial_verify_triggers_exactly_one_fetch(harness):
    token = harness.mint_a()
    assert harness.sim.request_count() == 0
    assert harness.verify(token).subject == "user-1"
    assert harness.sim.request_count(harness.paths[ISSUER_A]) == 1
    # A second verify within the snapshot's lifetime must not fetch again.
    assert harness.verify(token).subject == "user-1"
    assert harness.sim.request_count(harness.paths[ISSUER_A]) == 1


def test_snapshot_expiry_boundary(harness):
    token = harness.mint_a(ttl=600)
    harness.verify(token)
    snap = harness.cache_a.snapshot()
    assert snap.expires_at == snap.fetched_at + 60
    # 59 seconds later the snapshot is still usable.
    harness.clock.set(snap.fetched_at + 59)
    assert harness.verify(token).subject == "user-1"
    assert harness.sim.request_count(harness.paths[ISSUER_A]) == 1
    # At exactly expires_at it is stale and a refresh must be attempted.
    harness.clock.set(snap.fetched_at + 60)
    assert harness.verify(token).subject == "user-1"
    assert harness.sim.request_count(harness.paths[ISSUER_A]) == 2


def test_rotated_out_kid_rejects_old_token_after_publish(harness):
    old_token = harness.mint_a(kid=harness.a.kid, ttl=600)
    assert harness.verify(old_token).subject == "user-1"

    new_key = generate_rsa_key()
    harness.publish_keys(ISSUER_A, [("key-2", new_key.public_key())])
    harness.clock.advance(60)  # previous snapshot now stale
    result = harness.cache_a.force_refresh()
    assert result.snapshot.keys.keys() == {"key-2"}

    new_token = harness.a.mint(now=harness.clock.now(), kid="key-2", key=new_key, ttl=600)
    assert harness.verify(new_token).subject == "user-1"
    with pytest.raises(UnknownKidError) as info:
        harness.verify(old_token)
    assert info.value.code == "unknown_kid"


def test_same_kid_replaced_public_key_invalidates_old_tokens(harness):
    old_token = harness.mint_a(kid="key-1", ttl=600)
    assert harness.verify(old_token).subject == "user-1"

    replacement = generate_rsa_key()
    harness.publish_keys(ISSUER_A, [("key-1", replacement.public_key())])
    harness.clock.advance(60)
    result = harness.cache_a.force_refresh()
    assert result.snapshot.keys["key-1"].public_numbers() == replacement.public_key().public_numbers()

    # Old token: same kid, old key -> signature must fail against the new key.
    with pytest.raises(TokenValidationError) as info:
        harness.verify(old_token)
    assert info.value.code == "signature_invalid"

    new_token = harness.a.mint(now=harness.clock.now(), kid="key-1", key=replacement, ttl=600)
    assert harness.verify(new_token).subject == "user-1"


def test_successful_verification_is_never_cached_across_snapshot_change(harness):
    """A token that verified once must be re-checked against the new snapshot."""
    token = harness.mint_a(ttl=600)
    assert harness.verify(token).subject == "user-1"
    seq_before = harness.cache_a.snapshot().seq

    harness.publish_keys(ISSUER_A, [("different", generate_rsa_key().public_key())])
    result = harness.cache_a.force_refresh()  # bypasses cooldown on purpose
    assert result.snapshot.seq > seq_before

    with pytest.raises(UnknownKidError):
        harness.verify(token)


def test_failed_refresh_keeps_fresh_snapshot_and_does_not_extend_ttl(harness):
    token = harness.mint_a(ttl=600)
    harness.verify(token)
    snap = harness.cache_a.snapshot()
    harness.sim.set_raw(harness.paths[ISSUER_A], b"boom", status=500)
    harness.clock.set(snap.expires_at - 1)
    with pytest.raises(Exception):
        harness.cache_a.force_refresh()
    assert harness.verify(token).subject == "user-1"
    assert harness.cache_a.snapshot().expires_at == snap.expires_at

    # One second later the snapshot is expired and there is no fallback.
    harness.clock.set(snap.expires_at)
    with pytest.raises(KeyUnavailableError):
        harness.verify(token)


def test_fetch_timeout_fails_closed_once_expired(harness):
    # Short client-side timeout, then hold the simulator response past it.
    h = make_harness(fetch_timeout=0.25)
    try:
        token = h.mint_a(ttl=600)
        h.sim.hold_next(1)
        started = threading.Event()

        box: dict[str, object] = {}

        def attempt() -> None:
            started.set()
            try:
                h.cache_a.force_refresh()
                box["outcome"] = "ok"
            except Exception as exc:  # noqa: BLE001 - test assertion below
                box["outcome"] = type(exc).__name__
                box["code"] = getattr(exc, "code", None)

        thread = threading.Thread(target=attempt)
        thread.start()
        started.wait()
        record = h.sim.wait_for_request(2.0)
        assert record is not None
        thread.join(timeout=5)
        assert not thread.is_alive()
        assert box["outcome"] == "RefreshFailedError"
        assert box["code"] in ("jwks_fetch_failed", "jwks_empty")
        # No snapshot was ever published, so verification fails closed.
        h.sim.release_all_held()
        with pytest.raises(KeyUnavailableError):
            h.verify(token)
    finally:
        h.sim.stop()


def test_slow_auto_refresh_does_not_block_cached_verification(harness):
    token = harness.mint_a(ttl=600)
    assert harness.verify(token).subject == "user-1"
    snap = harness.cache_a.snapshot()
    harness.sim.drain()

    # Snapshot is still fresh, but the 5 s start-rate cooldown has elapsed, so
    # an unknown kid may start an automatic refresh.  That fetch hangs.
    harness.clock.set(snap.fetched_at + 5)
    harness.sim.hold_next(1)
    unknown_token = harness.mint_a(kid="attacker-kid-0001", ttl=600)
    result: dict[str, object] = {}

    def slow_verify() -> None:
        try:
            harness.verify(unknown_token)
            result["outcome"] = "ok"
        except Exception as exc:  # noqa: BLE001
            result["outcome"] = getattr(exc, "code", type(exc).__name__)

    thread = threading.Thread(target=slow_verify, daemon=True)
    thread.start()
    record = harness.sim.wait_for_request(2.0)
    assert record is not None
    assert harness.cache_a.stats()["in_flight"] is not None

    # While the refresh is held, a cached token must still verify promptly
    # without any network access.
    began = time.monotonic()
    for _ in range(20):
        assert harness.verify(token).subject == "user-1"
    elapsed = time.monotonic() - began
    assert elapsed < 0.5, f"cached verification blocked for {elapsed:.2f}s"
    assert harness.sim.request_count(harness.paths[ISSUER_A]) == 2

    harness.sim.release_all_held()
    thread.join(timeout=5)
    assert not thread.is_alive()
    assert result["outcome"] == "unknown_kid"


def test_old_response_cannot_overwrite_newer_snapshot(harness):
    """The interleaving the task explicitly asks for.

    Timeline (all on the injected clock):
      t+0  snapshot 1 (key A) published
      t+5  automatic refresh starts; simulator captures body(A) then blocks
      t+6  admin refresh runs, serves body(B), publishes snapshot 2
      t+7  the held automatic response for body(A) is released -> must be
           discarded, not published
    """
    token_a = harness.mint_a(ttl=900)
    assert harness.verify(token_a).subject == "user-1"
    assert harness.cache_a.snapshot().seq == 1
    harness.sim.drain()

    key_b = generate_rsa_key()
    # At arrival time the simulator still serves key A.
    harness.sim.set_jwks(harness.paths[ISSUER_A], harness.a.jwks())
    harness.clock.advance(5)
    harness.sim.hold_next(1)

    auto_outcome: dict[str, object] = {}

    def auto_refresh() -> None:
        try:
            harness.verify(harness.mint_a(kid="brand-new-kid", ttl=900))
        except Exception as exc:  # noqa: BLE001
            auto_outcome["code"] = getattr(exc, "code", type(exc).__name__)

    thread = threading.Thread(target=auto_refresh, daemon=True)
    thread.start()
    held = harness.sim.wait_for_request(2.0)
    assert held is not None
    assert held.body_digest  # body captured before blocking

    # New document is available; admin refresh publishes it immediately.
    harness.publish_keys(ISSUER_A, [("key-1", key_b.public_key())])
    harness.clock.advance(1)
    before = harness.cache_a.snapshot().seq
    admin = harness.cache_a.force_refresh()
    assert admin.op_id > before
    assert admin.snapshot.seq == admin.op_id
    assert admin.snapshot.keys["key-1"].public_numbers() == key_b.public_key().public_numbers()

    # Now release the stale automatic response.
    held.release()
    thread.join(timeout=5)
    assert not thread.is_alive()

    final = harness.cache_a.snapshot()
    assert final.seq == admin.snapshot.seq, "a late, older response must not overwrite the newer snapshot"
    assert final.digest == admin.snapshot.digest
    stats = harness.cache_a.stats()
    assert stats["discarded"] >= 1
    assert stats["last_error"] is None

    # The rotation is visible: the old token is now rejected, new one accepted.
    new_token = harness.a.mint(now=harness.clock.now(), kid="key-1", key=key_b, ttl=900)
    assert harness.verify(new_token).subject == "user-1"
    with pytest.raises(TokenValidationError):
        harness.verify(token_a)
    assert auto_outcome["code"] in ("unknown_kid", "signature_invalid")


def test_admin_refresh_bypasses_cooldown(harness):
    token = harness.mint_a(ttl=600)
    assert harness.verify(token).subject == "user-1"
    assert harness.cache_a.stats()["next_auto_refresh_at"] == harness.clock.now() + 5
    # Immediately after the automatic fetch, an admin refresh still runs.
    result = harness.cache_a.force_refresh()
    assert result.op_id == 2
    assert harness.sim.request_count(harness.paths[ISSUER_A]) == 2


def test_admin_refresh_does_not_wait_for_held_auto_refresh(harness):
    token = harness.mint_a(ttl=600)
    harness.verify(token)
    harness.sim.drain()
    harness.clock.advance(60)  # stale -> automatic refresh allowed
    harness.sim.hold_next(1)
    harness.sim.set_jwks(harness.paths[ISSUER_A], harness.a.jwks())

    unknown = harness.mint_a(kid="never-seen", ttl=600)
    thread = threading.Thread(target=lambda: _swallow(harness.verify, unknown), daemon=True)
    thread.start()
    held = harness.sim.wait_for_request(2.0)
    assert held is not None

    # Admin refresh must complete while the earlier request is still held.
    began = time.monotonic()
    result = harness.cache_a.force_refresh()
    elapsed = time.monotonic() - began
    assert elapsed < 1.0, f"admin refresh waited on the held request ({elapsed:.2f}s)"
    assert result.snapshot.seq == result.op_id

    held.release()
    thread.join(timeout=5)
    assert harness.cache_a.snapshot().seq == result.snapshot.seq


def test_concurrent_admin_refreshes_are_single_flight(harness):
    token = harness.mint_a(ttl=600)
    harness.verify(token)
    harness.sim.drain()
    harness.sim.hold_next(1)
    results: list[int] = []
    errors: list[str] = []

    def admin() -> None:
        try:
            results.append(harness.cache_a.force_refresh().op_id)
        except Exception as exc:  # noqa: BLE001
            errors.append(getattr(exc, "code", type(exc).__name__))

    threads = [threading.Thread(target=admin) for _ in range(8)]
    for t in threads:
        t.start()
    held = harness.sim.wait_for_request(2.0)
    assert held is not None
    time.sleep(0.3)  # let the other admin callers join the in-flight operation
    assert harness.cache_a.stats()["waiters"] is not None
    harness.sim.release_all_held()
    for t in threads:
        t.join(timeout=10)
    assert not errors
    assert len(results) == 8
    # All eight calls observed the same published operation.
    assert set(results) == {results[0]}
    # Exactly two fetches total: the initial one and this single admin fetch.
    assert harness.sim.request_count(harness.paths[ISSUER_A]) == 2


def test_cross_issuer_same_kid_is_isolated(harness):
    # Both issuers happen to use kid "key-1" but with different keys.
    assert harness.a.kid == harness.b.kid == "key-1"
    token_a = harness.mint_a(ttl=600)
    token_b = harness.mint_b(ttl=600)
    verified_a = harness.verify(token_a)
    verified_b = harness.verify(token_b)
    assert verified_a.issuer == ISSUER_A and verified_b.issuer == ISSUER_B
    assert verified_a.snapshot_digest != verified_b.snapshot_digest

    # A token claiming issuer A but signed by B's key for the same kid must fail.
    forged = harness.b.mint(now=harness.clock.now(), ttl=600)
    payload = _replace_claim(forged, "iss", ISSUER_A)
    payload = _replace_claim(payload, "aud", AUD_A)
    with pytest.raises(TokenValidationError) as info:
        harness.verify(payload)
    assert info.value.code == "signature_invalid"

    # A token claiming issuer B but signed by A's key must fail too.
    forged_b = harness.a.mint(now=harness.clock.now(), ttl=600)
    forged_b = _replace_claim(forged_b, "iss", ISSUER_B)
    forged_b = _replace_claim(forged_b, "aud", AUD_B)
    with pytest.raises(TokenValidationError) as info:
        harness.verify(forged_b)
    assert info.value.code == "signature_invalid"


def test_each_issuer_has_its_own_snapshot_and_fetch_path(harness):
    harness.verify(harness.mint_a(ttl=600))
    harness.verify(harness.mint_b(ttl=600))
    assert harness.sim.request_count(harness.paths[ISSUER_A]) == 1
    assert harness.sim.request_count(harness.paths[ISSUER_B]) == 1
    assert harness.cache_a.snapshot().issuer == ISSUER_A
    assert harness.cache_b.snapshot().issuer == ISSUER_B


def test_issuer_a_failure_does_not_affect_issuer_b(harness):
    token_a = harness.mint_a(ttl=600)
    token_b = harness.mint_b(ttl=600)
    harness.verify(token_a)
    harness.verify(token_b)
    harness.sim.set_raw(harness.paths[ISSUER_A], b"down", status=500)
    harness.clock.advance(60)  # both stale
    with pytest.raises(KeyUnavailableError):
        harness.verify(token_a)
    assert harness.verify(token_b).subject == "user-1"


# ------------------------------------------------------------------ helpers

def _swallow(func, *args):
    try:
        func(*args)
    except Exception:  # noqa: BLE001
        pass


def _replace_claim(token: str, name: str, value: str) -> str:
    """Re-encode a payload with one claim changed (invalidates the signature)."""
    import base64
    import json

    from jwt_service.issuer import encode_segment

    header, payload, _sig = token.split(".")
    data = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    data[name] = value
    return f"{header}.{encode_segment(data)}.{_sig}"
