"""Concurrency: single-flight, cooldown, 64+ parallel requests, noise resistance.

All proof is based on the simulator's per-path request counter and on actual
signature verification results; no test asserts "cache hit" from a log line.
"""

from __future__ import annotations

import random
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from conftest import AUD_A, ISSUER_A, ISSUER_B, make_harness
from jwt_service.errors import KeyUnavailableError, TokenValidationError, UnknownKidError


def test_64_concurrent_requests_verystart_exactly_one_fetch():
    """64 threads start cold on two issuers -> exactly one fetch per issuer."""
    h = make_harness()
    try:
        h.sim.hold_next(1)  # hold the first issuer-A fetch so all 32 pile up
        h.sim.set_jwks(h.paths[ISSUER_B], h.b.jwks())

        now = h.clock.now()
        token_a = h.mint_a(now=now, ttl=600)
        token_b = h.mint_b(now=now, ttl=600)
        tokens = [token_a] * 32 + [token_b] * 32
        results: list[str] = []
        lock = threading.Lock()
        barrier = threading.Barrier(64)

        def run(token: str) -> None:
            barrier.wait()
            try:
                verified = h.verify(token)
                outcome = f"ok:{verified.issuer}"
            except Exception as exc:  # noqa: BLE001
                outcome = f"err:{getattr(exc, 'code', type(exc).__name__)}"
            with lock:
                results.append(outcome)

        with ThreadPoolExecutor(max_workers=64) as pool:
            futures = [pool.submit(run, token) for token in tokens]
            held = h.sim.wait_for_request(3.0)
            assert held is not None
            time.sleep(0.2)
            h.sim.release_all_held()
            for future in futures:
                future.result(timeout=20)

        assert len(results) == 64
        assert results.count(f"ok:{ISSUER_A}") == 32
        assert results.count(f"ok:{ISSUER_B}") == 32
        assert h.sim.request_count(h.paths[ISSUER_A]) == 1
        assert h.sim.request_count(h.paths[ISSUER_B]) == 1
        assert h.cache_a.stats()["fetch_attempts"] == 1
        assert h.cache_b.stats()["fetch_attempts"] == 1
        assert h.cache_a.stats()["published"] == 1
        assert h.cache_b.stats()["published"] == 1
    finally:
        h.sim.stop()


def test_random_unknown_kids_merge_into_one_inflight_refresh():
    """128 distinct random kids => one in-flight fetch, no per-kid fetches."""
    h = make_harness()
    try:
        # Establish a good snapshot first (so the unknown kids are truly unknown).
        assert h.verify(h.mint_a(ttl=600)).subject == "user-1"
        h.sim.drain()
        h.clock.advance(5)  # cooldown elapsed; automatic refresh permitted
        h.sim.hold_next(1)

        rng = random.Random(20261117)
        kids = [f"random-{rng.getrandbits(64):016x}" for _ in range(128)]
        tokens = []
        for kid in kids:
            tokens.append(h.mint_a(kid=kid, ttl=600))

        outcomes: list[str] = []
        lock = threading.Lock()
        barrier = threading.Barrier(len(tokens))

        def run(token: str) -> None:
            barrier.wait()
            try:
                h.verify(token)
                outcome = "ok"
            except Exception as exc:  # noqa: BLE001
                outcome = getattr(exc, "code", type(exc).__name__)
            with lock:
                outcomes.append(outcome)

        with ThreadPoolExecutor(max_workers=len(tokens)) as pool:
            futures = [pool.submit(run, token) for token in tokens]
            held = h.sim.wait_for_request(3.0)
            assert held is not None
            time.sleep(0.3)
            h.sim.release_all_held()
            for future in futures:
                future.result(timeout=30)

        assert outcomes.count("unknown_kid") == len(tokens), outcomes[:10]
        # Exactly one additional fetch, despite 128 distinct unknown kids.
        assert h.sim.request_count(h.paths[ISSUER_A]) == 2
    finally:
        h.sim.stop()


def test_cooldown_limits_refresh_starts_under_kid_flood():
    """Attacker cycling kids cannot start fetches faster than one per 5 s."""
    h = make_harness()
    try:
        assert h.verify(h.mint_a(ttl=600)).subject == "user-1"
        base = h.sim.request_count(h.paths[ISSUER_A])
        now = h.clock.now()

        # 200 requests with 200 distinct unknown kids, spread over 4 s of
        # injected time (which is less than the 5 s start-rate cooldown).
        for i in range(200):
            if i % 50 == 0 and i:
                h.clock.advance(1)  # 1..3 seconds total elapse over the flood
            token = h.mint_a(kid=f"flood-{i:04d}", ttl=600)
            try:
                h.verify(token)
            except UnknownKidError:
                pass
            except KeyUnavailableError:
                pass
        assert h.clock.now() - now == 3
        # 200 unknown kids produced zero additional fetches during the window.
        assert h.sim.request_count(h.paths[ISSUER_A]) == base

        # After the cooldown window, exactly one more fetch is allowed, and the
        # whole subsequent flood merges into that single attempt.
        h.clock.advance(2)
        for i in range(200, 260):
            token = h.mint_a(kid=f"flood-{i:04d}", ttl=600)
            try:
                h.verify(token)
            except UnknownKidError:
                pass
        assert h.sim.request_count(h.paths[ISSUER_A]) == base + 1
        assert h.cache_a.stats()["fetch_attempts"] == base + 1
    finally:
        h.sim.stop()


def test_cooldown_allows_one_refresh_after_window():
    h = make_harness()
    try:
        assert h.verify(h.mint_a(ttl=600)).subject == "user-1"
        base = h.sim.request_count(h.paths[ISSUER_A])
        now = h.clock.now()

        h.clock.advance(4)
        _expect_error(h, h.mint_a(kid="a", ttl=600), UnknownKidError)
        assert h.sim.request_count(h.paths[ISSUER_A]) == base  # still cooling

        h.clock.advance(1)  # now == last_start + 5
        _expect_error(h, h.mint_a(kid="b", ttl=600), UnknownKidError)
        assert h.sim.request_count(h.paths[ISSUER_A]) == base + 1

        # Immediately after that refresh starts, a new kid is still blocked.
        _expect_error(h, h.mint_a(kid="c", ttl=600), UnknownKidError)
        assert h.sim.request_count(h.paths[ISSUER_A]) == base + 1
        assert h.clock.now() - now == 5
    finally:
        h.sim.stop()


def test_cooldown_is_per_issuer():
    h = make_harness()
    try:
        assert h.verify(h.mint_a(ttl=600)).subject == "user-1"
        assert h.verify(h.mint_b(ttl=600)).subject == "user-1"
        h.clock.advance(5)
        unknown_a = h.mint_a(kid="new-a", ttl=600)
        unknown_b = h.mint_b(kid="new-b", ttl=600)
        _expect_error(h, unknown_a, UnknownKidError)
        _expect_error(h, unknown_b, UnknownKidError)
        assert h.sim.request_count(h.paths[ISSUER_A]) == 2
        assert h.sim.request_count(h.paths[ISSUER_B]) == 2
    finally:
        h.sim.stop()


def test_cooldown_blocks_hammering_even_after_refresh_completes():
    h = make_harness()
    try:
        assert h.verify(h.mint_a(ttl=600)).subject == "user-1"
        base = h.sim.request_count(h.paths[ISSUER_A])
        h.clock.advance(5)
        _expect_error(h, h.mint_a(kid="x1", ttl=600), UnknownKidError)
        assert h.sim.request_count(h.paths[ISSUER_A]) == base + 1
        # Refresh is complete, but the cooldown still gates a second start.
        assert h.cache_a.stats()["in_flight"] is None
        for i in range(10):
            _expect_error(h, h.mint_a(kid=f"x{i+2}", ttl=600), UnknownKidError)
        assert h.sim.request_count(h.paths[ISSUER_A]) == base + 1
    finally:
        h.sim.stop()


def test_admin_refresh_still_advances_cooldown():
    h = make_harness()
    try:
        assert h.verify(h.mint_a(ttl=600)).subject == "user-1"
        base = h.sim.request_count(h.paths[ISSUER_A])
        h.cache_a.force_refresh()
        assert h.sim.request_count(h.paths[ISSUER_A]) == base + 1
        # Automatic refresh is now blocked by the cooldown set by the admin call.
        _expect_error(h, h.mint_a(kid="y", ttl=600), UnknownKidError)
        assert h.sim.request_count(h.paths[ISSUER_A]) == base + 1
    finally:
        h.sim.stop()


def test_many_parallel_valid_verifications_after_rotation():
    """64 parallel verifications against a rotated key set all use the new snapshot."""
    h = make_harness()
    try:
        old = h.mint_a(ttl=900)
        assert h.verify(old).subject == "user-1"

        new_key = _gen()
        h.publish_keys(ISSUER_A, [("key-1", new_key.public_key())])
        h.clock.advance(60)
        h.cache_a.force_refresh()

        new_tokens = [
            h.a.mint(now=h.clock.now(), kid="key-1", key=new_key, ttl=900, sub=f"u{i}")
            for i in range(32)
        ]
        mixed = new_tokens + [old] * 32
        outcomes: dict[str, int] = {}
        lock = threading.Lock()
        barrier = threading.Barrier(64)

        def run(token: str) -> None:
            barrier.wait()
            try:
                h.verify(token)
                key = "new_ok" if token in set(new_tokens) else "old_ok"
            except TokenValidationError as exc:
                key = f"old_{exc.code}" if token == old else "new_fail"
            with lock:
                outcomes[key] = outcomes.get(key, 0) + 1

        with ThreadPoolExecutor(max_workers=64) as pool:
            list(pool.map(run, mixed))
        assert outcomes.get("new_ok") == 32, outcomes
        assert outcomes.get("old_signature_invalid") == 32, outcomes
    finally:
        h.sim.stop()


def test_expired_snapshot_with_many_waiters_fails_closed():
    """All 64 waiters must fail closed, none may see a stale key."""
    h = make_harness()
    try:
        token = h.mint_a(ttl=600)
        assert h.verify(token).subject == "user-1"
        h.sim.drain()
        h.clock.advance(60)
        h.sim.set_raw(h.paths[ISSUER_A], b"down", status=500)
        outcomes: list[str] = []
        lock = threading.Lock()
        barrier = threading.Barrier(64)

        def run() -> None:
            barrier.wait()
            try:
                h.verify(token)
                verdict = "ok"
            except Exception as exc:  # noqa: BLE001
                verdict = getattr(exc, "code", type(exc).__name__)
            with lock:
                outcomes.append(verdict)

        with ThreadPoolExecutor(max_workers=64) as pool:
            list(pool.map(lambda _: run(), range(64)))
        assert outcomes.count("keys_unavailable") == 64, set(outcomes)
    finally:
        h.sim.stop()


# ------------------------------------------------------------------ helpers

def _expect_error(h, token: str, kind: type[BaseException]) -> None:
    try:
        h.verify(token)
    except kind:
        return
    except Exception as exc:  # noqa: BLE001
        raise AssertionError(f"unexpected {type(exc).__name__}: {exc}") from exc
    raise AssertionError(f"expected {kind.__name__}")


def _gen():
    from jwt_service.issuer import generate_rsa_key

    return generate_rsa_key()
