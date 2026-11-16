"""Two harder interleavings around admin/automatic refresh coordination."""

from __future__ import annotations

import threading
import time

from conftest import ISSUER_A
from jwt_service.issuer import generate_rsa_key


def test_admin_refresh_joining_inflight_admin_op(harness):
    """An admin refresh joins an in-flight admin op instead of fetching again.

    Timeline:
      t+0  admin op starts; the simulator captures body(A) then blocks
      t+1  a second admin call arrives and joins op 1 (single-flight)
      t+2  the served document is replaced with body(B)
      t+3  op 1 is released and publishes its captured body(A)
      t+4  a later admin refresh fetches body(B) and publishes it

    The property under test: a joining caller cannot publish anything, so it
    can never move the cache backwards; and once the swap is fetched, the
    newer generation always wins.
    """
    token_a = harness.mint_a(ttl=900)
    assert harness.verify(token_a).subject == "user-1"
    harness.sim.drain()

    seen: list[tuple[str, int, str]] = []
    lock = threading.Lock()

    def admin(tag: str) -> None:
        result = harness.cache_a.force_refresh()
        with lock:
            seen.append((tag, result.op_id, result.snapshot.digest))

    harness.sim.hold_next(1)
    first = threading.Thread(target=admin, args=("first",), daemon=True)
    first.start()
    held = harness.sim.wait_for_request(2.0)
    assert held is not None

    second = threading.Thread(target=admin, args=("second",), daemon=True)
    second.start()
    time.sleep(0.3)
    stats = harness.cache_a.stats()
    assert stats["in_flight"]["kind"] == "admin"
    assert stats["waiters"] >= 1

    key_b = generate_rsa_key()
    harness.publish_keys(ISSUER_A, [("key-1", key_b.public_key())])
    harness.sim.release_all_held()
    first.join(timeout=10)
    second.join(timeout=10)
    assert not first.is_alive() and not second.is_alive()

    assert len(seen) == 2, seen
    assert len({op for _, op, _ in seen}) == 1, seen
    assert seen[0][2] == seen[1][2], "both joiners must observe one snapshot"
    published = harness.cache_a.snapshot()

    # A further admin refresh picks up the swapped document and advances.
    harness.sim.drain()
    third = harness.cache_a.force_refresh()
    assert third.op_id > published.seq
    assert third.snapshot.keys["key-1"].public_numbers() == key_b.public_key().public_numbers()
    assert harness.cache_a.snapshot().digest == third.snapshot.digest


def test_auto_waiters_joined_to_superseded_op_use_newer_snapshot(harness):
    """Waiters whose automatic op was superseded must not receive its error."""
    assert harness.verify(harness.mint_a(ttl=900)).subject == "user-1"
    harness.sim.drain()
    harness.clock.advance(5)
    harness.sim.hold_next(1)

    outcomes: list[str] = []
    lock = threading.Lock()

    def auto() -> None:
        token = harness.mint_a(kid="brand-new", ttl=900)
        try:
            harness.verify(token)
            verdict = "ok"
        except Exception as exc:  # noqa: BLE001 - assertion below needs the code
            verdict = getattr(exc, "code", type(exc).__name__)
        with lock:
            outcomes.append(verdict)

    threads = [threading.Thread(target=auto, daemon=True) for _ in range(16)]
    for thread in threads:
        thread.start()
    held = harness.sim.wait_for_request(2.0)
    assert held is not None
    time.sleep(0.3)

    key_b = generate_rsa_key()
    harness.publish_keys(ISSUER_A, [("key-1", key_b.public_key())])
    admin = harness.cache_a.force_refresh()  # supersedes the held auto operation
    harness.sim.release_all_held()
    for thread in threads:
        thread.join(timeout=10)
    assert len(outcomes) == 16
    # The unknown kid is absent from the new snapshot, so every waiter must
    # report unknown_kid -- never keys_unavailable, and never a stale success.
    assert set(outcomes) == {"unknown_kid"}, outcomes
    assert harness.cache_a.snapshot().digest == admin.snapshot.digest
