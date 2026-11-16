"""Per-issuer JWKS snapshot cache.

Guarantees implemented here
============================

* **Atomic publication.**  A snapshot object is immutable.  A fetch result is
  parsed and validated in full *before* it is swapped in under the issuer
  lock.  A malformed document never partially replaces an older one.

* **No verification-result cache.**  ``resolve`` is called by the verifier on
  every request; a new snapshot is therefore visible to every verification
  that *starts* after the swap.  There is no "this token verified once" memo.

* **Single-flight.**  At most one *automatic* refresh per issuer is in flight.
  All concurrent unknown-kid callers join that operation instead of starting
  their own.

* **Start-rate cooldown.**  ``_next_auto_refresh_at`` advances whenever *any*
  refresh starts (automatic or forced).  An attacker cycling random ``kid``
  values cannot start automatic refreshes faster than one per
  ``auto_refresh_cooldown_seconds``.

* **Non-blocking fast path.**  A request whose ``kid`` is present in a fresh
  snapshot returns while holding the lock only for a lookup; it never waits on
  an in-flight network fetch.

* **Fail closed.**  If no fresh snapshot exists and a refresh cannot complete,
  ``KeyUnavailableError`` is raised.  Snapshot lifetime is never extended.

* **Monotonic generations (anti-overwrite).**  Every refresh gets a strictly
  increasing ``op_id``; a snapshot is published with ``seq = op_id``.  A later
  force refresh marks an earlier in-flight operation ``superseded``; a result
  is published only when ``not superseded and op_id > published_seq``.  A
  stale response that arrives after a newer snapshot can therefore never roll
  the cache back, regardless of arrival order.

Admin (forced) refresh deliberately supersedes an in-flight *automatic*
refresh: it does not wait for the slow automatic fetch, but the automatic
result is discarded.  Concurrent admin refreshes are themselves single-flight
(an admin call joins an in-flight admin operation).
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Any, Callable

from .clock import Clock
from .config import IssuerConfig, JwksLimits
from .errors import (
    JwksDocumentError,
    KeyUnavailableError,
    RefreshFailedError,
    TransportError,
    UnknownKidError,
)
from .jwks import KeySnapshot, parse_jwks_document
from .token import ResolvedKey

Fetcher = Callable[[IssuerConfig], bytes]

_INITIAL_COOLDOWN = -1  # sentinel: automatic refresh allowed immediately


class _RefreshOp:
    __slots__ = (
        "op_id",
        "kind",
        "started_at",
        "event",
        "superseded",
        "snapshot",
        "error",
        "waiters",
    )

    def __init__(self, op_id: int, kind: str, started_at: int) -> None:
        self.op_id = op_id
        self.kind = kind
        self.started_at = started_at
        self.event = threading.Event()
        self.superseded = False
        self.snapshot: KeySnapshot | None = None
        self.error: str | None = None
        self.waiters = 0


@dataclass(frozen=True, slots=True)
class RefreshResult:
    issuer: str
    snapshot: KeySnapshot
    op_id: int
    kind: str


class IssuerKeyCache:
    def __init__(
        self,
        config: IssuerConfig,
        *,
        clock: Clock,
        fetcher: Fetcher,
        limits: JwksLimits,
        ttl_seconds: int = 60,
        auto_refresh_cooldown_seconds: int = 5,
        fetch_timeout_seconds: float = 2.0,
    ) -> None:
        self.config = config
        self._clock = clock
        self._fetcher = fetcher
        self._limits = limits
        self._ttl = ttl_seconds
        self._cooldown = auto_refresh_cooldown_seconds
        self._waiter_timeout = max(fetch_timeout_seconds * 3.0, 2.0)

        self._cond = threading.Condition(threading.Lock())
        self._snapshot: KeySnapshot | None = None
        self._inflight: _RefreshOp | None = None
        self._seq = 0
        self._op_counter = 0
        self._next_auto_refresh_at = _INITIAL_COOLDOWN
        self._last_error: str | None = None
        self._attempts = 0
        self._published = 0
        self._discarded = 0
        self._waiters = 0

    # ------------------------------------------------------------------ read

    def snapshot(self) -> KeySnapshot | None:
        with self._cond:
            return self._snapshot

    def resolve(self, kid: str, now: int) -> ResolvedKey:
        with self._cond:
            snap = self._snapshot
            if snap is not None and snap.is_fresh(now):
                key = snap.keys.get(kid)
                if key is not None:
                    return ResolvedKey(public_key=key, snapshot=snap)
            op = self._inflight
            if op is not None:
                join = True
                owner = False
            else:
                if self._auto_allowed_locked(now):
                    op = self._start_op_locked(now, kind="auto")
                    owner = True
                    join = False
                else:
                    raise self._no_key_locked(kid, now, "refresh_cooldown")

        if owner:
            self._run_auto(op, kid, now)
        else:
            assert join
            return self._await_and_resolve(op, kid, now)
        return self._resolve_after(op, kid, now)

    # -------------------------------------------------------------- refresh

    def force_refresh(self, now: int | None = None) -> RefreshResult:
        """Fetch, validate and publish a new snapshot, waiting for completion.

        Bypasses the automatic cooldown.  It supersedes an in-flight automatic
        refresh (whose late result is discarded) and is single-flight with
        other admin refreshes.
        """
        if now is None:
            now = self._clock.now()
        with self._cond:
            current = self._inflight
            if current is not None and current.kind == "admin":
                op = current
                owner = False
            else:
                if current is not None:
                    current.superseded = True
                op = self._start_op_locked(now, kind="admin")
                owner = True
        if owner:
            snapshot, error = self._fetch_and_parse(op, now)
            self._finish(op, snapshot, error)
        else:
            with self._cond:
                self._waiters += 1
                op.waiters += 1
                self._cond.notify_all()
            try:
                completed = op.event.wait(timeout=self._waiter_timeout * 4)
            finally:
                with self._cond:
                    self._waiters -= 1
                    op.waiters -= 1
                    self._cond.notify_all()
            if not completed:
                raise RefreshFailedError(
                    "refresh_timeout",
                    f"forced refresh for {self.config.issuer!r} did not complete in time",
                )
        if op.error is not None or op.snapshot is None:
            code = op.error or "refresh_failed"
            raise RefreshFailedError(code, f"forced refresh for {self.config.issuer!r} failed")
        return RefreshResult(
            issuer=self.config.issuer,
            snapshot=op.snapshot,
            op_id=op.op_id,
            kind="admin",
        )

    def _run_auto(self, op: _RefreshOp, kid: str, now: int) -> None:
        snapshot, error = self._fetch_and_parse(op, now)
        self._finish(op, snapshot, error)

    def _fetch_and_parse(
        self, op: _RefreshOp, now: int
    ) -> tuple[KeySnapshot | None, str | None]:
        try:
            body = self._fetcher(self.config)
        except TransportError as exc:
            return None, exc.code
        except Exception:
            return None, "jwks_fetch_failed"
        try:
            snapshot = parse_jwks_document(
                body,
                issuer=self.config.issuer,
                seq=op.op_id,
                fetched_at=op.started_at,
                ttl_seconds=self._ttl,
                limits=self._limits,
            )
        except JwksDocumentError as exc:
            return None, exc.code
        except Exception:
            return None, "invalid_jwks"
        return snapshot, None

    def _start_op_locked(self, now: int, *, kind: str) -> _RefreshOp:
        self._op_counter += 1
        op = _RefreshOp(self._op_counter, kind, now)
        self._inflight = op
        self._attempts += 1
        # Cooldown is advanced by every start, including admin-triggered ones,
        # so automatic refreshes can never be driven faster than the limit.
        self._next_auto_refresh_at = now + self._cooldown
        self._cond.notify_all()
        return op

    def _finish(
        self, op: _RefreshOp, snapshot: KeySnapshot | None, error: str | None
    ) -> None:
        with self._cond:
            if self._inflight is op:
                self._inflight = None
            published = False
            if snapshot is not None:
                if op.superseded:
                    self._discarded += 1
                elif op.op_id <= self._seq:
                    # Defensive: generation must be strictly increasing.
                    self._discarded += 1
                else:
                    self._snapshot = snapshot
                    self._seq = op.op_id
                    self._published += 1
                    published = True
            if published:
                op.snapshot = snapshot
                op.error = None
                self._last_error = None
            else:
                op.snapshot = None
                if error is None:
                    error = "refresh_superseded"
                op.error = error
                # A superseded result is not a meaningful "last error": a newer
                # operation is responsible for the current state.
                if not op.superseded:
                    self._last_error = error
            op.event.set()
            self._cond.notify_all()

    # ------------------------------------------------------------- resolving

    def _resolve_after(self, op: _RefreshOp, kid: str, now: int) -> ResolvedKey:
        with self._cond:
            snap = self._snapshot
            if snap is not None and snap.is_fresh(now):
                key = snap.keys.get(kid)
                if key is not None:
                    return ResolvedKey(
                        public_key=key,
                        snapshot=snap,
                        # Only report "refreshed" when this operation's own
                        # result is what got published.
                        refreshed=snap.seq == op.op_id and not op.superseded,
                    )
                raise UnknownKidError(
                    "unknown_kid",
                    f"kid is not present in the fresh {self.config.issuer!r} snapshot",
                )
            raise KeyUnavailableError(
                "keys_unavailable",
                f"no fresh JWKS snapshot for {self.config.issuer!r} "
                f"(refresh error: {op.error or 'none'})",
            )

    def _await_and_resolve(
        self, op: _RefreshOp, kid: str, now: int, depth: int = 0
    ) -> ResolvedKey:
        with self._cond:
            self._waiters += 1
            op.waiters += 1
            self._cond.notify_all()
        try:
            op.event.wait(timeout=self._waiter_timeout)
        finally:
            with self._cond:
                self._waiters -= 1
                op.waiters -= 1
                self._cond.notify_all()

        with self._cond:
            snap = self._snapshot
            if snap is not None and snap.is_fresh(now):
                key = snap.keys.get(kid)
                if key is not None:
                    return ResolvedKey(public_key=key, snapshot=snap)
            nxt = self._inflight
        # If our operation was superseded by an admin refresh that is still
        # running, wait for that newer operation instead of returning a stale
        # failure.  Bounded to avoid attacker-driven unbounded chaining.
        if nxt is not None and nxt is not op and depth < 2:
            return self._await_and_resolve(nxt, kid, now, depth + 1)
        with self._cond:
            raise self._no_key_locked(kid, now, op.error or "refresh_incomplete")

    def _no_key_locked(self, kid: str, now: int, reason: str) -> Exception:
        snap = self._snapshot
        if snap is not None and snap.is_fresh(now):
            return UnknownKidError(
                "unknown_kid",
                f"kid is not present in the fresh {self.config.issuer!r} snapshot "
                f"({reason})",
            )
        return KeyUnavailableError(
            "keys_unavailable",
            f"no fresh JWKS snapshot for {self.config.issuer!r} ({reason})",
        )

    def _auto_allowed_locked(self, now: int) -> bool:
        return now >= self._next_auto_refresh_at

    # ------------------------------------------------------------ diagnostics

    def stats(self) -> dict[str, Any]:
        with self._cond:
            snap = self._snapshot
            op = self._inflight
            now = self._clock.now()
            return {
                "issuer": self.config.issuer,
                "jwks_url": self.config.jwks_url,
                "audience": self.config.audience,
                "snapshot": None
                if snap is None
                else {
                    "seq": snap.seq,
                    "fetched_at": snap.fetched_at,
                    "expires_at": snap.expires_at,
                    "fresh": snap.is_fresh(now),
                    "kids": sorted(snap.keys),
                    "digest": snap.digest,
                    "bytes": snap.raw_bytes,
                },
                "now": now,
                "in_flight": None
                if op is None
                else {"op_id": op.op_id, "kind": op.kind, "started_at": op.started_at},
                "waiters": self._waiters,
                "next_auto_refresh_at": self._next_auto_refresh_at,
                "last_error": self._last_error,
                "fetch_attempts": self._attempts,
                "published": self._published,
                "discarded": self._discarded,
                "cooldown_seconds": self._cooldown,
                "ttl_seconds": self._ttl,
            }


class KeyCacheManager:
    """Groups one cache per configured issuer; also the verifier's resolver."""

    def __init__(self, caches: dict[str, IssuerKeyCache]) -> None:
        self._caches = dict(caches)

    @classmethod
    def build(
        cls,
        configs: tuple[IssuerConfig, ...] | list[IssuerConfig],
        *,
        clock: Clock,
        fetcher: Fetcher,
        limits: JwksLimits,
        ttl_seconds: int,
        auto_refresh_cooldown_seconds: int,
        fetch_timeout_seconds: float,
    ) -> "KeyCacheManager":
        caches = {}
        for cfg in configs:
            caches[cfg.issuer] = IssuerKeyCache(
                cfg,
                clock=clock,
                fetcher=fetcher,
                limits=limits,
                ttl_seconds=ttl_seconds,
                auto_refresh_cooldown_seconds=auto_refresh_cooldown_seconds,
                fetch_timeout_seconds=fetch_timeout_seconds,
            )
        return cls(caches)

    def resolvers(self) -> dict[str, IssuerKeyCache]:
        """One resolver per issuer, keyed by the exact trusted ``iss`` value.

        The verifier looks this up only after validating ``iss`` against the
        configured issuer list, which is what keeps identical ``kid`` values
        in different issuers isolated.
        """
        return dict(self._caches)

    def resolve_for(self, issuer: str, kid: str, now: int) -> ResolvedKey:
        return self.get(issuer).resolve(kid, now)

    def get(self, issuer: str) -> IssuerKeyCache:
        try:
            return self._caches[issuer]
        except KeyError as exc:
            raise UnknownKidError("unknown_issuer", "no cache for issuer") from exc

    def force_refresh(self, issuer: str, now: int | None = None) -> RefreshResult:
        return self.get(issuer).force_refresh(now)

    def stats(self) -> list[dict[str, Any]]:
        return [self._caches[name].stats() for name in sorted(self._caches)]

    def issuer_caches(self) -> dict[str, IssuerKeyCache]:
        return dict(self._caches)
