"""Wiring: config + simulator/fetcher + caches + verifier in one object."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from .cache import KeyCacheManager
from .clock import Clock, SystemClock
from .config import IssuerConfig, ServiceConfig, config_to_dict
from .errors import JwtServiceError
from .fetch import JwksFetcher
from .token import JwtVerifier, VerifiedToken


@dataclass
class AppServices:
    config: ServiceConfig
    clock: Clock
    manager: KeyCacheManager
    verifier: JwtVerifier

    @classmethod
    def build(
        cls,
        config: ServiceConfig,
        *,
        clock: Clock | None = None,
        fetcher: Callable[[IssuerConfig], bytes] | None = None,
    ) -> "AppServices":
        clock = clock or SystemClock()
        if fetcher is None:
            fetcher = JwksFetcher(
                limits=config.limits, timeout_seconds=config.fetch_timeout_seconds
            )
        manager = KeyCacheManager.build(
            config.issuers,
            clock=clock,
            fetcher=fetcher,
            limits=config.limits,
            ttl_seconds=config.snapshot_ttl_seconds,
            auto_refresh_cooldown_seconds=config.auto_refresh_cooldown_seconds,
            fetch_timeout_seconds=config.fetch_timeout_seconds,
        )
        verifier = JwtVerifier(
            issuers={item.issuer: item for item in config.issuers},
            resolvers=manager.resolvers(),
            clock=clock,
            max_kid_length=config.limits.max_kid_length,
        )
        return cls(config=config, clock=clock, manager=manager, verifier=verifier)

    def verify(self, token: str) -> VerifiedToken:
        return self.verifier.verify(token)

    def status(self) -> dict[str, Any]:
        return {
            "config": config_to_dict(self.config),
            "issuers": self.manager.stats(),
            "now": self.clock.now(),
        }

    def warm_up(self) -> dict[str, Any]:
        """Best-effort initial fetch for each issuer (never raises)."""
        results: dict[str, Any] = {}
        for cfg in self.config.issuers:
            try:
                result = self.manager.force_refresh(cfg.issuer)
                results[cfg.issuer] = {"ok": True, "seq": result.snapshot.seq}
            except JwtServiceError as exc:
                results[cfg.issuer] = {"ok": False, "error": exc.code}
        return results
