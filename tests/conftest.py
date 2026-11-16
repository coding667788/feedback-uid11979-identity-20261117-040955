"""Shared test harness: one in-process simulator + verifier per test."""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from jwt_service.app import AppServices  # noqa: E402
from jwt_service.cache import IssuerKeyCache  # noqa: E402
from jwt_service.clock import ManualClock  # noqa: E402
from jwt_service.config import IssuerConfig, JwksLimits, ServiceConfig  # noqa: E402
from jwt_service.issuer import LocalIssuer  # noqa: E402
from jwt_service.simulator import JwksSimulator  # noqa: E402
from jwt_service.token import JwtVerifier  # noqa: E402

ISSUER_A = "https://issuer-a.test"
ISSUER_B = "https://issuer-b.test"
AUD_A = "api-a"
AUD_B = "api-b"
START_TIME = 1_800_000_000
ADMIN_TOKEN = "test-admin-token-0123456789"


@dataclass
class Harness:
    sim: JwksSimulator
    clock: ManualClock
    config: ServiceConfig
    services: AppServices
    a: LocalIssuer
    b: LocalIssuer
    paths: dict[str, str] = field(default_factory=dict)

    # -- helpers -----------------------------------------------------------
    @property
    def cache_a(self) -> IssuerKeyCache:
        return self.services.manager.get(ISSUER_A)

    @property
    def cache_b(self) -> IssuerKeyCache:
        return self.services.manager.get(ISSUER_B)

    def publish(self, issuer: str) -> None:
        """Serve the LocalIssuer's current key set at its configured path."""
        target = self.a if issuer == ISSUER_A else self.b
        self.sim.set_jwks(self.paths[issuer], target.jwks())

    def publish_keys(self, issuer: str, keys: list[tuple[str, Any]]) -> None:
        self.sim.set_jwks_from_keys(self.paths[issuer], keys)

    def verify(self, token: str):
        return self.services.verify(token)

    def mint_a(self, **kwargs: Any) -> str:
        kwargs.setdefault("now", self.clock.now())
        return self.a.mint(**kwargs)

    def mint_b(self, **kwargs: Any) -> str:
        kwargs.setdefault("now", self.clock.now())
        return self.b.mint(**kwargs)

    def token_for_issuer(self, issuer_cfg: IssuerConfig) -> LocalIssuer:
        return self.a if issuer_cfg.issuer == ISSUER_A else self.b


def make_harness(
    *,
    ttl: int = 60,
    cooldown: int = 5,
    start: int = START_TIME,
    limits: JwksLimits | None = None,
    fetch_timeout: float = 2.0,
) -> Harness:
    sim = JwksSimulator().start()
    clock = ManualClock(start)
    a = LocalIssuer(ISSUER_A, AUD_A)
    b = LocalIssuer(ISSUER_B, AUD_B)
    paths = {ISSUER_A: "/issuer-a/jwks.json", ISSUER_B: "/issuer-b/jwks.json"}
    config = ServiceConfig(
        issuers=(
            IssuerConfig(ISSUER_A, sim.url(paths[ISSUER_A]), AUD_A),
            IssuerConfig(ISSUER_B, sim.url(paths[ISSUER_B]), AUD_B),
        ),
        admin_token=ADMIN_TOKEN,
        snapshot_ttl_seconds=ttl,
        auto_refresh_cooldown_seconds=cooldown,
        fetch_timeout_seconds=fetch_timeout,
        limits=limits or JwksLimits(),
    )
    sim.set_jwks(paths[ISSUER_A], a.jwks())
    sim.set_jwks(paths[ISSUER_B], b.jwks())
    services = AppServices.build(config, clock=clock)
    return Harness(
        sim=sim, clock=clock, config=config, services=services, a=a, b=b, paths=paths
    )


@pytest.fixture
def harness():
    h = make_harness()
    try:
        yield h
    finally:
        h.sim.stop()


def url_path(url: str) -> str:
    from urllib.parse import urlsplit

    return urlsplit(url).path


def build_verifier(harness: Harness) -> JwtVerifier:
    return harness.services.verifier
