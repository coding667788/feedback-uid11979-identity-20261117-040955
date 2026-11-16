"""Configuration objects and the strict config-file loader.

All trust anchors (issuer identifiers, JWKS URLs, audiences) come from this
file.  Nothing from a token header can add or replace one.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .errors import ConfigError
from .strict_json import strict_json_loads

DEFAULT_SNAPSHOT_TTL_SECONDS = 60
DEFAULT_AUTO_REFRESH_COOLDOWN_SECONDS = 5
DEFAULT_FETCH_TIMEOUT_SECONDS = 2.0
DEFAULT_MAX_JWKS_BYTES = 256 * 1024
DEFAULT_MAX_JWKS_KEYS = 32
DEFAULT_MIN_RSA_BITS = 2048
DEFAULT_MAX_RSA_BITS = 8192
DEFAULT_MAX_KID_LENGTH = 256
DEFAULT_ADMIN_TOKEN_MIN_LENGTH = 16


@dataclass(frozen=True, slots=True)
class JwksLimits:
    max_bytes: int = DEFAULT_MAX_JWKS_BYTES
    max_keys: int = DEFAULT_MAX_JWKS_KEYS
    min_rsa_bits: int = DEFAULT_MIN_RSA_BITS
    max_rsa_bits: int = DEFAULT_MAX_RSA_BITS
    max_kid_length: int = DEFAULT_MAX_KID_LENGTH

    def __post_init__(self) -> None:
        if not 1024 <= self.max_bytes <= 16 * 1024 * 1024:
            raise ConfigError("invalid_limits", "max_bytes is out of range")
        if not 1 <= self.max_keys <= 1024:
            raise ConfigError("invalid_limits", "max_keys is out of range")
        if not 2048 <= self.min_rsa_bits <= 16384:
            raise ConfigError("invalid_limits", "min_rsa_bits is out of range")
        if self.max_rsa_bits < self.min_rsa_bits:
            raise ConfigError("invalid_limits", "max_rsa_bits < min_rsa_bits")
        if not 16 <= self.max_kid_length <= 4096:
            raise ConfigError("invalid_limits", "max_kid_length is out of range")


@dataclass(frozen=True, slots=True)
class IssuerConfig:
    issuer: str
    jwks_url: str
    audience: str

    def __post_init__(self) -> None:
        _require_text(self.issuer, "issuer", 512)
        _require_text(self.audience, "audience", 512)
        _require_text(self.jwks_url, "jwks_url", 2048)
        parts = urlsplit(self.jwks_url)
        if parts.scheme.lower() not in ("http", "https"):
            raise ConfigError("invalid_config", "jwks_url must use http or https")
        if not parts.hostname:
            raise ConfigError("invalid_config", "jwks_url must contain a host")
        if parts.username or parts.password:
            raise ConfigError("invalid_config", "jwks_url must not contain credentials")
        if parts.fragment:
            raise ConfigError("invalid_config", "jwks_url must not contain a fragment")


@dataclass(frozen=True, slots=True)
class ServiceConfig:
    issuers: tuple[IssuerConfig, ...]
    admin_token: str
    listen_host: str = "127.0.0.1"
    listen_port: int = 8080
    snapshot_ttl_seconds: int = DEFAULT_SNAPSHOT_TTL_SECONDS
    auto_refresh_cooldown_seconds: int = DEFAULT_AUTO_REFRESH_COOLDOWN_SECONDS
    fetch_timeout_seconds: float = DEFAULT_FETCH_TIMEOUT_SECONDS
    limits: JwksLimits = field(default_factory=JwksLimits)

    def __post_init__(self) -> None:
        if len(self.issuers) < 1:
            raise ConfigError("invalid_config", "at least one issuer is required")
        issuers: set[str] = set()
        urls: set[str] = set()
        audiences: set[str] = set()
        for item in self.issuers:
            if not isinstance(item, IssuerConfig):
                raise ConfigError("invalid_config", "issuers must be IssuerConfig values")
            if item.issuer in issuers:
                raise ConfigError("invalid_config", f"duplicate issuer {item.issuer!r}")
            if item.jwks_url in urls:
                raise ConfigError("invalid_config", "each issuer needs a distinct jwks_url")
            if item.audience in audiences:
                raise ConfigError("invalid_config", "each issuer needs a distinct audience")
            issuers.add(item.issuer)
            urls.add(item.jwks_url)
            audiences.add(item.audience)
        if not isinstance(self.admin_token, str):
            raise ConfigError("invalid_config", "admin_token must be a string")
        if len(self.admin_token) < DEFAULT_ADMIN_TOKEN_MIN_LENGTH:
            raise ConfigError(
                "invalid_config",
                f"admin_token must be at least {DEFAULT_ADMIN_TOKEN_MIN_LENGTH} characters",
            )
        if self.listen_host not in ("127.0.0.1", "::1", "localhost"):
            raise ConfigError("invalid_config", "listen_host must be a loopback address")
        if type(self.listen_port) is not int or not 0 <= self.listen_port <= 65535:
            raise ConfigError("invalid_config", "listen_port is out of range")
        if type(self.snapshot_ttl_seconds) is not int or not 1 <= self.snapshot_ttl_seconds <= 3600:
            raise ConfigError("invalid_config", "snapshot_ttl_seconds is out of range")
        if (
            type(self.auto_refresh_cooldown_seconds) is not int
            or not 1 <= self.auto_refresh_cooldown_seconds <= 3600
        ):
            raise ConfigError(
                "invalid_config", "auto_refresh_cooldown_seconds is out of range"
            )
        if (
            isinstance(self.fetch_timeout_seconds, bool)
            or not isinstance(self.fetch_timeout_seconds, (int, float))
            or not 0.05 <= self.fetch_timeout_seconds <= 60.0
        ):
            raise ConfigError("invalid_config", "fetch_timeout_seconds is out of range")


def _require_text(value: Any, name: str, max_len: int) -> None:
    if not isinstance(value, str) or not value:
        raise ConfigError("invalid_config", f"{name} must be a non-empty string")
    if len(value) > max_len:
        raise ConfigError("invalid_config", f"{name} is too long")
    if any(ord(ch) < 0x20 for ch in value):
        raise ConfigError("invalid_config", f"{name} contains control characters")


def _get(obj: dict[str, Any], name: str, default: Any = None) -> Any:
    return obj[name] if name in obj else default


def load_service_config(path: str | Path) -> ServiceConfig:
    """Load and validate a JSON config file (UTF-8, no duplicate members)."""
    try:
        raw = Path(path).read_bytes()
    except OSError as exc:
        raise ConfigError("config_unreadable", f"cannot read config: {exc}") from exc
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ConfigError("invalid_config", "config is not valid UTF-8") from exc
    try:
        data = strict_json_loads(text)
    except Exception as exc:  # strict parser raises TokenValidationError
        raise ConfigError("invalid_config", f"config JSON is invalid: {exc}") from exc
    if type(data) is not dict:
        raise ConfigError("invalid_config", "config root must be a JSON object")

    issuer_items = _get(data, "issuers")
    if type(issuer_items) is not list or not issuer_items:
        raise ConfigError("invalid_config", "issuers must be a non-empty array")
    issuers = []
    for item in issuer_items:
        if type(item) is not dict:
            raise ConfigError("invalid_config", "each issuer entry must be an object")
        issuers.append(
            IssuerConfig(
                issuer=_get(item, "issuer"),
                jwks_url=_get(item, "jwks_url"),
                audience=_get(item, "audience"),
            )
        )

    limits_data = _get(data, "limits", {})
    if type(limits_data) is not dict:
        raise ConfigError("invalid_config", "limits must be an object")
    allowed_limit_names = set(JwksLimits.__dataclass_fields__)
    unknown = set(limits_data) - allowed_limit_names
    if unknown:
        raise ConfigError("invalid_config", f"unknown limits keys: {sorted(unknown)}")
    limits = JwksLimits(**limits_data)

    raw_timeout = _get(data, "fetch_timeout_seconds", DEFAULT_FETCH_TIMEOUT_SECONDS)
    if isinstance(raw_timeout, bool) or not isinstance(raw_timeout, (int, float)):
        raise ConfigError("invalid_config", "fetch_timeout_seconds must be a number")

    return ServiceConfig(
        issuers=tuple(issuers),
        admin_token=_get(data, "admin_token"),
        listen_host=_get(data, "listen_host", "127.0.0.1"),
        listen_port=_get(data, "listen_port", 8080),
        snapshot_ttl_seconds=_get(
            data, "snapshot_ttl_seconds", DEFAULT_SNAPSHOT_TTL_SECONDS
        ),
        auto_refresh_cooldown_seconds=_get(
            data, "auto_refresh_cooldown_seconds", DEFAULT_AUTO_REFRESH_COOLDOWN_SECONDS
        ),
        fetch_timeout_seconds=float(raw_timeout),
        limits=limits,
    )


def config_to_dict(config: ServiceConfig) -> dict[str, Any]:
    """Public, secret-free view used by /admin/status and diagnostics."""
    return {
        "issuers": [
            {
                "issuer": item.issuer,
                "jwks_url": item.jwks_url,
                "audience": item.audience,
            }
            for item in config.issuers
        ],
        "snapshot_ttl_seconds": config.snapshot_ttl_seconds,
        "auto_refresh_cooldown_seconds": config.auto_refresh_cooldown_seconds,
        "fetch_timeout_seconds": config.fetch_timeout_seconds,
        "limits": {
            "max_bytes": config.limits.max_bytes,
            "max_keys": config.limits.max_keys,
            "min_rsa_bits": config.limits.min_rsa_bits,
            "max_rsa_bits": config.limits.max_rsa_bits,
            "max_kid_length": config.limits.max_kid_length,
        },
    }


def dumps_json(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), sort_keys=True)
