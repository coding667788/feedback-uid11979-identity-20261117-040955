"""Exception hierarchy used by the verifier.

Every exception carries a stable machine-readable ``code``.  Messages never
contain token material, keys or request headers, so they are safe to log and
to return to clients.
"""

from __future__ import annotations


class JwtServiceError(Exception):
    code = "jwt_service_error"

    def __init__(self, code: str | None = None, message: str = "") -> None:
        if code is not None:
            self.code = code
        self.message = message or self.code
        super().__init__(f"{self.code}: {self.message}")


class TokenValidationError(JwtServiceError):
    """The bearer token is not acceptable (HTTP 401)."""

    code = "invalid_token"


class UnknownKidError(TokenValidationError):
    code = "unknown_kid"


class KeyUnavailableError(JwtServiceError):
    """No usable, unexpired key snapshot exists (HTTP 503)."""

    code = "keys_unavailable"


class JwksDocumentError(JwtServiceError):
    """A JWKS document is malformed or exceeds a hard limit."""

    code = "invalid_jwks"


class TransportError(JwtServiceError):
    """Fetching the trusted JWKS URL failed."""

    code = "jwks_fetch_failed"


class RefreshFailedError(JwksDocumentError):
    """A refresh attempt did not produce a publishable snapshot."""

    code = "refresh_failed"


class ConfigError(JwtServiceError):
    code = "invalid_config"
