"""Public package for the strict local JWT verification service."""

from .app import AppServices
from .cache import IssuerKeyCache, KeyCacheManager, RefreshResult
from .clock import Clock, ManualClock, SystemClock
from .config import IssuerConfig, JwksLimits, ServiceConfig
from .errors import (
    ConfigError,
    JwksDocumentError,
    JwtServiceError,
    KeyUnavailableError,
    RefreshFailedError,
    TokenValidationError,
    TransportError,
    UnknownKidError,
)
from .fetch import JwksFetcher
from .issuer import LocalIssuer, TokenSpec, generate_rsa_key, sign_jwt
from .jwks import KeySnapshot, parse_jwks_document, public_jwk
from .server import VerificationService
from .simulator import JwksSimulator
from .token import JwtVerifier, VerifiedToken

__version__ = "1.0.0"

__all__ = [
    "AppServices",
    "Clock",
    "ConfigError",
    "IssuerConfig",
    "IssuerKeyCache",
    "JwksDocumentError",
    "JwksFetcher",
    "JwksLimits",
    "JwksSimulator",
    "JwtServiceError",
    "JwtVerifier",
    "KeyCacheManager",
    "KeySnapshot",
    "KeyUnavailableError",
    "LocalIssuer",
    "ManualClock",
    "RefreshFailedError",
    "RefreshResult",
    "ServiceConfig",
    "SystemClock",
    "TokenSpec",
    "TokenValidationError",
    "TransportError",
    "UnknownKidError",
    "VerificationService",
    "VerifiedToken",
    "generate_rsa_key",
    "parse_jwks_document",
    "public_jwk",
    "sign_jwt",
    "__version__",
]
