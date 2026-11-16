"""HTTP client used to fetch a trusted JWKS document.

The URL is taken solely from configuration.  Redirects are not followed (a
redirect would let the remote move the trust anchor), the response size is
capped while reading, and no credentials are forwarded.
"""

from __future__ import annotations

import http.client
from urllib.parse import urlsplit

from .config import IssuerConfig, JwksLimits
from .errors import TransportError


class JwksFetcher:
    """Fetches a JWKS over plain HTTP from the pre-configured URL only."""

    def __init__(self, *, limits: JwksLimits, timeout_seconds: float) -> None:
        self._limits = limits
        self._timeout = timeout_seconds

    def __call__(self, config: IssuerConfig) -> bytes:
        parts = urlsplit(config.jwks_url)
        if parts.scheme.lower() != "http":
            raise TransportError(
                "jwks_fetch_failed", "this build only fetches http:// JWKS URLs"
            )
        host = parts.hostname
        port = parts.port or 80
        path = parts.path or "/"
        if parts.query:
            path = f"{path}?{parts.query}"

        # Explicitly no redirect handling: 3xx is a hard failure.
        conn = http.client.HTTPConnection(host, port, timeout=self._timeout)
        try:
            conn.request(
                "GET",
                path,
                headers={
                    "Accept": "application/jwk-set+json, application/json",
                    "Accept-Encoding": "identity",
                    "User-Agent": "strict-jwt-verifier/1.0",
                },
            )
            response = conn.getresponse()
            status = response.status
            content_type = response.getheader("Content-Type", "") or ""
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = response.read(64 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > self._limits.max_bytes:
                    raise TransportError(
                        "jwks_too_large", "JWKS response exceeded the size limit"
                    )
                chunks.append(chunk)
        except TransportError:
            raise
        except (OSError, http.client.HTTPException) as exc:
            raise TransportError("jwks_fetch_failed", f"JWKS fetch failed: {exc}") from exc
        finally:
            conn.close()

        if status != 200:
            raise TransportError(
                "jwks_fetch_failed", f"JWKS endpoint returned HTTP {status}"
            )
        body = b"".join(chunks)
        if not body:
            raise TransportError("jwks_empty", "JWKS endpoint returned an empty body")
        return body
