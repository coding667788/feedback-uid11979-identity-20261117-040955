"""Verification HTTP service.

Endpoints
---------
``GET  /healthz``            liveness only
``GET  /admin/status``       per-issuer snapshot/refresh counters (admin auth)
``POST /admin/refresh``      force refresh; blocks until published (admin auth)
``POST /verify``             ``Authorization: Bearer <jwt>`` -> 200/401/503

Responses are always JSON.  Errors expose a stable ``error`` code and never
echo the token, its header, or key material.
"""

from __future__ import annotations

import json
import threading
import hmac
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .app import AppServices
from .config import dumps_json
from .errors import (
    JwtServiceError,
    KeyUnavailableError,
    TokenValidationError,
)

MAX_REQUEST_BODY = 16 * 1024
MAX_AUTHORIZATION_CHARS = 20 * 1024


@dataclass(frozen=True, slots=True)
class HttpReply:
    status: int
    body: dict[str, Any]


def _error(status: int, code: str) -> HttpReply:
    return HttpReply(status, {"valid": False, "error": code})


class _Server(ThreadingHTTPServer):
    # socketserver's default listen backlog of 5 resets connections under a
    # burst of parallel verification requests.
    request_queue_size = 256
    daemon_threads = True
    allow_reuse_address = True


class VerificationService:
    def __init__(self, services: AppServices, host: str = "127.0.0.1", port: int = 0) -> None:
        self.services = services
        self._admin_token = services.config.admin_token
        self._httpd = _Server((host, port), self._make_handler())
        self._thread: threading.Thread | None = None
        self._max_inflight = 256
        self._slots = threading.BoundedSemaphore(self._max_inflight)

    # -- lifecycle ---------------------------------------------------------
    def start(self) -> "VerificationService":
        if self._thread is None:
            self._thread = threading.Thread(
                target=self._httpd.serve_forever,
                name="jwt-verification-service",
                daemon=True,
            )
            self._thread.start()
        return self

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

    def __enter__(self) -> "VerificationService":
        return self.start()

    def __exit__(self, *exc: Any) -> None:
        self.stop()

    @property
    def host(self) -> str:
        return self._httpd.server_address[0]

    @property
    def port(self) -> int:
        return self._httpd.server_address[1]

    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    # -- request handling (also directly testable) --------------------------
    def handle(
        self,
        method: str,
        path: str,
        headers: dict[str, str],
        body: bytes = b"",
    ) -> HttpReply:
        lowered = {k.lower(): v for k, v in headers.items()}
        if method == "GET" and path == "/healthz":
            return HttpReply(200, {"status": "ok"})
        if path in ("/admin/status", "/admin/refresh"):
            if not self._admin_ok(lowered.get("authorization", "")):
                return _error(401, "admin_unauthorized")
            if path == "/admin/status":
                if method != "GET":
                    return _error(405, "method_not_allowed")
                return HttpReply(200, self.services.status())
            if method != "POST":
                return _error(405, "method_not_allowed")
            return self._handle_refresh(body)
        if path == "/verify":
            if method != "POST":
                return _error(405, "method_not_allowed")
            return self._handle_verify(lowered.get("authorization", ""))
        return _error(404, "not_found")

    def _admin_ok(self, authorization: str) -> bool:
        if not authorization.startswith("Bearer "):
            return False
        presented = authorization[len("Bearer ") :]
        if len(presented) > 4096:
            return False
        return hmac.compare_digest(presented.encode("utf-8"), self._admin_token.encode("utf-8"))

    def _handle_refresh(self, body: bytes) -> HttpReply:
        issuer = ""
        if body:
            try:
                data = json.loads(body.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                return _error(400, "invalid_request_body")
            if not isinstance(data, dict):
                return _error(400, "invalid_request_body")
            issuer = data.get("issuer", "")
            if not isinstance(issuer, str):
                return _error(400, "invalid_request_body")
        caches = self.services.manager.issuer_caches()
        if issuer:
            if issuer not in caches:
                return _error(404, "unknown_issuer")
            targets = [issuer]
        else:
            targets = sorted(caches)

        results: dict[str, Any] = {}
        failed = False
        for name in targets:
            try:
                result = caches[name].force_refresh()
                results[name] = {
                    "ok": True,
                    "seq": result.snapshot.seq,
                    "digest": result.snapshot.digest,
                    "kids": sorted(result.snapshot.keys),
                    "expires_at": result.snapshot.expires_at,
                }
            except JwtServiceError as exc:
                failed = True
                results[name] = {"ok": False, "error": exc.code}
        status = 200 if not failed else 502
        return HttpReply(status, {"refreshed": results})

    def _handle_verify(self, authorization: str) -> HttpReply:
        if not authorization:
            return _error(401, "missing_authorization")
        if not authorization.startswith("Bearer "):
            return _error(401, "unsupported_authorization_scheme")
        token = authorization[len("Bearer ") :].strip()
        if not token:
            return _error(401, "invalid_token")
        if len(authorization) > MAX_AUTHORIZATION_CHARS:
            return _error(401, "token_too_large")
        if not self._slots.acquire(blocking=False):
            return _error(503, "server_busy")
        try:
            verified = self.services.verify(token)
        except TokenValidationError as exc:
            return _error(401, exc.code)
        except KeyUnavailableError as exc:
            return _error(503, exc.code)
        except JwtServiceError as exc:
            return _error(500, exc.code)
        except Exception:
            return _error(500, "internal_error")
        finally:
            self._slots.release()
        return HttpReply(200, verified.public_view())

    # -- http.server glue ---------------------------------------------------
    def _make_handler(self) -> type[BaseHTTPRequestHandler]:
        service = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, fmt: str, *args: Any) -> None:
                pass

            def _read_body(self) -> bytes | None:
                try:
                    length = int(self.headers.get("Content-Length") or 0)
                except ValueError:
                    return None
                if length < 0 or length > MAX_REQUEST_BODY:
                    return None
                return self.rfile.read(length) if length else b""

            def _dispatch(self, method: str) -> None:
                body = self._read_body()
                if body is None:
                    self._send(_error(400, "invalid_request_body"))
                    return
                headers = {key: value for key, value in self.headers.items()}
                reply = service.handle(method, self.path, headers, body)
                self._send(reply)

            def _send(self, reply: HttpReply) -> None:
                payload = dumps_json(reply.body).encode("utf-8")
                self.send_response(reply.status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.end_headers()
                self.wfile.write(payload)
                self.wfile.flush()

            def do_GET(self) -> None:  # noqa: N802
                self._dispatch("GET")

            def do_POST(self) -> None:  # noqa: N802
                self._dispatch("POST")

            def do_PUT(self) -> None:  # noqa: N802
                self._dispatch("PUT")

            def do_DELETE(self) -> None:  # noqa: N802
                self._dispatch("DELETE")

        return Handler
