"""Local, controllable JWKS HTTP simulator.

Each request follows a fixed protocol:

1. On arrival the handler takes a **snapshot of the response body, status and
   headers as they are at that instant** (``SimulatedRequest.body``).
2. It then may block on that request's private release event.
3. When released it writes exactly the bytes captured in step 1.

Because the body is captured before blocking, a test can change the served
document while an *old* request is held, then release the old request and
verify that its stale response cannot overwrite the newer snapshot.  Every
request and its captured body digest is recorded, which is what the
refresh-coalescing and cooldown tests assert against.
"""

from __future__ import annotations

import hashlib
import json
import queue
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .jwks import public_jwk
from .strict_json import b64url_encode
from cryptography.hazmat.primitives.asymmetric import rsa


@dataclass
class SimulatedRequest:
    seq: int
    path: str
    body: bytes
    status: int
    content_type: str
    arrived_at: float
    released_at: float | None = None
    finished_at: float | None = None
    client_gone: bool = False
    _release: threading.Event = field(default_factory=threading.Event, repr=False)

    @property
    def body_digest(self) -> str:
        return hashlib.sha256(self.body).hexdigest()[:16]

    def release(self) -> None:
        self._release.set()


class _State:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.documents: dict[str, tuple[int, bytes, str]] = {}
        self.default_document = b'{"keys":[]}'
        self.pending: "queue.Queue[SimulatedRequest]" = queue.Queue()
        self.held: list[SimulatedRequest] = []
        self.requests: list[SimulatedRequest] = []
        self.counter = 0
        self.hold_count = 0


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    state: _State

    def log_message(self, fmt: str, *args: Any) -> None:  # silence stderr noise
        pass

    def do_GET(self) -> None:  # noqa: N802 (http.server API)
        state = self.state
        with state.lock:
            state.counter += 1
            seq = state.counter
            status, body, content_type = state.documents.get(
                self.path, (200, state.default_document, "application/json")
            )
            account = (
                self.headers.get("Authorization") is not None
                or self.headers.get("Cookie") is not None
            )
            record = SimulatedRequest(
                seq=seq,
                path=self.path,
                body=body,
                status=status,
                content_type=content_type,
                arrived_at=time.monotonic(),
            )
            state.requests.append(record)
            if account:
                # Recorded only so tests can assert no credentials are sent.
                record.path = self.path + " [credentials-present]"
            hold = state.hold_count > 0
            if hold:
                state.hold_count -= 1
                state.held.append(record)
            state.pending.put(record)

        if hold:
            record._release.wait(timeout=30.0)
        record.released_at = time.monotonic()

        try:
            self.send_response(record.status)
            self.send_header("Content-Type", record.content_type)
            self.send_header("Content-Length", str(len(record.body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            if record.body:
                self.wfile.write(record.body)
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            record.client_gone = True
        finally:
            record.finished_at = time.monotonic()


class _SimulatorServer(ThreadingHTTPServer):
    request_queue_size = 256
    daemon_threads = True
    allow_reuse_address = True


class JwksSimulator:
    def __init__(self, host: str = "127.0.0.1", port: int = 0) -> None:
        self._state = _State()
        state = self._state

        class Handler(_Handler):
            pass

        Handler.state = state
        self._httpd = _SimulatorServer((host, port), Handler)
        self._thread: threading.Thread | None = None

    # -- lifecycle ---------------------------------------------------------
    def start(self) -> "JwksSimulator":
        if self._thread is None:
            self._thread = threading.Thread(
                target=self._httpd.serve_forever,
                name="jwks-simulator",
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

    def __enter__(self) -> "JwksSimulator":
        return self.start()

    def __exit__(self, *exc: Any) -> None:
        self.stop()

    @property
    def host(self) -> str:
        return self._httpd.server_address[0]

    @property
    def port(self) -> int:
        return self._httpd.server_address[1]

    def url(self, path: str) -> str:
        return f"http://{self.host}:{self.port}{path}"

    # -- served content ----------------------------------------------------
    def set_jwks(self, path: str, document: bytes | dict[str, Any]) -> None:
        if isinstance(document, dict):
            document = json.dumps(document, separators=(",", ":")).encode("utf-8")
        with self._state.lock:
            self._state.documents[path] = (200, document, "application/json")

    def set_raw(self, path: str, body: bytes, *, status: int = 200,
                content_type: str = "application/json") -> None:
        with self._state.lock:
            self._state.documents[path] = (status, body, content_type)

    def set_jwks_from_keys(
        self, path: str, keys: list[tuple[str, rsa.RSAPublicKey]]
    ) -> None:
        self.set_jwks(path, {"keys": [public_jwk(kid, key) for kid, key in keys]})

    # -- blocking control --------------------------------------------------
    def hold_next(self, count: int = 1) -> None:
        """Block the next ``count`` requests until individually released."""
        with self._state.lock:
            self._state.hold_count += count

    def release_all_held(self) -> int:
        """Release every currently held request; returns how many were released."""
        with self._state.lock:
            targets = [r for r in self._state.held if r.released_at is None]
        for record in targets:
            record.release()
        return len(targets)

    def drain(self) -> int:
        """Discard queued request notifications (does not release held requests)."""
        drained = 0
        while True:
            try:
                self._state.pending.get_nowait()
            except queue.Empty:
                return drained
            drained += 1

    def wait_for_request(self, timeout: float = 5.0) -> SimulatedRequest | None:
        try:
            return self._state.pending.get(timeout=timeout)
        except queue.Empty:
            return None

    def wait_for_requests(self, count: int, timeout: float = 5.0) -> list[SimulatedRequest]:
        got: list[SimulatedRequest] = []
        deadline = time.monotonic() + timeout
        while len(got) < count:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            record = self.wait_for_request(remaining)
            if record is None:
                break
            got.append(record)
        return got

    # -- accounting --------------------------------------------------------
    def request_count(self, path: str | None = None) -> int:
        with self._state.lock:
            if path is None:
                return len(self._state.requests)
            return sum(1 for r in self._state.requests if r.path.split(" ")[0] == path)

    def requests(self, path: str | None = None) -> list[SimulatedRequest]:
        with self._state.lock:
            items = list(self._state.requests)
        if path is None:
            return items
        return [r for r in items if r.path.split(" ")[0] == path]

    def credentials_seen(self) -> bool:
        with self._state.lock:
            return any("credentials-present" in r.path for r in self._state.requests)

    def reset(self) -> None:
        with self._state.lock:
            self._state.requests.clear()
            self._state.held.clear()
            self._state.counter = 0
            self._state.hold_count = 0
        self.release_all_held()


def jwks_document(keys: list[tuple[str, rsa.RSAPublicKey]]) -> dict[str, Any]:
    return {"keys": [public_jwk(kid, key) for kid, key in keys]}


__all__ = ["JwksSimulator", "SimulatedRequest", "jwks_document", "b64url_encode"]
