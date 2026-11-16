"""Transport-layer tests for the pinned-URL JWKS fetcher."""

from __future__ import annotations

import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

import pytest

from conftest import make_harness
from jwt_service.config import IssuerConfig, JwksLimits
from jwt_service.errors import TransportError
from jwt_service.fetch import JwksFetcher


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 64


def _serve(handler_fn) -> tuple[ThreadingHTTPServer, str]:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        def do_GET(self):
            handler_fn(self)

    server = _Server(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"


def _config(url: str) -> IssuerConfig:
    return IssuerConfig("https://issuer.test", url, "aud")


def test_fetcher_returns_body():
    body = b'{"keys":[]}'
    server, base = _serve(lambda h: _send(h, 200, body))
    try:
        fetched = JwksFetcher(limits=JwksLimits(), timeout_seconds=2.0)(
            _config(base + "/jwks.json")
        )
        assert fetched == body
    finally:
        server.shutdown()
        server.server_close()


def test_fetcher_rejects_non_200():
    server, base = _serve(lambda h: _send(h, 500, b"server error"))
    try:
        with pytest.raises(TransportError) as info:
            JwksFetcher(limits=JwksLimits(), timeout_seconds=2.0)(
                _config(base + "/jwks.json")
            )
        assert info.value.code == "jwks_fetch_failed"
    finally:
        server.shutdown()
        server.server_close()


def test_fetcher_does_not_follow_redirects():
    server, base = _serve(
        lambda h: _redirect(h, "http://127.0.0.1:1/attacker.json")
    )
    try:
        with pytest.raises(TransportError) as info:
            JwksFetcher(limits=JwksLimits(), timeout_seconds=2.0)(
                _config(base + "/jwks.json")
            )
        assert info.value.code == "jwks_fetch_failed"
    finally:
        server.shutdown()
        server.server_close()


def test_fetcher_caps_body_size():
    body = b'{"keys":[]}' + b" " * 4096
    server, base = _serve(lambda h: _send(h, 200, body))
    try:
        with pytest.raises(TransportError) as info:
            JwksFetcher(limits=JwksLimits(max_bytes=1024), timeout_seconds=2.0)(
                _config(base + "/jwks.json")
            )
        assert info.value.code == "jwks_too_large"
    finally:
        server.shutdown()
        server.server_close()


def test_fetcher_rejects_empty_body():
    server, base = _serve(lambda h: _send(h, 200, b""))
    try:
        with pytest.raises(TransportError) as info:
            JwksFetcher(limits=JwksLimits(), timeout_seconds=2.0)(
                _config(base + "/jwks.json")
            )
        assert info.value.code in ("jwks_empty", "jwks_fetch_failed")
    finally:
        server.shutdown()
        server.server_close()


def test_fetcher_sends_no_credentials():
    seen: list[dict] = []

    def handler(h):
        seen.append({k.lower(): v for k, v in h.headers.items()})
        _send(h, 200, b'{"keys":[]}')

    server, base = _serve(handler)
    try:
        JwksFetcher(limits=JwksLimits(), timeout_seconds=2.0)(_config(base + "/jwks.json"))
    finally:
        server.shutdown()
        server.server_close()
    assert seen
    headers = seen[0]
    assert "authorization" not in headers
    assert "cookie" not in headers
    assert headers.get("accept-encoding") == "identity"


def test_fetcher_connects_to_configured_host_only(harness):
    """The URL host in config is the one contacted; a header cannot change it."""
    token = harness.mint_a(ttl=300)
    harness.verify(token)
    assert harness.sim.request_count() == 1
    assert urlsplit(harness.config.issuers[0].jwks_url).hostname == harness.sim.host


def _send(handler: BaseHTTPRequestHandler, status: int, body: bytes) -> None:
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    if body:
        handler.wfile.write(body)


def _redirect(handler: BaseHTTPRequestHandler, location: str) -> None:
    handler.send_response(302)
    handler.send_header("Location", location)
    handler.send_header("Content-Length", "0")
    handler.end_headers()
