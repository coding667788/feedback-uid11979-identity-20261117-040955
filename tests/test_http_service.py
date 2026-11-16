"""HTTP service and admin endpoint tests (real sockets, real signatures)."""

from __future__ import annotations

import http.client
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from conftest import ADMIN_TOKEN, AUD_A, ISSUER_A, ISSUER_B, make_harness
from jwt_service.server import VerificationService


@pytest.fixture
def http_service():
    h = make_harness()
    srv = VerificationService(h.services, host="127.0.0.1", port=0).start()
    try:
        yield h, srv
    finally:
        srv.stop()
        h.sim.stop()


def _request(srv: VerificationService, method: str, path: str,
             *, token: str | None = None, admin: str | None = None,
             body: bytes = b"", timeout: float = 10.0):
    conn = http.client.HTTPConnection(srv.host, srv.port, timeout=timeout)
    headers: dict[str, str] = {}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    if admin is not None:
        headers["Authorization"] = f"Bearer {admin}"
    if body:
        headers["Content-Type"] = "application/json"
    try:
        conn.request(method, path, body=body, headers=headers)
        response = conn.getresponse()
        payload = response.read()
        return response.status, json.loads(payload) if payload else None
    finally:
        conn.close()


def test_health_endpoint(http_service):
    _, srv = http_service
    status, body = _request(srv, "GET", "/healthz")
    assert status == 200 and body == {"status": "ok"}


def test_verify_success_over_http(http_service):
    h, srv = http_service
    token = h.mint_a(ttl=300)
    status, body = _request(srv, "POST", "/verify", token=token)
    assert status == 200, body
    assert body["valid"] is True
    assert body["issuer"] == ISSUER_A
    assert body["subject"] == "user-1"
    assert body["audience"] == [AUD_A]
    assert body["claims"]["nbf"] == h.clock.now()


def test_verify_missing_or_malformed_authorization(http_service):
    _, srv = http_service
    status, body = _request(srv, "POST", "/verify")
    assert status == 401 and body["error"] == "missing_authorization"

    conn = http.client.HTTPConnection(srv.host, srv.port, timeout=5)
    try:
        conn.request("POST", "/verify", headers={"Authorization": "Basic abc"})
        response = conn.getresponse()
        body = json.loads(response.read())
        assert response.status == 401
        assert body["error"] == "unsupported_authorization_scheme"
    finally:
        conn.close()


def test_verify_invalid_token_over_http(http_service):
    h, srv = http_service
    status, body = _request(srv, "POST", "/verify", token="not.a.jwt")
    assert status == 401
    assert body["valid"] is False
    # "not" is valid base64url whose pad bits are non-zero -> rejected early.
    assert body["error"] in ("json_invalid", "b64url_not_canonical")

    status, body = _request(srv, "POST", "/verify", token="only-one-segment")
    assert status == 401 and body["error"] == "token_bad_segments"


def test_verify_expired_token_over_http(http_service):
    h, srv = http_service
    token = h.mint_a(ttl=30)
    h.clock.advance(30)
    status, body = _request(srv, "POST", "/verify", token=token)
    assert status == 401 and body["error"] == "token_expired"


def test_verify_fails_closed_when_snapshot_expired_and_jwks_down(http_service):
    h, srv = http_service
    token = h.mint_a(ttl=600)
    assert _request(srv, "POST", "/verify", token=token)[0] == 200
    h.sim.set_raw(h.paths[ISSUER_A], b"down", status=503)
    h.clock.advance(60)
    status, body = _request(srv, "POST", "/verify", token=token)
    assert status == 503 and body["error"] == "keys_unavailable"


def test_admin_requires_token(http_service):
    _, srv = http_service
    status, body = _request(srv, "GET", "/admin/status")
    assert status == 401 and body["error"] == "admin_unauthorized"
    status, _ = _request(srv, "GET", "/admin/status", admin="wrong-token")
    assert status == 401


def test_admin_status_shape(http_service):
    h, srv = http_service
    assert _request(srv, "POST", "/verify", token=h.mint_a(ttl=300))[0] == 200
    status, body = _request(srv, "GET", "/admin/status", admin=ADMIN_TOKEN)
    assert status == 200
    assert body["now"] == h.clock.now()
    issuers = {entry["issuer"]: entry for entry in body["issuers"]}
    assert set(issuers) == {ISSUER_A, ISSUER_B}
    assert issuers[ISSUER_A]["snapshot"]["fresh"] is True
    assert "key-1" in issuers[ISSUER_A]["snapshot"]["kids"]
    assert "admin_token" not in json.dumps(body)


def test_admin_refresh_waits_and_reports_new_snapshot(http_service):
    h, srv = http_service
    assert _request(srv, "POST", "/verify", token=h.mint_a(ttl=300))[0] == 200
    before = h.cache_a.snapshot().seq

    new_key = __import__("jwt_service.issuer", fromlist=["generate_rsa_key"]).generate_rsa_key()
    h.publish_keys(ISSUER_A, [("rotated", new_key.public_key())])
    status, body = _request(srv, "POST", "/admin/refresh", admin=ADMIN_TOKEN,
                            body=json.dumps({"issuer": ISSUER_A}).encode())
    assert status == 200, body
    entry = body["refreshed"][ISSUER_A]
    assert entry["ok"] is True
    assert entry["seq"] > before
    assert entry["kids"] == ["rotated"]
    # The response is only sent after publication: the new token works now.
    token = h.a.mint(now=h.clock.now(), kid="rotated", key=new_key, ttl=300)
    assert _request(srv, "POST", "/verify", token=token)[0] == 200


def test_admin_refresh_reports_failure_and_keeps_old_snapshot(http_service):
    h, srv = http_service
    token = h.mint_a(ttl=600)
    assert _request(srv, "POST", "/verify", token=token)[0] == 200
    good = h.cache_a.snapshot()
    h.sim.set_raw(h.paths[ISSUER_A], b"nope", status=500)
    status, body = _request(srv, "POST", "/admin/refresh", admin=ADMIN_TOKEN,
                            body=json.dumps({"issuer": ISSUER_A}).encode())
    assert status == 502
    assert body["refreshed"][ISSUER_A]["ok"] is False
    assert h.cache_a.snapshot() is good
    # Still fresh -> still serving.
    assert _request(srv, "POST", "/verify", token=token)[0] == 200


def test_admin_refresh_unknown_issuer(http_service):
    _, srv = http_service
    status, body = _request(srv, "POST", "/admin/refresh", admin=ADMIN_TOKEN,
                            body=b'{"issuer":"https://nope.test"}')
    assert status == 404 and body["error"] == "unknown_issuer"


def test_admin_refresh_all_issuers(http_service):
    h, srv = http_service
    status, body = _request(srv, "POST", "/admin/refresh", admin=ADMIN_TOKEN)
    assert status == 200
    assert set(body["refreshed"]) == {ISSUER_A, ISSUER_B}


def test_method_not_allowed(http_service):
    _, srv = http_service
    status, body = _request(srv, "GET", "/verify")
    assert status == 405 and body["error"] == "method_not_allowed"
    status, _ = _request(srv, "POST", "/admin/status", admin=ADMIN_TOKEN)
    assert status == 405


def test_unknown_path(http_service):
    _, srv = http_service
    status, body = _request(srv, "GET", "/nope")
    assert status == 404


def test_no_credentials_forwarded_to_jwks(http_service):
    h, srv = http_service
    assert _request(srv, "POST", "/verify", token=h.mint_a(ttl=300))[0] == 200
    assert h.sim.credentials_seen() is False


def test_64_parallel_http_verifications(http_service):
    h, srv = http_service
    now = h.clock.now()
    tokens = [h.mint_a(now=now, ttl=600, sub=f"u{i}") for i in range(32)]
    tokens += [h.mint_b(now=now, ttl=600, sub=f"u{i}") for i in range(32)]
    h.sim.drain()
    barrier = threading.Barrier(64)

    def run(token: str) -> tuple[int, dict]:
        barrier.wait()
        return _request(srv, "POST", "/verify", token=token)

    with ThreadPoolExecutor(max_workers=64) as pool:
        results = list(pool.map(run, tokens))
    assert all(status == 200 for status, _ in results), [
        r for r in results if r[0] != 200
    ][:3]
    # 32 + 32 all started cold; at most one fetch per issuer.
    assert h.sim.request_count(h.paths[ISSUER_A]) == 1
    assert h.sim.request_count(h.paths[ISSUER_B]) == 1


def test_http_service_rotation_with_admin_refresh(http_service):
    """Rotate via the admin HTTP endpoint, then confirm old/new token behavior."""
    h, srv = http_service
    old = h.mint_a(ttl=900)
    assert _request(srv, "POST", "/verify", token=old)[0] == 200

    new_key = __import__("jwt_service.issuer", fromlist=["generate_rsa_key"]).generate_rsa_key()
    h.publish_keys(ISSUER_A, [("key-1", new_key.public_key())])
    status, _ = _request(srv, "POST", "/admin/refresh", admin=ADMIN_TOKEN,
                         body=json.dumps({"issuer": ISSUER_A}).encode())
    assert status == 200

    status, body = _request(srv, "POST", "/verify", token=old)
    assert status == 401 and body["error"] == "signature_invalid"

    new = h.a.mint(now=h.clock.now(), kid="key-1", key=new_key, ttl=900)
    assert _request(srv, "POST", "/verify", token=new)[0] == 200
