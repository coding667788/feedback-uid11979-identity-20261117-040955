"""End-to-end tests of the shipped CLI entry points across processes.

Unlike ``scripts/demo.py`` (a human-facing demo), this is a pytest module so
that process-level behaviour is part of the automated suite: it starts the JWKS
simulator in-process, launches ``jwt_service.server_main`` as a real child
process, mints tokens through ``jwt_service.token_cli`` as a real child
process, and rotates keys through the admin HTTP endpoint.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from conftest import ISSUER_A, ISSUER_B
from jwt_service.issuer import generate_rsa_key
from jwt_service.keystore import new_issuer, save_keystore
from jwt_service.simulator import JwksSimulator

ROOT = Path(__file__).resolve().parents[1]
ADMIN = "e2e-admin-token-0123456789"


def _child_env() -> dict[str, str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT)
    return env


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _http(url: str, method: str = "GET", body: bytes = b"",
          headers: dict[str, str] | None = None) -> tuple[int, dict]:
    request = urllib.request.Request(url, data=body or None, method=method,
                                     headers=headers or {})
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            return response.status, json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read() or b"{}")


def _wait_healthy(base: str, timeout: float = 20.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            status, _ = _http(f"{base}/healthz")
            if status == 200:
                return True
        except Exception:
            pass
        time.sleep(0.05)
    return False


@pytest.fixture
def e2e():
    with tempfile.TemporaryDirectory(prefix="jwt-e2e-") as tmp:
        tmpdir = Path(tmp)
        keystore = tmpdir / "keys.json"
        config = tmpdir / "service.json"
        stored = [
            new_issuer(ISSUER_A, "api-a", ["key-1"]),
            new_issuer(ISSUER_B, "api-b", ["key-1"]),
        ]
        save_keystore(keystore, stored)

        sim = JwksSimulator().start()
        server = None
        try:
            paths = {}
            for item in stored:
                path = f"/{item.issuer.rsplit('//', 1)[1]}/jwks.json"
                paths[item.issuer] = path
                sim.set_jwks(path, item.jwks())
            port = _free_port()
            config.write_text(json.dumps({
                "issuers": [
                    {"issuer": item.issuer, "jwks_url": sim.url(paths[item.issuer]),
                     "audience": item.audience}
                    for item in stored
                ],
                "admin_token": ADMIN,
                "listen_host": "127.0.0.1",
                "listen_port": port,
                "snapshot_ttl_seconds": 60,
                "auto_refresh_cooldown_seconds": 5,
                "fetch_timeout_seconds": 2.0,
            }), encoding="utf-8")

            server = subprocess.Popen(
                [sys.executable, "-m", "jwt_service.server_main",
                 "--config", str(config)],
                cwd=str(ROOT), env=_child_env(),
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            base = f"http://127.0.0.1:{port}"
            if not _wait_healthy(base):
                stderr = ""
                if server.poll() is not None:
                    stderr = server.stderr.read() if server.stderr else ""
                pytest.fail(f"verification service did not become healthy: {stderr}")
            yield {
                "base": base, "sim": sim, "keystore": keystore,
                "paths": paths, "stored": stored,
            }
        finally:
            if server is not None:
                server.terminate()
                try:
                    server.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait(timeout=5)
            sim.stop()


def _mint(keystore: Path, issuer: str, *, kid: str | None = None,
          ttl: int = 300) -> str:
    args = [sys.executable, "-m", "jwt_service.token_cli",
            "--keystore", str(keystore), "--issuer", issuer, "--ttl", str(ttl)]
    if kid:
        args += ["--kid", kid]
    completed = subprocess.run(
        args, cwd=str(ROOT), env=_child_env(),
        capture_output=True, text=True, timeout=120,
    )
    assert completed.returncode == 0, completed.stderr
    token = completed.stdout.strip()
    assert token.count(".") == 2
    return token


def test_e2e_verify_both_issuers_and_admin_status(e2e):
    base = e2e["base"]
    token_a = _mint(e2e["keystore"], ISSUER_A)
    token_b = _mint(e2e["keystore"], ISSUER_B)
    status, body_a = _http(f"{base}/verify", "POST", b"",
                           {"Authorization": f"Bearer {token_a}"})
    assert status == 200, body_a
    assert body_a["issuer"] == ISSUER_A
    status, body_b = _http(f"{base}/verify", "POST", b"",
                           {"Authorization": f"Bearer {token_b}"})
    assert status == 200, body_b
    assert body_b["issuer"] == ISSUER_B
    assert body_a["snapshot_digest"] != body_b["snapshot_digest"]

    status, admin_body = _http(f"{base}/admin/status",
                               headers={"Authorization": f"Bearer {ADMIN}"})
    assert status == 200
    assert ADMIN not in json.dumps(admin_body)
    assert len(admin_body["issuers"]) == 2


def test_e2e_rotation_via_admin_endpoint(e2e):
    base = e2e["base"]
    old_token = _mint(e2e["keystore"], ISSUER_A, ttl=600)
    assert _http(f"{base}/verify", "POST", b"",
                 {"Authorization": f"Bearer {old_token}"})[0] == 200

    new_private = generate_rsa_key()
    from jwt_service.jwks import public_jwk

    e2e["sim"].set_jwks(e2e["paths"][ISSUER_A],
                        {"keys": [public_jwk("key-1", new_private.public_key())]})
    status, body = _http(
        f"{base}/admin/refresh", "POST",
        json.dumps({"issuer": ISSUER_A}).encode(),
        {"Authorization": f"Bearer {ADMIN}", "Content-Type": "application/json"},
    )
    assert status == 200, body
    assert body["refreshed"][ISSUER_A]["ok"] is True

    status, body = _http(f"{base}/verify", "POST", b"",
                         {"Authorization": f"Bearer {old_token}"})
    assert status == 401
    assert body["error"] == "signature_invalid"


def test_e2e_rotated_out_kid_and_admin_failure(e2e):
    base = e2e["base"]
    old_token = _mint(e2e["keystore"], ISSUER_B, ttl=600)
    assert _http(f"{base}/verify", "POST", b"",
                 {"Authorization": f"Bearer {old_token}"})[0] == 200

    from jwt_service.jwks import public_jwk

    replacement = generate_rsa_key()
    e2e["sim"].set_jwks(e2e["paths"][ISSUER_B],
                        {"keys": [public_jwk("key-9", replacement.public_key())]})
    assert _http(f"{base}/admin/refresh", "POST",
                 json.dumps({"issuer": ISSUER_B}).encode(),
                 {"Authorization": f"Bearer {ADMIN}"})[0] == 200

    status, body = _http(f"{base}/verify", "POST", b"",
                         {"Authorization": f"Bearer {old_token}"})
    assert status == 401 and body["error"] == "unknown_kid"

    # A failing refresh keeps the still-fresh snapshot and reports the failure.
    e2e["sim"].set_raw(e2e["paths"][ISSUER_B], b"broken", status=500)
    status, body = _http(f"{base}/admin/refresh", "POST",
                         json.dumps({"issuer": ISSUER_B}).encode(),
                         {"Authorization": f"Bearer {ADMIN}"})
    assert status == 502
    assert body["refreshed"][ISSUER_B]["ok"] is False
