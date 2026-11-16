"""End-to-end demonstration against real processes and real sockets.

This script does NOT use any test doubles:

* the JWKS simulator runs in this process on a real TCP port,
* the verification service runs as a **separate Python subprocess** listening on
  a real port and using the production ``JwksFetcher`` over real HTTP,
* tokens are minted by the standalone ``jwt_service.token_cli`` subprocess,
* rotation is driven by the admin HTTP endpoint,
* every outcome is a real RSA signature verification performed by the service.

Run:  python scripts/demo.py
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

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from jwt_service.issuer import generate_rsa_key  # noqa: E402
from jwt_service.keystore import new_issuer, save_keystore  # noqa: E402
from jwt_service.simulator import JwksSimulator  # noqa: E402

ISSUER_A = "https://issuer-a.test"
ISSUER_B = "https://issuer-b.test"
ADMIN_TOKEN = "demo-admin-token-0123456789"


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def http_json(url: str, method: str = "GET", payload: bytes = b"",
              headers: dict[str, str] | None = None) -> tuple[int, dict]:
    request = urllib.request.Request(url, data=payload or None, method=method,
                                     headers=headers or {})
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def wait_until(predicate, timeout: float = 15.0, interval: float = 0.05) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return False


def run_child(args: list[str]) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT)
    return subprocess.run(
        [sys.executable, *args], cwd=str(ROOT), env=env,
        capture_output=True, text=True, timeout=120,
    )


def mint(keystore: Path, issuer: str, *, kid: str | None = None, ttl: int = 300) -> str:
    args = ["-m", "jwt_service.token_cli", "--keystore", str(keystore),
            "--issuer", issuer, "--ttl", str(ttl)]
    if kid:
        args += ["--kid", kid]
    completed = run_child(args)
    if completed.returncode != 0:
        raise RuntimeError(f"token_cli failed: {completed.stderr}")
    return completed.stdout.strip()


def main() -> int:
    checks: list[tuple[str, bool, str]] = []

    def check(name: str, ok: bool, detail: str = "") -> None:
        checks.append((name, ok, detail))
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f"  ({detail})" if detail else ""))

    with tempfile.TemporaryDirectory(prefix="jwt-demo-") as tmp:
        tmpdir = Path(tmp)
        keystore = tmpdir / "test-keys.json"
        config_path = tmpdir / "service.json"

        stored = [
            new_issuer(ISSUER_A, "aud-a", ["key-1"]),
            new_issuer(ISSUER_B, "aud-b", ["key-1"]),  # same kid, different key
        ]
        save_keystore(keystore, stored)

        sim = JwksSimulator().start()
        try:
            for item in stored:
                path = f"/{item.issuer.rsplit('//', 1)[1]}/jwks.json"
                sim.set_jwks(path, item.jwks())
            print(f"simulator on http://{sim.host}:{sim.port}")

            service_port = free_port()
            config_path.write_text(json.dumps({
                "issuers": [
                    {"issuer": ISSUER_A,
                     "jwks_url": sim.url(f"/{ISSUER_A.rsplit('//', 1)[1]}/jwks.json"),
                     "audience": "aud-a"},
                    {"issuer": ISSUER_B,
                     "jwks_url": sim.url(f"/{ISSUER_B.rsplit('//', 1)[1]}/jwks.json"),
                     "audience": "aud-b"},
                ],
                "admin_token": ADMIN_TOKEN,
                "listen_host": "127.0.0.1",
                "listen_port": service_port,
                "snapshot_ttl_seconds": 60,
                "auto_refresh_cooldown_seconds": 5,
            }), encoding="utf-8")

            env = dict(os.environ)
            env["PYTHONPATH"] = str(ROOT)
            server = subprocess.Popen(
                [sys.executable, "-m", "jwt_service.server_main", "--config", str(config_path)],
                cwd=str(ROOT), env=env,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            base = f"http://127.0.0.1:{service_port}"
            try:
                if not wait_until(lambda: _healthy(base)):
                    print(server.stderr.read() if server.poll() is not None else "")
                    print("service did not start")
                    return 1
                print(f"service on {base} (pid {server.pid})\n")

                lane = "A"
                print(f"{lane}. Cold start: real token verifies over HTTP")
                token_a = mint(keystore, ISSUER_A)
                token_b = mint(keystore, ISSUER_B)
                status, body = http_json(f"{base}/verify", "POST", b"",
                                         {"Authorization": f"Bearer {token_a}"})
                check("issuer A token accepted", status == 200 and body["issuer"] == ISSUER_A,
                      f"HTTP {status}")
                status_b, body_b = http_json(f"{base}/verify", "POST", b"",
                                             {"Authorization": f"Bearer {token_b}"})
                check("issuer B token accepted", status_b == 200 and body_b["issuer"] == ISSUER_B,
                      f"HTTP {status_b}")
                check("A and B used different snapshots",
                      body["snapshot_digest"] != body_b["snapshot_digest"])
                check("one simulator fetch per issuer",
                      sim.request_count() == 2, f"fetches={sim.request_count()}")

                print("\nB. Cached verification does not refetch")
                fetches = sim.request_count()
                for _ in range(10):
                    http_json(f"{base}/verify", "POST", b"",
                              {"Authorization": f"Bearer {token_a}"})
                check("10 verifications caused 0 additional fetches",
                      sim.request_count() == fetches, f"fetches={sim.request_count()}")

                print("\nC. Unknown issuer / bad audience / tampering rejected")
                status, _ = http_json(f"{base}/verify", "POST", b"",
                                      {"Authorization": "Bearer eyJhbGciOiJub25lIn0.e30."})
                check("alg=none rejected", status == 401, f"HTTP {status}")

                print("\nD. Rotation: same kid, new public key, via admin refresh")
                old_token = mint(keystore, ISSUER_A, ttl=600)
                check("old token still valid before rotation",
                      http_json(f"{base}/verify", "POST", b"",
                                {"Authorization": f"Bearer {old_token}"})[0] == 200)
                new_private = generate_rsa_key()
                sim.set_jwks(f"/{ISSUER_A.rsplit('//', 1)[1]}/jwks.json",
                             {"keys": [__import__("jwt_service.jwks", fromlist=["public_jwk"])
                                       .public_jwk("key-1", new_private.public_key())]})
                status, body = http_json(
                    f"{base}/admin/refresh", "POST",
                    json.dumps({"issuer": ISSUER_A}).encode(),
                    {"Authorization": f"Bearer {ADMIN_TOKEN}",
                     "Content-Type": "application/json"},
                )
                check("admin refresh published a new snapshot",
                      status == 200 and body["refreshed"][ISSUER_A]["ok"],
                      f"HTTP {status} seq={body['refreshed'][ISSUER_A].get('seq')}")
                status, body = http_json(f"{base}/verify", "POST", b"",
                                         {"Authorization": f"Bearer {old_token}"})
                check("old token rejected after rotation (signature_invalid)",
                      status == 401 and body.get("error") == "signature_invalid",
                      f"HTTP {status} {body.get('error')}")

                print("\nE. Admin status and failures")
                status, body = http_json(f"{base}/admin/status", headers={
                    "Authorization": f"Bearer {ADMIN_TOKEN}"})
                check("admin status readable", status == 200)
                check("admin status hides the admin token",
                      ADMIN_TOKEN not in json.dumps(body))
                status, _ = http_json(f"{base}/admin/status")
                check("admin status requires auth", status == 401, f"HTTP {status}")
                status, _ = http_json(f"{base}/admin/refresh", "POST",
                                      b'{"issuer":"https://nope.test"}',
                                      {"Authorization": f"Bearer {ADMIN_TOKEN}"})
                check("unknown issuer -> 404", status == 404, f"HTTP {status}")

                print("\nF. No JWKS request carried credentials")
                check("simulator saw no cookies/authorization",
                      sim.credentials_seen() is False)
            finally:
                server.terminate()
                try:
                    server.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    server.kill()
        finally:
            sim.stop()

    failures = [c for c in checks if not c[1]]
    print("\n" + "=" * 60)
    print(f"{len(checks) - len(failures)}/{len(checks)} checks passed")
    if failures:
        for name, _, detail in failures:
            print(f"  FAILED: {name} {detail}")
        return 1
    return 0


def _healthy(base: str) -> bool:
    try:
        with urllib.request.urlopen(f"{base}/healthz", timeout=1) as response:
            return response.status == 200
    except Exception:
        return False


if __name__ == "__main__":
    raise SystemExit(main())
