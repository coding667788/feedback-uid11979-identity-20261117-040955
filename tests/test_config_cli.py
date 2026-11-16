"""Configuration, keystore and CLI tests."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from conftest import ADMIN_TOKEN
from jwt_service.config import (
    IssuerConfig,
    JwksLimits,
    ServiceConfig,
    load_service_config,
)
from jwt_service.errors import ConfigError
from jwt_service.issuer import TokenSpec, sign_jwt
from jwt_service.keystore import StoredIssuer, load_keystore, new_issuer, save_keystore
from jwt_service.token_cli import build_token, main as token_main

ROOT = Path(__file__).resolve().parents[1]


def _write(tmp_path: Path, payload: object) -> Path:
    path = tmp_path / "config.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _valid_config_payload() -> dict:
    return {
        "issuers": [
            {"issuer": "https://a.test", "jwks_url": "http://127.0.0.1:9001/a", "audience": "aud-a"},
            {"issuer": "https://b.test", "jwks_url": "http://127.0.0.1:9001/b", "audience": "aud-b"},
        ],
        "admin_token": ADMIN_TOKEN,
        "listen_host": "127.0.0.1",
        "listen_port": 0,
    }


def test_valid_config_round_trip(tmp_path):
    config = load_service_config(_write(tmp_path, _valid_config_payload()))
    assert [item.issuer for item in config.issuers] == ["https://a.test", "https://b.test"]
    assert config.snapshot_ttl_seconds == 60
    assert config.auto_refresh_cooldown_seconds == 5
    assert config.limits.min_rsa_bits == 2048


@pytest.mark.parametrize(
    "mutate",
    [
        lambda c: c["issuers"][1].update(issuer=c["issuers"][0]["issuer"]),
        lambda c: c["issuers"][1].update(jwks_url=c["issuers"][0]["jwks_url"]),
        lambda c: c["issuers"][1].update(audience=c["issuers"][0]["audience"]),
        lambda c: c.update(admin_token="short"),
        lambda c: c["issuers"][0].update(jwks_url="file:///etc/passwd"),
        lambda c: c["issuers"][0].update(jwks_url="http://user:pw@host/jwks"),
        lambda c: c.update(listen_host="0.0.0.0"),
        lambda c: c.update(snapshot_ttl_seconds=0),
        lambda c: c.update(auto_refresh_cooldown_seconds=0),
        lambda c: c["issuers"][0].pop("audience"),
        lambda c: c.update(issuers=[]),
        lambda c: c.update(limits={"max_keys": 0}),
        lambda c: c.update(limits={"unknown": 1}),
        lambda c: c.update(fetch_timeout_seconds="2"),
        lambda c: c.update(fetch_timeout_seconds=True),
    ],
)
def test_invalid_configs_rejected(tmp_path, mutate):
    payload = _valid_config_payload()
    mutate(payload)
    with pytest.raises(ConfigError):
        load_service_config(_write(tmp_path, payload))


def test_duplicate_json_member_in_config_rejected(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(
        '{"issuers":[],"issuers":[],"admin_token":"%s"}' % ADMIN_TOKEN, encoding="utf-8"
    )
    with pytest.raises(ConfigError):
        load_service_config(path)


def test_config_file_must_exist(tmp_path):
    with pytest.raises(ConfigError) as info:
        load_service_config(tmp_path / "missing.json")
    assert info.value.code == "config_unreadable"


def test_service_config_direct_construction():
    with pytest.raises(ConfigError):
        ServiceConfig(
            issuers=(
                IssuerConfig("https://a", "http://h/a", "aud"),
                IssuerConfig("https://b", "http://h/a", "aud2"),
            ),
            admin_token=ADMIN_TOKEN,
        )
    with pytest.raises(ConfigError):
        JwksLimits(min_rsa_bits=1024)


# --------------------------------------------------------------- keystore

def test_keystore_round_trip(tmp_path):
    issuer = new_issuer("https://a.test", "aud-a", ["k1", "k2"])
    path = tmp_path / "keys.json"
    save_keystore(path, [issuer])
    loaded = load_keystore(path)
    assert len(loaded) == 1
    assert [k.kid for k in loaded[0].keys] == ["k1", "k2"]
    numbers = loaded[0].active().public_key.public_numbers()
    assert numbers == issuer.active().public_key.public_numbers()
    assert loaded[0].jwks()["keys"][0]["kid"] == "k1"


def test_keystore_rejects_garbage(tmp_path):
    path = tmp_path / "keys.json"
    path.write_text('{"issuers":[{"issuer":"x"}]}', encoding="utf-8")
    with pytest.raises(ConfigError):
        load_keystore(path)


# --------------------------------------------------------------- token CLI

def test_token_cli_builds_verifiable_token(tmp_path):
    issuer = new_issuer("https://a.test", "aud-a", ["k1", "k2"])
    path = tmp_path / "keys.json"
    save_keystore(path, [issuer])
    token = build_token(issuer, now=1_800_000_000, ttl=120, sub="alice")
    assert token.count(".") == 2
    # Verify with the same key independently.
    from jwt_service.strict_json import b64url_decode_strict

    header_b64, payload_b64, sig_b64 = token.split(".")
    payload = json.loads(b64url_decode_strict(payload_b64))
    assert payload["iss"] == "https://a.test"
    assert payload["sub"] == "alice"
    assert payload["aud"] == "aud-a"
    assert payload["exp"] == 1_800_000_120
    assert payload["nbf"] == 1_800_000_000
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    issuer.keys[0].public_key.verify(
        b64url_decode_strict(sig_b64),
        f"{header_b64}.{payload_b64}".encode(),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )


def test_token_cli_specific_kid_and_unknown_kid(tmp_path, capsys):
    issuer = new_issuer("https://a.test", "aud-a", ["k1", "k2"])
    path = tmp_path / "keys.json"
    save_keystore(path, [issuer])
    rc = token_main([
        "--keystore", str(path), "--issuer", "https://a.test",
        "--kid", "k2", "--now", "1800000000",
    ])
    assert rc == 0
    token = capsys.readouterr().out.strip()
    header = json.loads(
        __import__("jwt_service.strict_json", fromlist=["b64url_decode_strict"])
        .b64url_decode_strict(token.split(".")[0])
    )
    assert header["kid"] == "k2"

    rc = token_main([
        "--keystore", str(path), "--issuer", "https://a.test", "--kid", "nope",
    ])
    assert rc == 2


def test_token_cli_runs_as_module(tmp_path):
    issuer = new_issuer("https://a.test", "aud-a", ["k1"])
    path = tmp_path / "keys.json"
    save_keystore(path, [issuer])
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT)
    completed = subprocess.run(
        [
            sys.executable, "-m", "jwt_service.token_cli",
            "--keystore", str(path), "--issuer", "https://a.test",
            "--sub", "bob", "--ttl", "60", "--now", "1800000000",
        ],
        cwd=str(tmp_path), env=env, capture_output=True, text=True, timeout=60,
    )
    assert completed.returncode == 0, completed.stderr
    token = completed.stdout.strip()
    assert token.count(".") == 2


def test_parser_rejects_unknown_crit_and_bad_alg_independently():
    """Unit-level check of the header gate, independent of the HTTP layer."""
    from jwt_service.token import _split, _validate_header

    issuer = new_issuer("https://a.test", "aud-a", ["k1"])
    spec = TokenSpec(
        issuer="https://a.test", subject="s", audience="aud-a", kid="k1",
        exp=10, nbf=0, extra_header={"crit": ["foo"]},
    )
    parsed = _split(sign_jwt(spec, issuer.keys[0].private_key))
    with pytest.raises(Exception) as info:
        _validate_header(parsed.header, 256)
    assert getattr(info.value, "code", None) == "unsupported_crit"
