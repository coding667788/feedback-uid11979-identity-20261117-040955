"""Test keystore used by the simulator and the standalone token generator.

The file contains **private keys**.  It is generated only for local testing,
is written with restrictive permissions where the platform allows it, and
must never be used for anything real.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from .errors import ConfigError
from .issuer import generate_rsa_key
from .jwks import public_jwk
from .strict_json import strict_json_loads


@dataclass
class StoredKey:
    kid: str
    private_key: rsa.RSAPrivateKey

    @property
    def public_key(self) -> rsa.RSAPublicKey:
        return self.private_key.public_key()


@dataclass
class StoredIssuer:
    issuer: str
    audience: str
    keys: list[StoredKey]

    def active(self) -> StoredKey:
        return self.keys[0]

    def jwks(self) -> dict:
        return {"keys": [public_jwk(k.kid, k.public_key) for k in self.keys]}


def new_issuer(issuer: str, audience: str, kids: list[str], *, bits: int = 2048) -> StoredIssuer:
    return StoredIssuer(
        issuer=issuer,
        audience=audience,
        keys=[StoredKey(kid=kid, private_key=generate_rsa_key(bits)) for kid in kids],
    )


def save_keystore(path: str | Path, issuers: list[StoredIssuer]) -> None:
    payload = {
        "_warning": "TEST KEYS ONLY - never use for production",
        "issuers": [
            {
                "issuer": item.issuer,
                "audience": item.audience,
                "keys": [
                    {
                        "kid": key.kid,
                        "private_pem": key.private_key.private_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PrivateFormat.PKCS8,
                            encryption_algorithm=serialization.NoEncryption(),
                        ).decode("ascii"),
                    }
                    for key in item.keys
                ],
            }
            for item in issuers
        ],
    }
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_suffix(target.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    os.replace(tmp, target)


def load_keystore(path: str | Path) -> list[StoredIssuer]:
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError("keystore_unreadable", f"cannot read keystore: {exc}") from exc
    try:
        data = strict_json_loads(text)
    except Exception as exc:
        raise ConfigError("keystore_invalid", f"keystore JSON is invalid: {exc}") from exc
    if type(data) is not dict or type(data.get("issuers")) is not list:
        raise ConfigError("keystore_invalid", "keystore must contain an issuers array")
    result: list[StoredIssuer] = []
    for entry in data["issuers"]:
        if type(entry) is not dict:
            raise ConfigError("keystore_invalid", "issuer entry must be an object")
        issuer = entry.get("issuer")
        audience = entry.get("audience")
        keys = entry.get("keys")
        if not isinstance(issuer, str) or not isinstance(audience, str):
            raise ConfigError("keystore_invalid", "issuer/audience must be strings")
        if type(keys) is not list or not keys:
            raise ConfigError("keystore_invalid", "issuer must have at least one key")
        stored: list[StoredKey] = []
        for key_entry in keys:
            if type(key_entry) is not dict:
                raise ConfigError("keystore_invalid", "key entry must be an object")
            kid = key_entry.get("kid")
            pem = key_entry.get("private_pem")
            if not isinstance(kid, str) or not isinstance(pem, str):
                raise ConfigError("keystore_invalid", "key needs kid and private_pem")
            try:
                private_key = serialization.load_pem_private_key(
                    pem.encode("ascii"), password=None
                )
            except (ValueError, TypeError) as exc:
                raise ConfigError("keystore_invalid", "private_pem is not usable") from exc
            if not isinstance(private_key, rsa.RSAPrivateKey):
                raise ConfigError("keystore_invalid", "private_pem must be an RSA key")
            stored.append(StoredKey(kid=kid, private_key=private_key))
        result.append(StoredIssuer(issuer=issuer, audience=audience, keys=stored))
    return result
