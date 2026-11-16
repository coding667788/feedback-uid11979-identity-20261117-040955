"""Standalone test-token generator (does not import the verifier).

    python -m jwt_service.token_cli --keystore state/test-keys.json \\
        --issuer https://issuer-a.test --sub alice --ttl 300

Prints a compact RS256 JWT signed with the issuer's *active* (first) test
key.  Use ``--kid`` to sign with a specific key, which is how rotation and
key-substitution scenarios are exercised.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from typing import Any

from .errors import ConfigError
from .issuer import TokenSpec, sign_jwt
from .keystore import StoredIssuer, load_keystore


def build_token(
    stored: StoredIssuer,
    *,
    now: int,
    sub: str = "user-1",
    ttl: int = 300,
    nbf: int | None = None,
    kid: str | None = None,
    audience: str | None = None,
    extra_claims: dict[str, Any] | None = None,
) -> str:
    key = stored.active()
    if kid is not None:
        matches = [k for k in stored.keys if k.kid == kid]
        if not matches:
            raise ConfigError("unknown_kid", f"issuer has no key {kid!r}")
        key = matches[0]
    spec = TokenSpec(
        issuer=stored.issuer,
        subject=sub,
        audience=audience or stored.audience,
        kid=key.kid,
        exp=now + ttl,
        nbf=now if nbf is None else nbf,
        iat=now,
        extra_claims=extra_claims,
    )
    return sign_jwt(spec, key.private_key)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate a local test JWT")
    parser.add_argument("--keystore", required=True)
    parser.add_argument("--issuer", required=True)
    parser.add_argument("--sub", default="user-1")
    parser.add_argument("--audience", default=None)
    parser.add_argument("--kid", default=None)
    parser.add_argument("--ttl", type=int, default=300)
    parser.add_argument("--nbf-offset", type=int, default=0,
                        help="nbf = now + offset (use a positive value to test 'not yet valid')")
    parser.add_argument("--now", type=int, default=None,
                        help="override the clock (defaults to real time)")
    parser.add_argument("--claims", default=None, help="extra claims as a JSON object")
    args = parser.parse_args(argv)

    try:
        issuers = {item.issuer: item for item in load_keystore(args.keystore)}
    except ConfigError as exc:
        print(f"keystore error: {exc}", file=sys.stderr)
        return 2
    if args.issuer not in issuers:
        print(f"unknown issuer {args.issuer!r}", file=sys.stderr)
        return 2
    extra = None
    if args.claims:
        try:
            extra = json.loads(args.claims)
        except json.JSONDecodeError as exc:
            print(f"--claims is not valid JSON: {exc}", file=sys.stderr)
            return 2
        if not isinstance(extra, dict):
            print("--claims must be a JSON object", file=sys.stderr)
            return 2
    now = args.now if args.now is not None else int(time.time())
    try:
        token = build_token(
            issuers[args.issuer],
            now=now,
            sub=args.sub,
            ttl=args.ttl,
            nbf=now + args.nbf_offset,
            kid=args.kid,
            audience=args.audience,
            extra_claims=extra,
        )
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(token)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
