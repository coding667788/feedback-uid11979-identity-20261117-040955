"""Generate test keys and the JWKS simulator's data.

    python -m jwt_service.tools_init --config config/local.json \\
        --keystore state/test-keys.json

Creates a keystore with one issuer entry per configured issuer (kid ``key-1``).
Keys are random RSA-2048 test keys.  The file is written under ``state/`` which
is git-ignored because it contains *private* test keys.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from urllib.parse import urlsplit

from .config import load_service_config
from .errors import ConfigError
from .keystore import new_issuer, save_keystore


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Create local test keys for the demo")
    parser.add_argument("--config", default="config/local.json")
    parser.add_argument("--keystore", default="state/test-keys.json")
    parser.add_argument("--kids", default="key-1", help="comma separated key ids")
    args = parser.parse_args(argv)
    try:
        config = load_service_config(args.config)
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 2
    kids = [kid.strip() for kid in args.kids.split(",") if kid.strip()]
    if not kids:
        print("at least one kid is required", file=sys.stderr)
        return 2
    issuers = [new_issuer(item.issuer, item.audience, kids) for item in config.issuers]
    save_keystore(args.keystore, issuers)
    print(f"wrote {len(issuers)} issuer(s) x {len(kids)} key(s) to {args.keystore}")
    for item in config.issuers:
        print(f"  {item.issuer} -> {urlsplit(item.jwks_url).path}")
    print("WARNING: these are test private keys. Never reuse them anywhere real.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
