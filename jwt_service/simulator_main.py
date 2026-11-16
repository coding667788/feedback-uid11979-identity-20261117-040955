"""Run the local JWKS simulator with a keystore.

    python -m jwt_service.simulator_main --config config/local.json \\
        --keystore state/test-keys.json

The simulator serves each configured issuer's JWKS at the path of its
configured ``jwks_url``.  It also exposes ``/__admin/stats`` for request
counts (loopback only) used by manual inspection; tests use the in-process
:class:`~jwt_service.simulator.JwksSimulator` object instead.
"""

from __future__ import annotations

import argparse
import sys
import time
from urllib.parse import urlsplit

from .config import load_service_config
from .errors import ConfigError
from .keystore import load_keystore
from .simulator import JwksSimulator


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Local JWKS HTTP simulator")
    parser.add_argument("--config", required=True)
    parser.add_argument("--keystore", required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=0)
    args = parser.parse_args(argv)

    try:
        config = load_service_config(args.config)
        stored = {item.issuer: item for item in load_keystore(args.keystore)}
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 2

    sim = JwksSimulator(args.host, args.port)
    for issuer_cfg in config.issuers:
        if issuer_cfg.issuer not in stored:
            print(f"keystore has no issuer {issuer_cfg.issuer!r}", file=sys.stderr)
            return 2
        path = urlsplit(issuer_cfg.jwks_url).path or "/"
        sim.set_jwks(path, stored[issuer_cfg.issuer].jwks())
        print(f"serving {issuer_cfg.issuer} at {path}", file=sys.stderr)
    sim.start()
    print(f"simulator listening on http://{sim.host}:{sim.port}", file=sys.stderr)
    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        sim.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
