"""Run the verification HTTP service from a JSON config file.

    python -m jwt_service.server_main --config config/local.json
"""

from __future__ import annotations

import argparse
import signal
import sys
import time

from .app import AppServices
from .config import load_service_config
from .errors import ConfigError
from .server import VerificationService


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Strict local JWT verification service")
    parser.add_argument("--config", required=True, help="path to service JSON config")
    parser.add_argument(
        "--no-warmup", action="store_true", help="do not fetch JWKS at startup"
    )
    args = parser.parse_args(argv)

    try:
        config = load_service_config(args.config)
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 2

    services = AppServices.build(config)
    if not args.no_warmup:
        results = services.warm_up()
        for issuer, outcome in results.items():
            print(f"warmup {issuer}: {outcome}", file=sys.stderr)
    with VerificationService(services, host=config.listen_host, port=config.listen_port) as srv:
        print(f"verification service listening on {srv.base_url()}", file=sys.stderr)
        print("press Ctrl+C to stop", file=sys.stderr)

        def _stop(signum: int, frame: object) -> None:
            raise KeyboardInterrupt

        try:
            signal.signal(signal.SIGINT, _stop)
        except (ValueError, OSError):
            pass
        try:
            while True:
                time.sleep(0.5)
        except KeyboardInterrupt:
            print("shutting down", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
