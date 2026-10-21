"""CLI entry point: ldap-keycloak-sync --config config.yaml [--dry-run] [--adopt-existing]."""

from __future__ import annotations

import argparse
import logging
import sys

from .config import load_config
from .sync import adopt_existing, run


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="ldap-keycloak-sync", description=__doc__)
    p.add_argument("--config", required=True, help="path to YAML config")
    p.add_argument("--dry-run", action="store_true", help="log planned actions, make no changes")
    p.add_argument(
        "--adopt-existing",
        action="store_true",
        help="one-time: tag current realm users as managed, then exit (no create/update/disable)",
    )
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    cfg = load_config(args.config)
    if args.adopt_existing:
        return adopt_existing(cfg, dry_run=args.dry_run)
    return run(cfg, dry_run=args.dry_run)


if __name__ == "__main__":
    sys.exit(main())
