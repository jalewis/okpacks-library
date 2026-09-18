#!/usr/bin/env python3
"""Generate or check README pack tables from catalog.json."""

from __future__ import annotations

import argparse
from pathlib import Path

try:
    from pack_catalog_docs import synchronize
except ModuleNotFoundError:  # imported as scripts.generate_pack_catalog by tests
    from scripts.pack_catalog_docs import synchronize


ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="fail instead of updating drifted files")
    args = parser.parse_args()

    drifted = synchronize(ROOT, check=args.check)
    if not drifted:
        print("pack catalog documentation is current")
        return 0
    names = ", ".join(path.relative_to(ROOT).as_posix() for path in drifted)
    if args.check:
        print(f"pack catalog documentation is stale: {names}")
        print("run: python3 scripts/generate_pack_catalog.py")
        return 1
    print(f"updated pack catalog documentation: {names}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
