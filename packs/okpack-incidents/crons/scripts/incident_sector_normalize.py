#!/usr/bin/env python3
"""Backfill human-readable two-digit NAICS sectors on historical incident pages."""
from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path

import yaml

from naics_sector import naics_sector

_FM = re.compile(r"\A---[ \t]*\n(.*?\n)---[ \t]*\n?(.*)\Z", re.S)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--vault", default=os.environ.get("WIKI_PATH", "/opt/vault"))
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)
    root = Path(args.vault)
    wiki = root / "wiki" if (root / "wiki").is_dir() else root
    changed = unmapped = 0
    for path in (wiki / "security-incidents").rglob("*.md") if (wiki / "security-incidents").is_dir() else []:
        text = path.read_text(encoding="utf-8", errors="replace")
        match = _FM.match(text)
        if not match:
            continue
        fm = yaml.safe_load(match.group(1))
        if not isinstance(fm, dict) or fm.get("type") != "incident":
            continue
        sector = naics_sector(fm.get("industry"))
        if not sector:
            unmapped += 1
            continue
        if fm.get("sector") == sector:
            continue
        fm["sector"] = sector
        changed += 1
        if not args.dry_run:
            head = yaml.safe_dump(fm, sort_keys=False, allow_unicode=True).rstrip()
            path.write_text(f"---\n{head}\n---\n\n{match.group(2).strip()}\n", encoding="utf-8")
    print(f"incident-sector-normalize: {changed} changed, {unmapped} unmapped")
    print(json.dumps({"wakeAgent": False}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
