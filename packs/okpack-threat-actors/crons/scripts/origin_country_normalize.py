#!/usr/bin/env python3
"""Converge actor ``origin_country`` values to ISO alpha-2 codes (no_agent)."""
from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path

import yaml

from country_normalize import normalize_country

_FM = re.compile(r"\A---[ \t]*\n(.*?\n)---[ \t]*\n?(.*)\Z", re.S)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--vault", default=os.environ.get("WIKI_PATH", "/opt/vault"))
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)
    root = Path(args.vault)
    wiki = root / "wiki" if (root / "wiki").is_dir() else root
    changed = unresolved = 0
    for path in (wiki / "entities").rglob("*.md") if (wiki / "entities").is_dir() else []:
        text = path.read_text(encoding="utf-8", errors="replace")
        match = _FM.match(text)
        if not match:
            continue
        fm = yaml.safe_load(match.group(1))
        if not isinstance(fm, dict) or fm.get("type") != "actor" or not fm.get("origin_country"):
            continue
        canonical = normalize_country(fm["origin_country"])
        if not canonical:
            fm["origin_country_raw"] = fm.pop("origin_country")
            fm["needs_review"] = True
            unresolved += 1
        elif canonical == fm["origin_country"]:
            continue
        else:
            fm["origin_country"] = canonical
        changed += 1
        if not args.dry_run:
            head = yaml.safe_dump(fm, sort_keys=False, allow_unicode=True).rstrip()
            path.write_text(f"---\n{head}\n---\n\n{match.group(2).strip()}\n", encoding="utf-8")
    print(f"origin-country-normalize: {changed} changed, {unresolved} ambiguous/unrecognized")
    print(json.dumps({"wakeAgent": False}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
