#!/usr/bin/env python3
"""okpack-threat-actors — ThaiCERT / ETDA Threat Actor Encyclopedia importer (HISTORICAL SEED ONLY).

DISABLED BY DEFAULT (no domain-crons entry). ETDA's Threat Actor Encyclopedia has broad HISTORICAL
alias coverage but its update cadence slowed sharply after ~2021, so it's a one-time SEED for older
groups the MISP galaxy misses — not a live feed. Run it manually once against a downloaded export:

    THAICERT_SRC=/path/to/etda-export.json python3 thaicert_import.py --vault /opt/vault

⚠ VERIFY AT BUILD: ETDA does not publish a stable machine-readable API. This lane consumes a JSON
array of actor records with the shape below (adapt `_records()` if the export format differs — the
encyclopedia has been distributed as JSON dumps and via the community MISP mirror):
    [{"actor": "APT29", "names": [{"name": "Cozy Bear"}, ...] | ["Cozy Bear", ...],
      "description": "...", "country": "Russia", "tools": [...], "operations": [...]}]

It ENRICHES existing actor pages (unions aliases) and can create low-trust historical stubs.
License: ETDA content is free to use with credit — pages stamp `sources: [ThaiCERT ETDA]`.

Env: WIKI_PATH · THAICERT_SRC (local path or URL to the export) · THAICERT_CREATE_MISSING (0)
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _okf_write import content_root, clean, slug, write_page  # noqa: E402
from misp_galaxy_import import _merge_only, index_actors  # reuse the enrich helpers  # noqa: E402


def _load(src: str) -> list:
    if src.startswith(("http://", "https://")):
        req = urllib.request.Request(src, headers={"User-Agent": "okpack-threat-actors/thaicert"})
        with urllib.request.urlopen(req, timeout=90) as r:  # noqa: S310  # nosec B310 (fixed https upstream)
            data = json.loads(r.read().decode("utf-8"))
    else:
        data = json.loads(Path(src).read_text(encoding="utf-8"))
    return data if isinstance(data, list) else data.get("actors") or data.get("values") or []


def _records(raw: list):
    """Normalize an ETDA record -> (name, aliases, description, country). Adapt here if the export
    shape differs — this is the one spot coupled to ETDA's format (flagged in the module docstring)."""
    for rec in raw:
        name = (rec.get("actor") or rec.get("value") or rec.get("name") or "").strip()
        if not name:
            continue
        names = rec.get("names") or rec.get("synonyms") or []
        aliases = [(n.get("name") if isinstance(n, dict) else n) for n in names]
        aliases = [a for a in aliases if a and a != name]
        yield name, aliases, clean(rec.get("description") or ""), rec.get("country")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--vault", default=os.environ.get("WIKI_PATH", "/opt/vault"))
    ap.add_argument("--src", default=os.environ.get("THAICERT_SRC", ""))
    ap.add_argument("--create-missing", action="store_true",
                    default=os.environ.get("THAICERT_CREATE_MISSING", "0") == "1")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)
    if not args.src:
        print("ERROR: set THAICERT_SRC (path/URL to an ETDA export) — this lane is a manual "
              "historical seed, disabled by default. See the module docstring.", file=sys.stderr)
        return 2
    vault = content_root(Path(args.vault))

    try:
        raw = _load(args.src)
    except Exception as e:                            # noqa: BLE001
        print(f"ERROR: could not load ETDA export from {args.src}: {e}", file=sys.stderr)
        return 1

    idx = index_actors(vault)
    enriched = created = 0
    for name, aliases, desc, country in _records(raw):
        rel = idx.get(name.lower()) or next((idx[a.lower()] for a in aliases if a.lower() in idx), None)
        fm = {"type": "actor", "aliases": aliases, "sources": ["ThaiCERT ETDA"]}
        if country:
            fm["origin_country"] = country
        if rel:
            _merge_only(vault, rel, fm, dry_run=args.dry_run)
            enriched += 1
        elif args.create_missing:
            key = slug(name)
            fm.update({"id": key, "title": name, "needs_review": True,
                       "attribution_confidence": "unverified"})
            body = (f"# {name}\n\n{desc}\n\n> Historical seed from the ThaiCERT/ETDA Threat Actor "
                    "Encyclopedia (coverage may be dated). Low-trust — verify before relying on it.")
            write_page(vault, f"entities/{key}.md", fm, body, dry_run=args.dry_run)
            idx[name.lower()] = f"entities/{key}.md"
            created += 1

    print(f"thaicert-seed: {enriched} enriched, {created} created (historical, one-time)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
