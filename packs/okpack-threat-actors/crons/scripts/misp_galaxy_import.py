#!/usr/bin/env python3
"""okpack-threat-actors — MISP threat-actor galaxy importer (no_agent, ZERO LLM tokens).

The ALIAS engine. The MISP galaxy (github.com/MISP/misp-galaxy) ships a JSON cluster that already
aggregates ATT&CK + ThaiCERT + vendor naming into ONE synonym set per actor — purpose-built for the
reconciliation this pack showcases. This lane UNIONS those synonyms onto the ATT&CK-seeded actor
pages (matching by name or any existing alias), and CREATES a low-trust actor page for any galaxy
actor ATT&CK doesn't cover. Runs AFTER attack_import so it enriches rather than races it.

License: MISP galaxy is CC-BY — pages stamp `sources: [MISP galaxy]`.

Env: WIKI_PATH (/opt/vault) · MISP_GALAXY_URL (default the raw threat-actor.json) · MISP_CREATE_MISSING (1)
Usage: misp_galaxy_import.py [--vault DIR] [--no-create] [--dry-run]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.request
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _okf_write import content_root, clean, slug, write_page  # noqa: E402

GALAXY_URL = os.environ.get(
    "MISP_GALAXY_URL",
    "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/threat-actor.json")
FETCH_TIMEOUT = 90
_COUNTRY_TO_TYPE = {}   # (kept simple; country -> nothing inferred: attribution stays conservative)


def _fetch(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "okpack-threat-actors/misp"})
    with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT) as r:  # noqa: S310  # nosec B310 (fixed https upstream)
        return json.loads(r.read().decode("utf-8"))


def index_actors(vault: Path) -> dict:
    """name/alias (lowercased) -> relative page path, over existing type:actor pages."""
    idx = {}
    ent = vault / "entities"
    if not ent.exists():
        return idx
    for p in ent.rglob("*.md"):
        txt = p.read_text(encoding="utf-8", errors="ignore")
        if not txt.startswith("---"):
            continue
        end = txt.find("\n---", 3)
        try:
            fm = yaml.safe_load(txt[3:end]) if end != -1 else None
        except yaml.YAMLError:
            fm = None
        if not isinstance(fm, dict) or fm.get("type") != "actor":
            continue
        rel = str(p.relative_to(vault))
        for name in [fm.get("title"), fm.get("id")] + list(fm.get("aliases") or []):
            if name:
                idx.setdefault(str(name).lower(), rel)
    return idx


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--vault", default=os.environ.get("WIKI_PATH", "/opt/vault"))
    ap.add_argument("--no-create", action="store_true",
                    default=os.environ.get("MISP_CREATE_MISSING", "1") == "0")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)
    vault = content_root(Path(args.vault))

    try:
        galaxy = _fetch(GALAXY_URL)
    except Exception as e:                            # noqa: BLE001
        print(f"ERROR: MISP galaxy fetch failed: {e}", file=sys.stderr)
        return 1

    idx = index_actors(vault)
    enriched = created = errs = 0
    for v in galaxy.get("values", []):
        name = (v.get("value") or "").strip()
        if not name:
            continue
        meta = v.get("meta") or {}
        synonyms = [s for s in (meta.get("synonyms") or []) if s and s != name]
        # find the target page by primary name or any synonym already on a page
        rel = idx.get(name.lower()) or next((idx[s.lower()] for s in synonyms if s.lower() in idx), None)
        fm = {"type": "actor", "aliases": synonyms, "sources": ["MISP galaxy"]}
        if meta.get("country"):
            fm["origin_country"] = meta["country"]
        if meta.get("cfr-target-category"):
            fm["target_sector"] = [str(s).lower() for s in meta["cfr-target-category"]]
        try:
            if rel:                                   # ENRICH: merge synonyms onto the existing page
                _merge_only(vault, rel, fm, dry_run=args.dry_run)
                enriched += 1
            elif not args.no_create:                  # CREATE a low-trust galaxy-only actor
                key = slug(name)
                fm.update({"id": key, "title": name, "needs_review": True,
                           "attribution_confidence": "unverified"})
                body = (f"# {name}\n\n{clean(v.get('description') or '')}\n\n"
                        "> Seeded no_agent from the MISP threat-actor galaxy (not in MITRE ATT&CK). "
                        "Low-trust — verify before relying on attribution.")
                write_page(vault, f"entities/{key}.md", fm, body, dry_run=args.dry_run)
                idx[name.lower()] = f"entities/{key}.md"
                created += 1
        except OSError as e:
            errs += 1
            print(f"WARN: {name}: {e}", file=sys.stderr)

    print(f"misp-galaxy: {enriched} actor(s) alias-enriched, {created} created"
          f"{f', {errs} error(s)' if errs else ''}")
    print(json.dumps({"wakeAgent": False}))
    return 0


def _merge_only(vault: Path, rel: str, fm: dict, *, dry_run: bool) -> None:
    """Merge alias/sector fields onto an existing page WITHOUT rewriting its body."""
    path = vault / rel
    txt = path.read_text(encoding="utf-8")
    end = txt.find("\n---", 3)
    body = txt[end + 4:].lstrip("\n") if end != -1 else ""
    write_page(vault, rel, fm, body, dry_run=dry_run)


if __name__ == "__main__":
    sys.exit(main())
