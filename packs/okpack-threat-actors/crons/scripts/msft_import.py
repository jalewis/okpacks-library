#!/usr/bin/env python3
"""okpack-threat-actors — Microsoft "Rosetta Stone" actor-alias enrichment (no_agent, ZERO LLM tokens).

The cross-vendor ALIAS BACKBONE. Microsoft publishes `ThreatActorNaming/MicrosoftMapping.json` — its
weather-suffix actor names (Aqua Blizzard, Midnight Blizzard, …) mapped to each actor's "Other names"
(Gamaredon, NOBELIUM, APT29, …). This lane UNIONS those names onto the ATT&CK/MISP-seeded actor pages
(matching by the Microsoft name or any other name already on a page), so a feed mention under ANY
vendor's naming resolves to one canonical actor — and CREATES a low-trust page for a Microsoft actor
neither ATT&CK nor the MISP galaxy covers. Mirrors misp_galaxy_import; runs after it (okengine#182).

License: Microsoft threat-actor naming taxonomy, github.com/microsoft/mstic (MIT) — pages stamp
`sources: [Microsoft]`.

Env: WIKI_PATH (/opt/vault) · MSFT_MAP_URL (override the mapping URL) · MSFT_CREATE_MISSING (1)
Usage: msft_import.py [--vault DIR] [--no-create] [--dry-run]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _okf_write import content_root, slug, write_page          # noqa: E402
from misp_galaxy_import import index_actors, _merge_only        # noqa: E402  (reuse the alias engine)

MSFT_URL = os.environ.get(
    "MSFT_MAP_URL",
    "https://raw.githubusercontent.com/microsoft/mstic/master/"
    "PublicFeeds/ThreatActorNaming/MicrosoftMapping.json")
# Non-country `Origin/Threat` descriptors — kept OUT of origin_country (attribution discipline).
_MOTIVATIONS = {"financially motivated", "influence operations", "hacktivist", "cybercrime",
                "private sector offensive actor", "information operations", "unknown"}


def _fetch(url: str) -> list:
    req = urllib.request.Request(url, headers={"User-Agent": "okpack-threat-actors/msft"})
    with urllib.request.urlopen(req, timeout=90) as r:   # noqa: S310 (fixed https host)  # nosec B310 (fixed https upstream)
        return json.loads(r.read().decode("utf-8"))


def _origin_country(s: str) -> str | None:
    """First non-motivation token of Microsoft's `Origin/Threat` comma list — its country, if any."""
    for tok in str(s).split(","):
        t = tok.strip()
        if t and t.lower() not in _MOTIVATIONS:
            return t
    return None


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--vault", default=os.environ.get("WIKI_PATH", "/opt/vault"))
    ap.add_argument("--no-create", action="store_true",
                    default=os.environ.get("MSFT_CREATE_MISSING", "1") == "0")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)
    vault = content_root(Path(args.vault))

    try:
        records = _fetch(MSFT_URL)
    except Exception as e:                               # noqa: BLE001 — best-effort enrichment lane
        print(f"ERROR: Microsoft mapping fetch failed: {e}", file=sys.stderr)
        return 1

    idx = index_actors(vault)
    enriched = created = errs = 0
    for r in records:
        name = (r.get("Threat actor name") or "").strip()
        if not name:
            continue
        others = [a.strip() for a in (r.get("Other names") or "").split(",") if a.strip()]
        all_names = [name] + others
        # match by the Microsoft name OR any of its other names already on a page
        rel = next((idx[n.lower()] for n in all_names if n.lower() in idx), None)
        fm = {"type": "actor", "aliases": all_names, "sources": ["Microsoft"]}
        country = _origin_country(r.get("Origin/Threat") or "")
        if country:
            fm["origin_country"] = country
        try:
            if rel:                                      # ENRICH: union the names onto the page
                _merge_only(vault, rel, fm, dry_run=args.dry_run)
                enriched += 1
            elif not args.no_create:                     # CREATE a low-trust Microsoft-only actor
                key = slug(name)
                fm.update({"id": key, "title": name, "needs_review": True,
                           "attribution_confidence": "unverified"})
                body = (f"# {name}\n\n"
                        "> Seeded no_agent from the Microsoft threat-actor naming taxonomy "
                        "(not in MITRE ATT&CK or the MISP galaxy). Low-trust — verify attribution.")
                write_page(vault, f"entities/{key[:1] or '_'}/{key}.md", fm, body, dry_run=args.dry_run)
                idx[name.lower()] = f"entities/{key[:1] or '_'}/{key}.md"
                for n in all_names:
                    idx.setdefault(n.lower(), f"entities/{key[:1] or '_'}/{key}.md")
                created += 1
        except OSError as e:
            errs += 1
            print(f"WARN: {name}: {e}", file=sys.stderr)

    print(f"msft-mapping: {enriched} actor(s) alias-enriched, {created} created (of {len(records)})"
          f"{f', {errs} error(s)' if errs else ''}")
    print(json.dumps({"wakeAgent": False}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
