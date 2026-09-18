#!/usr/bin/env python3
"""okpack-threat-actors — actor↔CVE edge materializer (no_agent, ZERO LLM tokens).

Turns the actor→CVE relationship — which today is scattered across several actor fields and mediated
by ATT&CK techniques — into ONE navigable pivot the cockpit can render in both directions:

  * stamps `exploiting_actors` (sorted actor slugs) onto each EXISTING cve page  → the Vulnerabilities
    tab can show "who exploits this CVE" and drill CVE → actor.
  * stamps `exploited_cve_ids`  (sorted CVE ids)   onto each actor page          → the Adversaries
    tab can show "which CVEs this actor exploits" and drill actor → CVE.

Edge sources (union — so the pivot agrees no matter which ingest populated it):
  * DIRECT on actor pages: `exploits_cve`, `cves_exploited`, `np_cves_exploited`
    (the last is an operator-extension field; read opportunistically — absent deployments just skip it).
  * TECHNIQUE-MEDIATED: actor.`techniques` → technique.`exploits_cve` — the same actor→technique→CVE
    seam `cti_dashboards.py` uses for its top-exploited-cves board, so the two never disagree on that hop.

Enrich-only: a CVE id with no okcti cve page is recorded on the actor's `exploited_cve_ids` but never
creates a cve page. Direct read-modify-write with SET semantics (NOT a list-union merge) so an actor
that stops exploiting a CVE is dropped on the next run; body + all other frontmatter preserved.
Idempotent — a page whose field already equals the computed value is left untouched.

Env: WIKI_PATH (/opt/vault) · CVE_ACTOR_SOURCE_FIELDS (comma list, default
     "exploits_cve,cves_exploited,np_cves_exploited")
Usage: cve_actor_edge.py [--vault DIR] [--dry-run]
"""
from __future__ import annotations

import argparse
import collections
import glob
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _okf_write import content_root  # noqa: E402

_DEFAULT_SOURCE_FIELDS = ("exploits_cve", "cves_exploited", "np_cves_exploited")


def _split(p: Path) -> tuple[dict, str]:
    try:
        txt = p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {}, ""                    # page moved/deleted by a concurrent lane mid-scan
    if not txt.startswith("---"):
        return {}, txt
    end = txt.find("\n---", 3)
    if end < 0:
        return {}, txt
    try:
        fm = yaml.safe_load(txt[3:end])
    except yaml.YAMLError:
        fm = None
    body = txt[end + 4:]
    return (fm if isinstance(fm, dict) else {}), body.lstrip("\n")


def _cve_ids(val) -> list[str]:
    """Normalize a frontmatter value into a list of upper-cased CVE ids (accepts scalar or list)."""
    if val in (None, "", []):
        return []
    items = val if isinstance(val, list) else [val]
    out = []
    for x in items:
        s = str(x).strip().upper()
        if s.startswith("CVE-"):
            out.append(s)
    return out


def _load(wiki: Path):
    def rd(sub):
        return {Path(p).stem: _split(Path(p))[0]
                for p in glob.glob(f"{wiki}/{sub}/**/*.md", recursive=True)
                if not Path(p).stem.startswith(("INDEX", "_"))}
    ents = rd("entities")
    actors = {k: v for k, v in ents.items() if v.get("type") == "actor"}
    techs = {k: v for k, v in rd("techniques").items() if v.get("type") == "technique"}
    return actors, techs


def _cve_index(wiki: Path) -> dict:
    """CVE-ID (upper) -> cve page Path, wherever it is sharded (cve_id field, else the stem)."""
    out: dict[str, Path] = {}
    d = wiki / "cves"
    if d.is_dir():
        for p in d.rglob("*.md"):
            if p.stem.startswith(("INDEX", "_")):
                continue
            fm, _ = _split(p)
            cid = str(fm.get("cve_id") or p.stem).upper()
            if cid.startswith("CVE-"):
                out.setdefault(cid, p)
    return out


def compute_edges(actors: dict, techs: dict, source_fields) -> tuple[dict, dict]:
    """(actor_slug -> sorted CVE ids, CVE id -> sorted actor IDS) from direct + technique-mediated
    edges. Pure — no I/O — so it is unit-testable with plain dicts.

    forward is keyed by SLUG (so the caller can find the actor page to stamp); reverse is valued by the
    actor's `id` field (falling back to slug), because the Vulnerabilities-tab bar resolves it via
    link_page {dir: entities, by: id} — ATT&CK-imported actors carry id=G#### != slug, so stamping the
    slug would leave those bars unlinked (okengine#259 rec 8 follow-up)."""
    tech_cves = {}                                     # ATT&CK id (and slug) -> [CVE ids]
    for slug, t in techs.items():
        cs = _cve_ids(t.get("exploits_cve"))
        if cs:
            tech_cves[str(t.get("attack_id") or slug)] = cs
            tech_cves[slug] = cs                       # actors may reference either the id or the slug

    actor_cves: dict[str, set] = collections.defaultdict(set)
    for slug, a in actors.items():
        for f in source_fields:                        # direct fields on the actor page
            actor_cves[slug].update(_cve_ids(a.get(f)))
        for tid in (a.get("techniques") or []):        # technique-mediated
            actor_cves[slug].update(tech_cves.get(str(tid), []))

    fwd = {slug: sorted(cves) for slug, cves in actor_cves.items() if cves}
    rev: dict[str, set] = collections.defaultdict(set)
    for slug, cves in fwd.items():
        aid = str(actors[slug].get("id") or slug)      # canonical id for link_page {by: id}; else slug
        for c in cves:
            rev[c].add(aid)
    return fwd, {c: sorted(s) for c, s in rev.items()}


def _stamp(path: Path, field: str, value: list, dry_run: bool) -> bool:
    """SET frontmatter <field> = <value> on an existing page (idempotent). Returns True if it wrote."""
    fm, body = _split(path)
    if not fm:
        return False
    if fm.get(field) == value:
        return False                                   # idempotent
    fm[field] = value
    if dry_run:
        return True
    head = yaml.safe_dump(fm, sort_keys=False, allow_unicode=True).rstrip()
    try:
        path.write_text(f"---\n{head}\n---\n\n{body.strip()}\n", encoding="utf-8")
    except OSError as e:
        print(f"WARN: stamp {path}: {e}", file=sys.stderr)
        return False
    return True


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--vault", default=os.environ.get("WIKI_PATH", "/opt/vault"))
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)
    wiki = content_root(Path(args.vault))
    source_fields = [f.strip() for f in os.environ.get(
        "CVE_ACTOR_SOURCE_FIELDS", ",".join(_DEFAULT_SOURCE_FIELDS)).split(",") if f.strip()]

    actors, techs = _load(wiki)
    if not actors:
        print("cve-actor-edge: no actor pages — nothing to do")
        print(json.dumps({"wakeAgent": False}))
        return 0
    fwd, rev = compute_edges(actors, techs, source_fields)

    # forward: exploited_cve_ids on actor pages
    ent = wiki / "entities"
    actor_path = {p.stem: p for p in ent.rglob("*.md")} if ent.is_dir() else {}
    fstamped = 0
    for slug, cves in fwd.items():
        p = actor_path.get(slug)
        if p and _stamp(p, "exploited_cve_ids", cves, args.dry_run):
            fstamped += 1

    # reverse: exploiting_actors on EXISTING cve pages only (enrich-only)
    idx = _cve_index(wiki)
    rstamped = unmapped = 0
    for cid, slugs in rev.items():
        p = idx.get(cid)
        if p is None:
            unmapped += 1
            continue
        if _stamp(p, "exploiting_actors", slugs, args.dry_run):
            rstamped += 1

    print(f"cve-actor-edge: {fstamped} actor page(s) stamped exploited_cve_ids, "
          f"{rstamped} cve page(s) stamped exploiting_actors "
          f"({unmapped} CVE id(s) with no okcti page, skipped)"
          f"{' [dry-run]' if args.dry_run else ''}")
    print(json.dumps({"wakeAgent": False}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
