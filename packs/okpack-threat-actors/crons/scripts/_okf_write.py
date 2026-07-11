#!/usr/bin/env python3
"""Shared OKF page-write helpers for the okpack-threat-actors no_agent importers.

Co-located with the importer scripts (staged together into /opt/data/scripts by
deploy-cron-scripts.sh), so `from _okf_write import ...` resolves at runtime — the same
pattern the other packs use for their shared cron libs. stdlib + PyYAML only.

The importers are AUTHORITATIVE for the fields THEY source (attack_id, aliases, tactic,
the relationship link block) but must NOT clobber fields OWNED BY OTHER LANES —
`attribution_confidence` (entity-backfill), `related_actors` (actor_correlation),
`needs_review`, curated `tags`. `write_page` therefore MERGES: it preserves every existing
frontmatter key, overlays the importer's fields, and UNIONS list fields like aliases/tags.
"""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path

import yaml

# okf_migrate is the engine cron lib, staged alongside pack scripts in /opt/data/scripts. Import it
# DEFENSIVELY: if it isn't on the path (e.g. a pack-only test env, or a deploy that staged pack
# scripts but not engine scripts), write_page falls back to its legacy flat behavior rather than
# crashing every importer (okengine#54).
try:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import okf_migrate
except Exception:  # noqa: BLE001
    okf_migrate = None

_SLUG = re.compile(r"[^a-z0-9]+")
# list-valued fields that should be UNIONED (not replaced) on re-import, so enrichment survives
_UNION_FIELDS = frozenset({"aliases", "tags", "related", "sources", "platforms"})
# fields an importer must never overwrite if another lane already set them. (related_actors is NOT
# here: no importer emits it, so it's preserved automatically; and the correlation lane must REPLACE
# it wholesale each run — a fresh computation, not an ever-growing union.)
_PRESERVE_IF_SET = frozenset({"attribution_confidence", "needs_review", "confidence"})


def slug(s: str) -> str:
    return _SLUG.sub("-", (s or "").lower()).strip("-")[:80] or "untitled"


def clean(text: str, cap: int = 4000) -> str:
    t = re.sub(r"<[^>]+>", "", text or "").strip()
    return re.sub(r"[ \t]+\n", "\n", t)[:cap]


def _split_frontmatter(md: str) -> tuple[dict, str]:
    """Return (frontmatter dict, body) from an existing page; ({}, whole) if none."""
    if md.startswith("---"):
        end = md.find("\n---", 3)
        if end != -1:
            try:
                fm = yaml.safe_load(md[3:end]) or {}
            except yaml.YAMLError:
                fm = {}
            body = md[end + 4:].lstrip("\n")
            return (fm if isinstance(fm, dict) else {}), body
    return {}, md


def _merge_fm(existing: dict, incoming: dict) -> dict:
    """existing (on disk) UNDER incoming (importer), preserving other-lane fields + unioning lists."""
    out = dict(existing)
    for k, v in incoming.items():
        if k in _PRESERVE_IF_SET and existing.get(k) not in (None, "", []):
            continue                                   # another lane owns it — leave it
        if k in _UNION_FIELDS and isinstance(v, list):
            seen, merged = set(), []
            for item in (existing.get(k) or []) + v:   # preserve existing order, append new
                key = str(item).lower()
                if key not in seen:
                    seen.add(key)
                    merged.append(item)
            out[k] = merged
        else:
            out[k] = v
    return out


def write_page(vault: Path, rel_path: str, fm: dict, body: str, *, dry_run: bool = False) -> str:
    """Create-or-MERGE an OKF page. Returns 'created' | 'updated' | 'dry'. Frontmatter keys with
    empty/None values are dropped. `body` replaces the importer-owned body section wholesale.

    Partitioned namespaces are routed to the canonical shard the reshelve drain would choose, and
    merged against any existing copy WHEREVER it sits (the flat root OR a wrong-shaped shard), so a
    partition-unaware rel_path can't create a duplicate the drain then re-shards (okengine#54). Flat
    namespaces keep rel_path verbatim; if the engine lib is unavailable, so does everything."""
    rel = rel_path[:-3] if rel_path.endswith(".md") else rel_path
    existing = None
    if okf_migrate is not None:
        ns, slug_ = rel.split("/", 1)[0], rel.rsplit("/", 1)[-1]
        root = vault.parent                       # vault == WIKI_PATH/wiki; okf_migrate wants root
        if okf_migrate.is_partitioned(root, ns):
            existing = okf_migrate.find_page(root, ns, slug_)
            rel = okf_migrate.canonical_key(root, ns, slug_, fm)
    path = vault / (rel + ".md")
    src = existing if (existing and existing.exists()) else (path if path.exists() else None)
    action = "updated" if src is not None else "created"
    if src is not None:
        prev_fm, _ = _split_frontmatter(src.read_text(encoding="utf-8"))
        fm = _merge_fm(prev_fm, fm)
    fm = {k: v for k, v in fm.items() if v not in (None, "", [], {})}
    if dry_run:
        return "dry"
    head = yaml.safe_dump(fm, sort_keys=False, allow_unicode=True, default_flow_style=False).rstrip()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"---\n{head}\n---\n\n{body.rstrip()}\n", encoding="utf-8")
    if existing and existing.resolve() != path.resolve():   # collapse a stale flat/wrong-shard copy
        try:
            existing.unlink()
        except OSError:
            pass
    return action


def content_root(vault) -> "Path":
    """The OKF content root = <vault>/wiki. `WIKI_PATH` holds the VAULT ROOT (a misnomer); every engine
    component derives `WIKI = VAULT / "wiki"` (write_server.py:69, build_index_tree.py:36,
    backlinks_refresh.py:49), so match it EXACTLY — always append wiki/. Callers pass the vault root
    (== WIKI_PATH), NEVER the wiki dir. write_page creates wiki/ if absent (writer lanes); reader
    helpers see it empty (they guard on .exists())."""
    return Path(vault) / "wiki"
