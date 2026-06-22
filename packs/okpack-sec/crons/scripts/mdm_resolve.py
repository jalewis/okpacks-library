#!/usr/bin/env python3
"""Pack adapter for the engine's over-merge-guarded canonical resolver
(okengine#39 / okpacks-library#8).

The reference-data importers map each source's record onto a shared canonical by name/
alias match. Matching on a *single* shared alias OVER-MERGES when an alias token is reused
across vendors (ThaiCERT's Iranian "Iridium" folded into Sandworm because Microsoft calls
Sandworm "IRIDIUM"). The engine ships the structural fix — `entity_resolve.resolve` merges
only on a primary-name match or >=2 shared keys — and this module is the pack-side glue:
build the canonical index from the vault's `entities/` pages, and surface a declined
single-alias near-match to the review queue (G3 flag-not-gate) instead of silently dropping
or over-merging it.

`entity_resolve` is an engine cron lib; at runtime it sits beside the importers in
/opt/data/scripts/, so it imports as a sibling. The import is lazy so this module loads in
unit-test envs that add the engine scripts dir to sys.path on demand.
"""
from __future__ import annotations

import re
from datetime import date
from pathlib import Path

_FM = re.compile(r"^---\n(.*?)\n---\n", re.DOTALL)
REVIEW_QUEUE_REL = "wiki/_review-queue.md"


def _engine():
    """The engine's over-merge-guarded resolver (deployed sibling /opt/data/scripts/)."""
    import entity_resolve
    return entity_resolve


def build_canonical_index(vault, match_types):
    """An `entity_resolve.CanonicalIndex` over `wiki/entities/` pages whose `type` is in
    `match_types` (e.g. {'intrusion-set'} for actors). One pass; first-writer-wins on a
    primary-name collision, mirroring the prior alias index."""
    import yaml
    er = _engine()
    idx = er.CanonicalIndex()
    types = {str(t).strip() for t in match_types}
    ents = Path(vault) / "wiki" / "entities"
    if not ents.is_dir():
        return idx
    for p in ents.rglob("*.md"):
        if p.name.startswith(("_", ".")):
            continue
        try:
            m = _FM.match(p.read_text(encoding="utf-8", errors="replace"))
            fm = yaml.safe_load(m.group(1)) if m else None
        except (OSError, yaml.YAMLError):
            continue
        if not isinstance(fm, dict) or str(fm.get("type", "")).strip() not in types:
            continue
        idx.add(p.stem.lower(), fm.get("name") or p.stem, fm.get("aliases") or [])
    return idx


def load_trusted_coref(vault, source="microsoft"):
    """Cross-vendor co-reference seed (okengine#39, "seed later"): the Microsoft mapping is
    the authoritative cross-vendor alias backbone. For every `observations/<source>/` record,
    each of its names/aliases is vouched to refer to that record's canonical. Returns a set of
    `(normalized_token, canonical_slug)` pairs that let `resolve` trust a SINGLE shared alias
    when the mapping backs it — so genuine cross-vendor aliases (UNC3524->apt29) merge instead
    of minting duplicates, while unvouched lone aliases (Iridium->sandworm) still decline."""
    import yaml
    er = _engine()
    trusted: set[tuple[str, str]] = set()
    base = Path(vault) / "wiki" / "observations" / source
    if not base.is_dir():
        return trusted
    for p in base.rglob("*.md"):
        if p.name.startswith(("_", ".")):
            continue
        try:
            m = _FM.match(p.read_text(encoding="utf-8", errors="replace"))
            fm = yaml.safe_load(m.group(1)) if m else None
        except (OSError, yaml.YAMLError):
            continue
        if not isinstance(fm, dict):
            continue
        canon = str(fm.get("canonical") or "").strip().lower()
        if not canon:
            continue
        for tok in [fm.get("name") or ""] + list(fm.get("aliases") or []):
            k = er.normalize(tok)
            if k:
                trusted.add((k, canon))
    return trusted


def resolve(idx, name, aliases, trusted=None):
    """Delegate to the engine resolver. Returns its `Resolution` (slug/evidence/merged/
    ambiguous). `trusted` is the optional co-reference seed from load_trusted_coref."""
    return _engine().resolve(idx, name, aliases or [], trusted=trusted)


def flag_over_merge(vault, minted_slug, name, ambiguous, source, today=None):
    """Append a declined single-alias near-match to the review queue, matching the existing
    bullet style. Idempotent: the weekly importers re-run, so skip if an equivalent flag (same
    body, any date) is already queued — otherwise every run duplicates it. Best-effort: a write
    failure must never crash a no_agent importer."""
    today = today or date.today().isoformat()
    shared = ", ".join(ambiguous.shared) if getattr(ambiguous, "shared", None) else "?"
    body = (f"**entities/{minted_slug[0]}/{minted_slug}.md** — over-merge guard "
            f"(okengine#39): **{name}** ({source}) was NOT merged into "
            f"`{ambiguous.candidate}` despite sharing alias(es) [{shared}] — only a single "
            f"ambiguous alias matched (primary-name differs). Minted as a distinct canonical; "
            f"confirm they are genuinely different entities, or merge if not.")
    q = Path(vault) / REVIEW_QUEUE_REL
    try:
        existing = q.read_text(encoding="utf-8", errors="replace") if q.exists() else ""
        if body in existing:
            return                       # already flagged — don't duplicate on re-run
        if not existing:
            q.parent.mkdir(parents=True, exist_ok=True)
            q.write_text("---\ntitle: Review Queue\n---\n\n# Review Queue\n\n"
                         "Agent-flagged pages awaiting human review.\n\n", encoding="utf-8")
        with q.open("a", encoding="utf-8") as f:
            f.write(f"- {today} {body}\n")
    except OSError:
        pass
