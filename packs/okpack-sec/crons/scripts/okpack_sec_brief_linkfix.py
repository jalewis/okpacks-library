#!/usr/bin/env python3
"""no_agent: normalize wikilinks in briefing pages to verified canonical paths (okpacks-library#42).

The daily brief is agent-written and guesses link paths (e.g. `intrusion-set/s/sapphire-sleet`)
that don't match the on-disk `entities/<letter>/<slug>` layout, and sometimes links pages that
don't exist. This deterministic pass resolves each `[[target|disp]]` against the vault — by exact
path, by slug, or by an entity's `mitre_id` / `cve_id` / name — and rewrites it to the real
canonical path. A target with no matching page is demoted to plain text, so a published brief
carries NO broken links. Idempotent; ZERO LLM tokens.

Usage: okpack_sec_brief_linkfix.py [--vault DIR] [--page P] [--dry-run]
Env: WIKI_PATH (default /opt/vault).
"""
from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path

try:
    import yaml
except Exception:  # pragma: no cover
    yaml = None

_WL = re.compile(r"\[\[([^|\]\n]+)(?:\|([^\]\n]*))?\]\]")
_FM = re.compile(r"\A---\s*\n(.*?\n)---\s*\n?", re.S)
_EXCLUDED_TOP = {"observations", "operational"}   # per-source / operator layers — never a link target


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", (s or "").lower()).strip("-")


def build_index(vault: str | os.PathLike) -> dict:
    """{lookup-key -> wiki-relative page path (no .md)} over linkable pages. Keys: page stem,
    and for entities also mitre_id / cve_id / normalized name. entities/ wins on collision so a
    multi-source slug resolves to the canonical, not a per-source observation copy."""
    wiki = Path(vault) / "wiki"
    idx: dict = {}

    def put(key: str, rel: str, prefer_entities: bool = False) -> None:
        key = (key or "").strip().lower()
        if not key:
            return
        if key not in idx or (prefer_entities and rel.startswith("entities/")):
            idx[key] = rel

    if not wiki.is_dir():
        return idx
    for p in wiki.rglob("*.md"):
        parts = p.relative_to(wiki).parts
        if parts[0] in _EXCLUDED_TOP or p.name.startswith(("_", ".")) or p.name.startswith("INDEX"):
            continue
        rel = p.relative_to(wiki).as_posix()[:-3]
        put(p.stem, rel, prefer_entities=True)
        if parts[0] == "entities" and yaml is not None:
            m = _FM.match(p.read_text(encoding="utf-8", errors="replace")[:2000])
            if not m:
                continue
            try:
                fm = yaml.safe_load(m.group(1)) or {}
            except yaml.YAMLError:
                continue
            if not isinstance(fm, dict):
                continue
            for f in ("mitre_id", "cve_id"):
                if fm.get(f):
                    put(str(fm[f]), rel)
            if fm.get("name"):
                put(_norm(str(fm["name"])), rel)
    return idx


def resolve(target: str, idx: dict, vault: str | os.PathLike) -> str | None:
    """Real wiki path for a wikilink target, or None if nothing matches."""
    t = target.strip()
    if (Path(vault) / "wiki" / (t + ".md")).is_file():
        return t                                   # exact path already valid
    seg = t.split("/")[-1].strip()
    for key in (seg.lower(), _norm(seg)):
        if key in idx:
            return idx[key]
    return None


def fix_text(text: str, idx: dict, vault: str | os.PathLike) -> tuple[str, int, int]:
    rewrote = dropped = 0

    def repl(m: "re.Match") -> str:
        nonlocal rewrote, dropped
        target = m.group(1).strip()
        disp = m.group(2) if m.group(2) is not None else target.split("/")[-1]
        if target.startswith("#"):                 # same-page anchor — leave it
            return m.group(0)
        r = resolve(target, idx, vault)
        if r is None:
            dropped += 1
            return disp                            # demote a dead link to plain text
        if r != target:
            rewrote += 1
        return f"[[{r}|{disp}]]"

    return _WL.sub(repl, text), rewrote, dropped


def fix_page(page: Path, idx: dict, vault, dry_run: bool = False) -> tuple[int, int]:
    txt = page.read_text(encoding="utf-8", errors="replace")
    new, rewrote, dropped = fix_text(txt, idx, vault)
    if new != txt and not dry_run:
        page.write_text(new, encoding="utf-8")
    return rewrote, dropped


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Normalize briefing wikilinks (no_agent).")
    ap.add_argument("--vault", default=os.environ.get("WIKI_PATH", "/opt/vault"))
    ap.add_argument("--page", help="a single page (else every wiki/briefings/*.md)")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)
    idx = build_index(args.vault)
    if args.page:
        pages = [Path(args.page)]
    else:
        bdir = Path(args.vault) / "wiki" / "briefings"
        pages = sorted(p for p in bdir.glob("*.md")
                       if not (p.name.startswith(("_", ".")) or p.name.startswith("INDEX")))
    total_rw = total_dr = 0
    for p in pages:
        rw, dr = fix_page(p, idx, args.vault, args.dry_run)
        total_rw += rw
        total_dr += dr
        if rw or dr:
            print(f"brief-linkfix: {p.name} — rewrote {rw}, demoted {dr} dead"
                  f"{' [dry-run]' if args.dry_run else ''}")
    print(f"brief-linkfix: {len(pages)} page(s), {total_rw} links rewritten, "
          f"{total_dr} dead links demoted to text")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
