#!/usr/bin/env python3
"""source_url_reconcile.py — deterministic url repair: raw feed metadata is the truth.

The feed-fetch lanes store each raw item with the feed's REAL url; the ingest agent then
writes the source page and RETYPES the url — and models mutate retyped URLs (~20% observed
live on okcti: 2026-07 for 2026/07, 'sev-' for 'seo-', invented path segments, even a
space inside a URL). A fabricated url makes the brief's original-article link a dead end.

This drain re-joins pages to raw items by EXACT normalized title and overwrites the page's
url with the raw url when they differ (surgical line edit — no frontmatter re-dump).
Ambiguous titles (two raw items, different urls) are skipped and reported. Pages older
than the raw rolling window are untouched. Deterministic, no_agent, idempotent.

Env:
  WIKI_PATH   vault root (default /opt/vault); raw/ lives at the vault root.
"""
from __future__ import annotations

import json
import os
import re
import sys
import unicodedata
from pathlib import Path

import yaml

FM = re.compile(r"\A---\s*\n(.*?\n)---", re.S)


def norm(t: str) -> str:
    t = unicodedata.normalize("NFKD", t)
    return re.sub(r"[^a-z0-9]+", " ", t.lower()).strip()


def _fm(p: Path):
    try:
        txt = p.read_text(errors="replace")
    except OSError:
        return None  # page moved/deleted by a concurrent lane mid-scan
    m = FM.match(txt)
    if not m:
        return None
    try:
        return yaml.safe_load(m.group(1)) or {}
    except yaml.YAMLError:
        return None


def main() -> int:
    vault = Path(os.environ.get("WIKI_PATH", "/opt/vault"))
    wiki = vault / "wiki"
    raw = vault / "raw"
    if not raw.is_dir() or not (wiki / "sources").is_dir():
        print("url-reconcile: no raw/ or sources/ — nothing to do")
        print(json.dumps({"wakeAgent": False}))
        return 0

    raw_by_title: dict[str, str] = {}
    dup: set[str] = set()
    for p in raw.rglob("*.md"):
        fm = _fm(p)
        if not fm:
            continue
        t, u = norm(str(fm.get("title") or "")), str(fm.get("url") or "").strip()
        if not t or not u.startswith("http"):
            continue
        if t in raw_by_title and raw_by_title[t] != u:
            dup.add(t)
            continue
        raw_by_title[t] = u

    def toks(s: str) -> frozenset:
        return frozenset(norm(s).split())

    raw_toks = [(toks(k), k) for k in raw_by_title]      # for the fuzzy fallback

    def fuzzy_match(title_n: str):
        """Unique high-overlap raw title for a page whose title the agent MANGLED (slugified,
        words dropped) — exact join fails but the tokens still identify the story. Conservative:
        best Jaccard >= 0.6, clear winner (second best trails by > 0.15), else no match."""
        pt = frozenset(title_n.split())
        if not pt:
            return None
        scored = []
        for rt, key in raw_toks:
            u = len(pt | rt)
            if u:
                scored.append((len(pt & rt) / u, key))
        scored.sort(reverse=True)
        if scored and scored[0][0] >= 0.6 and (len(scored) == 1 or scored[0][0] - scored[1][0] > 0.15):
            return scored[0][1]
        return None

    fixed = agreed = retitled = 0
    fixes: list[str] = []
    for p in (wiki / "sources").rglob("*.md"):
        if p.name.startswith(("INDEX", "_")):
            continue
        try:
            txt = p.read_text(errors="replace")
        except OSError:
            continue  # page moved/deleted by a concurrent lane mid-scan
        m = FM.match(txt)
        fm = _fm(p)
        if not (m and fm):
            continue
        t = norm(str(fm.get("title") or fm.get("name") or ""))
        if not t or t in dup:
            continue
        real = raw_by_title.get(t)
        raw_title_key = t if real else fuzzy_match(t)
        if not real and raw_title_key:
            real = raw_by_title[raw_title_key]
        if not real:
            continue
        cur = str(fm.get("url") or "").strip()
        if cur == real:
            agreed += 1
            continue
        if re.search(r"^url:", m.group(1), re.M):
            txt = re.sub(r"^url:.*$", f"url: {real}", txt, count=1, flags=re.M)
        else:
            txt = re.sub(r"\A(---\s*\n)", rf"\1url: {real}\n", txt, count=1)
        # a fuzzy join means the page TITLE is the mangled retype — heal it from feed truth too
        if raw_title_key and raw_title_key != t:
            orig_title = next((k for k in raw_by_title if k == raw_title_key), None)
            # recover the raw item's display title by re-reading it (index stores normalized keys)
            for rp in raw.rglob("*.md"):
                rfm = _fm(rp)
                if rfm and norm(str(rfm.get("title") or "")) == raw_title_key:
                    disp = str(rfm.get("title") or "").strip()
                    if disp and re.search(r"^title:", txt, re.M):
                        # lambda: json.dumps may emit \uXXXX which re.sub would parse as a (bad) template escape
                        txt = re.sub(r"^title:.*$", lambda _m: "title: " + json.dumps(disp), txt, count=1, flags=re.M)
                        retitled += 1
                    break
        p.write_text(txt, encoding="utf-8")
        fixed += 1
        fixes.append(f"  {p.relative_to(wiki)}: -> {real}")

    print(f"url-reconcile: {len(raw_by_title)} raw items · {agreed} pages already correct · "
          f"{fixed} FIXED ({retitled} titles healed) · {len(dup)} ambiguous title(s) skipped")
    for line in fixes[:20]:
        print(line)
    print(json.dumps({"wakeAgent": False}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
