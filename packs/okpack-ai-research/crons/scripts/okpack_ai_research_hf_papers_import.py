#!/usr/bin/env python3
"""okpack-ai-research — Hugging Face daily-papers importer (no_agent, ZERO LLM tokens).

Seeds the vault with a BOUNDED, high-signal set of trending papers from Hugging Face's
`daily_papers` surface — the curated successor to Papers With Code (paperswithcode.com now
redirects there). Papers are upvote-curated, so this is a reference seed, not the arXiv firehose
(which stays in the RSS→agent lane). Deterministic JSON -> conformant `source`/paper pages.

Non-destructive: CREATE-if-absent only — an existing source page (agent-curated, or seeded on an
earlier run) is never overwritten. The upvote count is an import-time snapshot.

Usage: okpack_ai_research_hf_papers_import.py [--limit N] [--vault DIR] [--dry-run]
Env: WIKI_PATH (default /opt/vault), OKPACK_AI_RESEARCH_HF_PAPERS_LIMIT (default 60).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.parse
import urllib.request
from datetime import date, datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from okpack_run_report import record_run  # noqa: E402

HF_PAPERS_API ="https://huggingface.co/api/daily_papers"
_MAX_AUTHORS = 12       # bound frontmatter on large author lists
_MAX_TAGS = 6           # ai_keywords -> tags, capped
_STRICT = False         # set in main() from --strict / OKPACK_STRICT_IMPORT; when on, fetch/parse/
                        # write failures exit nonzero instead of best-effort skip (okpacks-library#16)


def kebab(s: str) -> str:
    s = re.sub(r"[^\w\s-]", "", (s or "").lower())
    return re.sub(r"[\s_]+", "-", s).strip("-") or "x"


def paper_records(raw: list) -> list[dict]:
    """Normalize HF daily_papers items -> source-page records. Skips entries with no arXiv id."""
    out = []
    for it in raw:
        if not isinstance(it, dict):
            continue
        p = it.get("paper") or {}
        arxiv = (p.get("id") or "").strip()
        title = (p.get("title") or it.get("title") or "").strip()
        if not arxiv or not title:
            continue
        published = (p.get("publishedAt") or it.get("publishedAt") or "")[:10]
        authors = [a.get("name", "").strip() for a in (p.get("authors") or [])
                   if isinstance(a, dict) and a.get("name")]
        kws = [kebab(k) for k in (p.get("ai_keywords") or []) if isinstance(k, str) and k.strip()]
        out.append({
            "arxiv": arxiv,
            "title": title,
            "published": published if re.match(r"\d{4}-\d{2}-\d{2}", published) else "",
            "authors": authors[:_MAX_AUTHORS],
            "summary": (p.get("summary") or it.get("summary") or "").strip(),
            "upvotes": int(p.get("upvotes") or 0),
            "keywords": kws[:_MAX_TAGS],
            "url": f"https://arxiv.org/abs/{arxiv}",
            "hf_url": f"https://huggingface.co/papers/{arxiv}",
        })
    return out


def source_slug(rec: dict) -> str:
    """Stable, readable slug keyed by the arXiv id (unique), e.g.
    'ledgeragent-structured-state-…-2606-20529'."""
    stem = kebab(rec["title"])[:56].strip("-") or "paper"
    return f"{stem}-{rec['arxiv'].replace('.', '-').lower()}"


def source_path(vault: Path, rec: dict, slug: str) -> Path:
    if rec["published"]:
        y, m = rec["published"][:4], rec["published"][5:7]
        return vault / "wiki" / "sources" / y / m / f"{slug}.md"
    return vault / "wiki" / "sources" / "undated" / f"{slug}.md"


def render_source(rec: dict, today: str) -> str:
    import yaml
    fm: dict = {"type": "source", "source_kind": "paper", "title": rec["title"]}
    if rec["published"]:
        fm["published"] = rec["published"]
    if rec["authors"]:
        fm["authors"] = rec["authors"]
    fm["arxiv_id"] = rec["arxiv"]
    fm["url"] = rec["url"]
    fm["hf_upvotes"] = rec["upvotes"]
    fm["raw"] = f"raw:ai/hf-daily-{rec['arxiv']}"
    fm["tags"] = sorted(set(rec["keywords"]) | {"hf-daily-papers"})
    fm["last_updated"] = today
    fm["version"] = 1
    head = yaml.safe_dump(fm, sort_keys=False, allow_unicode=True,
                          default_flow_style=False).rstrip("\n")
    summary = rec["summary"] or f"{rec['title']} — trending on Hugging Face Daily Papers."
    note = ("\n\n> Seeded no_agent from Hugging Face Daily Papers (upvote-curated; "
            f"okpacks-library#13). [HF page]({rec['hf_url']}). Upvotes are an import-time snapshot; "
            "the ingest agent maintains entity cross-links + analysis.")
    return f"---\n{head}\n---\n## Summary\n{summary}{note}\n"


def import_sources(raw: list, vault: Path, today: str, dry_run: bool = False) -> dict:
    counts = {"created": 0, "exists": 0, "total": 0}
    for rec in paper_records(raw):
        counts["total"] += 1
        p = source_path(vault, rec, source_slug(rec))
        if p.exists():                       # never clobber an agent-curated / earlier page
            counts["exists"] += 1
            continue
        try:
            if not dry_run:
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(render_source(rec, today), encoding="utf-8")
        except OSError:
            if _STRICT:
                raise
            counts["exists"] += 1
            continue
        counts["created"] += 1
    return counts


def fetch_papers(limit: int) -> list:
    q = urllib.parse.urlencode({"limit": max(1, min(limit, 500))})
    req = urllib.request.Request(f"{HF_PAPERS_API}?{q}",
                                 headers={"User-Agent": "okpack-ai-research-hf-papers-import"})
    with urllib.request.urlopen(req, timeout=120) as r:   # noqa: S310 (trusted huggingface.co host)  # nosec B310
        data = json.loads(r.read().decode("utf-8"))
    return data if isinstance(data, list) else []


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Seed `source`/paper pages from Hugging Face Daily Papers (no_agent).")
    ap.add_argument("--limit", type=int,
                    default=int(os.environ.get("OKPACK_AI_RESEARCH_HF_PAPERS_LIMIT") or 60))
    ap.add_argument("--vault", default=os.environ.get("WIKI_PATH", "/opt/vault"))
    ap.add_argument("--src", help="local JSON file of daily_papers items (testing; skips network)")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--strict", action="store_true",
                    help="exit nonzero on fetch/parse/write failure instead of best-effort skip "
                         "(also OKPACK_STRICT_IMPORT=1); default is best-effort for scheduled crons")
    args = ap.parse_args(argv)
    global _STRICT
    _STRICT = bool(args.strict or os.environ.get("OKPACK_STRICT_IMPORT"))
    _started = datetime.now(timezone.utc)
    try:
        raw = (json.loads(Path(args.src).read_text(encoding="utf-8")) if args.src
               else fetch_papers(args.limit))
    except Exception as e:  # noqa: BLE001 — best-effort by default; strict -> nonzero
        print(f"hf-papers-import: {'ERROR' if _STRICT else 'WARN'} could not load papers ({e})"
              f"{'' if _STRICT else ' — skipping this run'}", file=sys.stderr)
        record_run(args.vault, "hf-papers", _started, "failed" if _STRICT else "degraded",
                   error=str(e), dry_run=getattr(args, "dry_run", False))
        return 1 if _STRICT else 0
    today = date.today().isoformat()
    try:
        c = import_sources(raw, Path(args.vault), today, args.dry_run)
    except OSError as e:
        print(f"hf-papers-import: ERROR write failed ({e})", file=sys.stderr)
        record_run(args.vault, "hf-papers", _started, "failed",
                   error=str(e), dry_run=getattr(args, "dry_run", False))
        return 1
    print(f"hf-papers-import: {c['total']} HF daily papers (top-{args.limit}) — "
          f"created {c['created']} source pages, {c['exists']} already present"
          f"{' [dry-run]' if args.dry_run else ''}")
    record_run(args.vault, "hf-papers", _started, "success", counts=c, dry_run=args.dry_run)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
