#!/usr/bin/env python3
"""okpack-threat-actors — actor recent-activity signal (no_agent, ZERO LLM tokens).

Answers "who is active RIGHT NOW" — distinct from the static ATT&CK graph — from source pages that
carry `mentions_actors` + a `published` date. Does two things:
  1. STAMPS `recent_reports` + `total_mentions` onto each actor page, so the cockpit WATCHLIST can rank
     the actor roster by recent activity (the research front door).
  2. Writes dashboards/top-actors-by-activity.md — the top-N ranking.
MERGE-safe / idempotent.

Env: WIKI_PATH (/opt/vault) · ACTIVITY_RECENT_DAYS (1095 = ~3y) · ACTIVITY_TOP_N (25)
Usage: actor_activity.py [--vault DIR] [--top-n N] [--dry-run]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _okf_write import content_root, write_page  # noqa: E402


def _split(p: Path) -> tuple[dict, str]:
    txt = p.read_text(encoding="utf-8", errors="ignore")
    if not txt.startswith("---"):
        return {}, txt
    end = txt.find("\n---", 3)
    try:
        fm = yaml.safe_load(txt[3:end]) if end != -1 else None
    except yaml.YAMLError:
        fm = None
    body = txt[end + 4:].lstrip("\n") if end != -1 else txt
    return (fm if isinstance(fm, dict) else {}), body


def _actor_index(wiki: Path) -> dict:
    """slug -> (title, rel_path) for every type:actor page."""
    out = {}
    ent = wiki / "entities"
    if ent.exists():
        for p in ent.rglob("*.md"):
            fm, _ = _split(p)
            if fm.get("type") == "actor":
                out[p.stem] = (fm.get("title") or p.stem, str(p.relative_to(wiki)))
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--vault", default=os.environ.get("WIKI_PATH", "/opt/vault"))
    ap.add_argument("--recent-days", type=int, default=int(os.environ.get("ACTIVITY_RECENT_DAYS", "1095")))
    ap.add_argument("--top-n", type=int, default=int(os.environ.get("ACTIVITY_TOP_N", "25")))
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)
    wiki = content_root(Path(args.vault))

    cutoff = (datetime.now(timezone.utc) - timedelta(days=args.recent_days)).strftime("%Y-%m-%d")
    counts: dict[str, dict] = {}
    src = wiki / "sources"
    nsrc = 0
    if src.exists():
        for p in src.rglob("*.md"):
            fm, _ = _split(p)
            mentions = fm.get("mentions_actors") or []
            if not mentions:
                continue
            nsrc += 1
            pub = str(fm.get("published") or "")[:10]
            for a in mentions:
                rec = counts.setdefault(str(a), {"recent": 0, "total": 0})
                rec["total"] += 1
                if pub and pub >= cutoff:
                    rec["recent"] += 1

    if not counts:
        print("actor-activity: no source mentions_actors found — run the ingest lanes first")
        print(json.dumps({"wakeAgent": False}))
        return 0

    idx = _actor_index(wiki)
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    # 1) stamp recent_reports + total_mentions onto each actor page (feeds the cockpit watchlist ranking)
    stamped = 0
    for slug, c in counts.items():
        if slug not in idx:
            continue
        _title, rel = idx[slug]
        _fm, body = _split(wiki / rel)
        # activity_tier buckets the roster for the cockpit watchlist's tier matrix (a curated field,
        # distinct from the engine's DERIVED hot/warm/cold tier so we don't collide with it).
        atier = "hot" if c["recent"] >= 3 else "warm" if c["recent"] >= 1 else "cold"
        try:
            # last_updated: the cockpit watchlist's moved_field — write_page merges but does not
            # bump the envelope, and imported actor pages carry no `updated` at all, so without
            # this stamp the "Recently moved / Gone quiet" sections are permanently empty.
            write_page(wiki, rel, {"type": "actor", "recent_reports": c["recent"],
                                   "total_mentions": c["total"], "activity_tier": atier,
                                   "last_updated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")},
                       body, dry_run=args.dry_run)
            stamped += 1
        except OSError as e:
            print(f"WARN: stamp {rel}: {e}", file=sys.stderr)

    # 2) the top-N dashboard
    ranked = sorted(counts.items(), key=lambda kv: (kv[1]["recent"], kv[1]["total"]), reverse=True)
    top = ranked[:args.top_n]
    lines = [f"# Top {len(top)} threat actors by recent activity", "",
             f"> Ranked by mentions in reporting published in the last {args.recent_days // 365}y "
             f"(since {cutoff}), across {nsrc} source pages. A 'who's active now' view, distinct from the "
             "static ATT&CK graph. Regenerated `no_agent`.", "",
             "| # | Actor | Recent reports | Total mentions |", "|---:|---|---:|---:|"]
    for i, (slug, c) in enumerate(top, 1):
        name = idx.get(slug, (slug, ""))[0]
        lines.append(f"| {i} | [[{slug}|{name}]] | {c['recent']} | {c['total']} |")
    lines += ["", f"_Generated {today}. See the **Actor watchlist** for the full roster._"]
    fm = {"type": "dashboard", "id": "top-actors-by-activity", "title": "Top actors by recent activity",
          "updated": today}
    try:
        write_page(wiki, "dashboards/top-actors-by-activity.md", fm, "\n".join(lines), dry_run=args.dry_run)
    except OSError as e:
        print(f"ERROR: write dashboard: {e}", file=sys.stderr)
        return 1

    print(f"actor-activity: {len(counts)} actors ranked, {stamped} stamped, top {len(top)} "
          "-> dashboards/top-actors-by-activity.md")
    print(json.dumps({"wakeAgent": False}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
