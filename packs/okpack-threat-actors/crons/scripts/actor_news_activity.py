#!/usr/bin/env python3
"""okpack-threat-actors — actor NEWS recency (no_agent, ZERO LLM tokens).

`actor_activity.py` answers "who's in the REPORTS": it reads `mentions_actors`, a field only the
annual-report / APTnotes importers write — so its recency caps at the newest report (an annual report
dated YYYY-01-01). This lane answers "who's in the NEWS right now" by matching the actor roster's
names + aliases against the news firehose (`source_kind: news`), and stamps two fields the cockpit
"Recently active" board sorts on:
  - news_last_seen   : the newest news date naming the actor (the recency sort key)
  - recent_news      : how many news items named it in the last NEWS_WINDOW_DAYS (activity volume)
  - recent_news_refs : the matched articles behind that count (plain `sources/...` page refs,
                       newest-first, capped at 10 — the reader fact panel linkifies plain paths) —
                       provenance, so the board's number is visible evidence on the actor page
                       instead of a count that links nothing
  - news_total       : how many news items named it in the last NEWS_LOOKBACK_DAYS — the SAME
                       matcher over the longer window, so recent_news <= news_total always holds.
                       The boards used to set recent_news beside `total_mentions`, a different
                       lane's count of report pages tagged in `mentions_actors`; the two were not
                       comparable, and News > Total on about half the rows (okpacks-library#100).

These are DEDICATED fields (not the generic `last_seen`, which ingest also sets) so this lane is the
sole owner — no race with the report lane, and a page's ingest-set `last_seen` can't leak onto the
board. Deterministic name/alias match (word-boundary, case-insensitive), no model. MERGE-safe.

Matching is deliberately conservative to protect precision (these dates drive an analyst board):
  * short/common names require local actor, tracked-name or adversarial-action context;
  * a single-word generic codename suffix (spider / panda / tempest / typhoon / …) is dropped — the
    multi-word alias that contains it ("Velvet Tempest") is still kept and is distinctive;
  * a term shared by two different actors is dropped as ambiguous.
--dry-run writes nothing and prints exactly what WOULD be stamped, plus the matched headlines, so the
match quality can be eyeballed before it touches the vault.

Env: WIKI_PATH (/opt/vault) · NEWS_WINDOW_DAYS (30) · NEWS_LOOKBACK_DAYS (180 — bounds the news_last_seen scan)
Usage: actor_news_activity.py [--vault DIR] [--dry-run]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _okf_write import content_root, write_page  # noqa: E402

_FM = re.compile(r"^---\s*\n(.*?)\n---\s*\n(.*)", re.S)
_PATH_DATE = re.compile(r"/sources/(\d{4})/(\d{2})/(\d{2})/")
_ISO = re.compile(r"(\d{4}-\d{2}-\d{2})")

from actor_mentions import eligible, mentions, terms_for, _GENERIC_PHRASE

# Source kinds that are NOT reporting. Everything else in `sources/` counts, including a kind
# this list has never seen — the polarity matters. An include-list ("only source_kind == news")
# drops anything it does not recognise, silently, and that is exactly how this lane went blind:
# the corpus vocabulary shifted and the selection went to zero without a single error.
# Reference data is bulk-imported catalogue rows (thousands of them) and a paper is not news.
EXCLUDED_KINDS = frozenset(
    (os.environ.get("NEWS_EXCLUDED_KINDS") or "reference-data,paper").lower().split(",")
) - {""}


def _split(p: Path) -> tuple[dict, str]:
    try:
        txt = p.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return {}, ""  # page moved/deleted by a concurrent lane mid-scan
    m = _FM.match(txt)
    if not m:
        return {}, ""
    try:
        fm = yaml.safe_load(m.group(1))
    except yaml.YAMLError:
        fm = None
    return (fm if isinstance(fm, dict) else {}), m.group(2)


def _terms_for(fm: dict) -> set:
    return terms_for(fm)


def _pub_date(fm: dict, path: Path) -> str:
    """ISO published date, else recovered from the sources/YYYY/MM/DD/ path (published frontmatter is
    corrupt on a chunk of the synthetic corpus, but the write-time shard path is reliable)."""
    m = _ISO.match(str(fm.get("published") or ""))
    if m:
        return m.group(1)
    pm = _PATH_DATE.search(str(path))
    return f"{pm.group(1)}-{pm.group(2)}-{pm.group(3)}" if pm else ""


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Per-actor news recency onto the actor roster.")
    ap.add_argument("--vault", default=os.environ.get("WIKI_PATH", "/opt/vault"))
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)
    window = int(os.environ.get("NEWS_WINDOW_DAYS", "30"))
    lookback = int(os.environ.get("NEWS_LOOKBACK_DAYS", "180"))
    wiki = content_root(Path(args.vault))

    # 1) build the term -> actor-slug map (dropping ambiguous terms shared by >1 actor)
    idx: dict[str, tuple] = {}                       # slug -> (title, rel_path)
    term2slug: dict[str, str] = {}
    ambiguous: set = set()
    ent = wiki / "entities"
    if ent.is_dir():
        for p in ent.rglob("*.md"):
            fm, actor_body = _split(p)
            if not eligible(fm, actor_body, wiki):
                continue
            # A tombstoned actor is not a roster member. It was already skipped on the SOURCE
            # side; skipping it here too matters more, because a retired page left in the roster
            # keeps CONSUMING the firehose: its terms still match articles, it still gets stamped
            # with fresh activity, and a generic retired name ("Attacker") can shadow a real one
            # by making a shared term ambiguous — the retirement would silently degrade the
            # signal it was meant to clean up.
            if str(fm.get("status") or "").strip().lower() == "tombstoned":
                continue
            slug = p.stem
            idx[slug] = (fm.get("title") or slug, str(p.relative_to(wiki)))
            for t in _terms_for(fm):
                if t in term2slug and term2slug[t] != slug:
                    ambiguous.add(t)
                else:
                    term2slug[t] = slug
    for t in ambiguous:
        term2slug.pop(t, None)

    # 2) scan the news firehose; per actor: newest news date + a windowed count + a sample headline
    today = datetime.now(timezone.utc).date()
    win_lo = (today - timedelta(days=window)).isoformat()
    look_lo = (today - timedelta(days=lookback)).isoformat()
    hits: dict[str, dict] = {}                        # slug -> {last, recent, total, sample}
    nnews = 0
    ndated = 0                                        # dated sources in range, BEFORE kind filtering
    kinds_seen: dict[str, int] = {}
    src = wiki / "sources"
    if src.is_dir():
        for p in src.rglob("*.md"):
            if p.name == "INDEX.md" or p.name.startswith(("_", ".")):
                continue
            fm, body = _split(p)
            if not fm:
                print(f"ERROR: unreadable/unparseable source {p}; activity retained", file=sys.stderr)
                return 1
            if str(fm.get("status") or "").lower() == "tombstoned":
                continue    # a same-story duplicate merged into its winner — don't double-count it
            pub = _pub_date(fm, p)
            if not pub or pub < look_lo:
                continue
            ndated += 1
            kind = str(fm.get("source_kind") or "").strip().lower() or "(absent)"
            kinds_seen[kind] = kinds_seen.get(kind, 0) + 1
            # EXCLUDE, don't include. This used to select `source_kind == "news"`, one exact
            # token out of a vocabulary of thirteen — so `cyber-news`, `incident-report`,
            # `commentary` and `advisory` were never read, and the lane saw about 40% of the
            # firehose on its BEST day. Worse, an exact include-list fails silently the moment
            # the vocabulary shifts: it went to zero on 2026-07-28 and stayed there.
            # An unfamiliar kind is counted and reported, never dropped unseen.
            if kind in EXCLUDED_KINDS:
                continue
            nnews += 1
            title = str(fm.get("title") or "")
            text = f"{title}\n{body[:1500]}"
            seen = mentions(text, term2slug)
            for slug in seen:
                h = hits.setdefault(slug, {"last": "", "recent": 0, "total": 0, "sample": "",
                                           "refs": []})
                h["total"] += 1                       # every match inside the lookback
                if pub > h["last"]:
                    h["last"] = pub
                    h["sample"] = title[:70]
                if pub >= win_lo:
                    h["recent"] += 1
                    # provenance for the board's count — the matched article itself
                    h["refs"].append((pub, p.relative_to(wiki).as_posix()[:-3]))

    # An empty selection drawn from a NON-empty corpus is `unknown`, not `nothing happened`.
    # This lane printed "scanned 0 news sources, no actor names matched" and exited 0 every day
    # for three weeks while ~30 fresh sources a day landed beside it. Nothing was wrong with the
    # sources and nothing was wrong with the matching — the SELECTOR had stopped selecting, and
    # the only number that would have shown it (sources in range vs sources selected) was never
    # printed. Report the discrepancy loudly, and name the vocabulary actually on disk so the
    # next person sees the cause instead of re-deriving it.
    if ndated and not nnews:
        top = sorted(kinds_seen.items(), key=lambda kv: -kv[1])[:8]
        print(f"actor-news-activity: UNDETECTABLE — {ndated} dated source(s) in the last "
              f"{lookback}d but NONE survived kind filtering, so this run proves nothing about "
              f"actor activity. source_kind on disk: "
              + ", ".join(f"{k}={v}" for k, v in top)
              + f" | excluded: {sorted(EXCLUDED_KINDS)}", file=sys.stderr)
        print(json.dumps({"wakeAgent": False, "status": "undetectable",
                          "dated_sources": ndated, "selected": 0,
                          "kinds_seen": kinds_seen}))
        return 1

    matched_actors = len(hits)
    for slug in idx:
        hits.setdefault(slug, {"last": "", "recent": 0, "total": 0, "sample": "", "refs": []})

    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    ranked = sorted(hits.items(), key=lambda kv: (kv[1]["last"], kv[1]["recent"]), reverse=True)
    stamped = 0
    for slug, h in ranked:
        if slug not in idx:
            continue
        title, rel = idx[slug]
        # newest-first, capped — the articles BEHIND recent_news, so the count is clickable
        # evidence on the actor page instead of a number with no provenance. PLAIN paths, not
        # [[wikilinks]]: the reader's fact panel linkifies plain-path frontmatter refs
        # (_ref_target — the normalized fm-ref convention; brackets defeat it). Stamped even when
        # empty (recent_news_refs is NOT a _UNION_FIELDS member, so each run replaces wholesale
        # and refs age out with the window instead of accumulating).
        refs = [r for _, r in sorted(h["refs"], reverse=True)[:10]]
        stamp = {"news_last_seen": h["last"], "recent_news": h["recent"],
                 "news_total": h["total"], "recent_news_refs": refs, "last_updated": now_iso}
        if args.dry_run:
            if stamped < 30:
                print(f"  {h['last']}  news={h['recent']:>2}/{h['total']:<3} {str(title)[:26]:26}  "
                      f"← {h['sample']}")
        else:
            _fm, body = _split(wiki / rel)
            if not _fm or not eligible(_fm, body, wiki):
                # Unreadable (moved by a concurrent lane, a permission flip) or unparseable. write_page
                # REPLACES the body, so stamping with the empty body _split returns erased the page:
                # APT10 and APT41 on one live vault, 2026-10-01. A missed stamp heals next run.
                print(f"WARN: stamp {rel}: page unreadable or unparseable; not stamped", file=sys.stderr)
                continue
            try:
                write_page(wiki, rel, stamp, body, dry_run=False, require_actor=True)
            except OSError as e:
                print(f"WARN: stamp {rel}: {e}", file=sys.stderr)
                continue
        stamped += 1

    print(f"actor-news-activity: {nnews} news sources scanned of {ndated} dated source(s), {len(term2slug)} terms "
          f"({len(ambiguous)} dropped ambiguous), {matched_actors} actors matched, {len(hits)} actors recomputed "
          f"({'dry-run — nothing written' if args.dry_run else f'{stamped} stamped'})")
    print(json.dumps({"wakeAgent": False}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
