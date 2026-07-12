#!/usr/bin/env python3
"""okpack-threat-actors — actor NEWS recency (no_agent, ZERO LLM tokens).

`actor_activity.py` answers "who's in the REPORTS": it reads `mentions_actors`, a field only the
annual-report / APTnotes importers write — so its recency caps at the newest report (an annual report
dated YYYY-01-01). This lane answers "who's in the NEWS right now" by matching the actor roster's
names + aliases against the news firehose (`source_kind: news`), and stamps two fields the cockpit
"Recently active" board sorts on:
  - news_last_seen : the newest news date naming the actor (the recency sort key)
  - recent_news    : how many news items named it in the last NEWS_WINDOW_DAYS (activity volume)

These are DEDICATED fields (not the generic `last_seen`, which ingest also sets) so this lane is the
sole owner — no race with the report lane, and a page's ingest-set `last_seen` can't leak onto the
board. Deterministic name/alias match (word-boundary, case-insensitive), no model. MERGE-safe.

Matching is deliberately conservative to protect precision (these dates drive an analyst board):
  * a term must be >= 5 chars, OR >= 4 chars if it contains a digit (keeps APT29 / FIN7 / TA505);
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

# Single-word codename suffixes / generics that over-match when they stand alone. A MULTI-word alias
# containing one (e.g. "velvet tempest", "volt typhoon") is distinctive and kept — only the bare token
# is dropped. Vendor taxonomies: CrowdStrike animals, Microsoft weather, Mandiant/Secureworks generics.
_GENERIC = {
    "group", "team", "unknown", "gang", "crew", "actor", "apt", "the",
    "spider", "panda", "bear", "kitten", "tiger", "buffalo", "jackal", "ox", "lynx", "wolf",
    "chollima", "leopard", "crane", "hawk", "pig", "spindle",
    "tempest", "typhoon", "sleet", "storm", "blizzard", "cyclone", "sandstorm", "hail", "dust", "flood",
}

# Ordinary English words collide with incidental prose — a single-token "Cleaver" matched an HTTP/3
# CVE headline that has nothing to do with the APT. Drop a SINGLE-TOKEN term that is a common English
# word; multi-word ("Comment Crew") and digit-bearing (APT29) names are never touched, so a two-word
# actor whose bare token is here still matches on its full name. This loses purely-single-word
# common-word actors (e.g. "Silence") in exchange for precision — the right trade for an analyst board.
# Curated + dependency-free on purpose: the cron stager copies only *.py, so no dictionary file can be
# bundled; an operator extends this seed via the same field. Kept sorted for review.
_ENGLISH_COMMON = frozenset("""
access alert anchor anvil apex armor arrow attack aurora autumn avalanche azure beacon blaze breach
bridge bunker cascade cedar chimera chisel cipher citadel cleaver client cobalt cobra comet comment
condor cortex cosmos crimson current cypress dagger dragon drifter eagle eclipse ember equation exploit
fabric falcon ferret fortress frost fusion galaxy gateway ghost glitch golden granite griffin hacker
hammer harbor hidden hollow hornet hunter hydra ivory javelin keeper kraken lance laurel legacy locust
machete mantis marble matrix meteor mirage monsoon nebula needle nettle network nexus nomad onyx oracle
origin otter patch phantom pliers portal prism pulse quantum quartz quiver rampart ranger rapier raven
reaper relay remote report saber scarlet scorpion secure seeker sentinel serpent server shade shadow
shield signal silence silver socket specter spectre sphinx spring static stealth summer surge switch
target tempest thorn thread threat thunder titan tornado torrent tunnel typhoon update vault vector
venom victim violet viper voltage warden weasel willow winter wizard wrench zenith
""".split())

# Single-token BRAND / product / place proper nouns aren't English-dictionary words, so the list
# above misses them — but they light up in security news constantly (a "Cleaver" APT carried the
# alias "Alibaba", which matched an article about Alibaba's XQUIC library). No real actor is named a
# bare vendor name, so dropping these as single tokens is safe; a multi-word alias is still kept.
_BRAND_COMMON = frozenset("""
adobe akamai alibaba amazon android apple azure baidu chrome cisco citrix cloudflare crowdstrike dell
discord docker fastly fedora fireeye firefox fortinet github gitlab google huawei ibm intel juniper
kaspersky linkedin linux mandiant mcafee meta microsoft mozilla netflix nginx nvidia okta openai
oracle outlook paypal proton pulse rackspace reddit redhat safari samsung sharepoint slack snowflake
sonicwall splunk symantec telegram tencent tesla twitter ubuntu vmware whatsapp windows yahoo zoom
""".split())


def _split(p: Path) -> tuple[dict, str]:
    m = _FM.match(p.read_text(encoding="utf-8", errors="ignore"))
    if not m:
        return {}, ""
    try:
        fm = yaml.safe_load(m.group(1))
    except yaml.YAMLError:
        fm = None
    return (fm if isinstance(fm, dict) else {}), m.group(2)


def _terms_for(fm: dict) -> set:
    """Distinctive match terms from an actor's title + aliases (see module docstring for the rules)."""
    out = set()
    for nm in [fm.get("title")] + (fm.get("aliases") or []):
        s = str(nm or "").strip().lower()
        if not s:
            continue
        if " " not in s and (s in _GENERIC or s in _ENGLISH_COMMON or s in _BRAND_COMMON):
            continue                                     # bare codename suffix / English word / brand -> too broad
        if len(s) >= 5 or (len(s) >= 4 and any(c.isdigit() for c in s)):
            out.add(s)
    return out


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
            fm, _ = _split(p)
            if fm.get("type") != "actor":
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
    if not term2slug:
        print("actor-news-activity: no usable actor name/alias terms")
        print(json.dumps({"wakeAgent": False}))
        return 0
    master = re.compile(r"\b(" + "|".join(re.escape(t) for t in
                        sorted(term2slug, key=len, reverse=True)) + r")\b", re.I)

    # 2) scan the news firehose; per actor: newest news date + a windowed count + a sample headline
    today = datetime.now(timezone.utc).date()
    win_lo = (today - timedelta(days=window)).isoformat()
    look_lo = (today - timedelta(days=lookback)).isoformat()
    hits: dict[str, dict] = {}                        # slug -> {last, recent, sample}
    nnews = 0
    src = wiki / "sources"
    if src.is_dir():
        for p in src.rglob("*.md"):
            fm, body = _split(p)
            if fm.get("source_kind") != "news":
                continue
            pub = _pub_date(fm, p)
            if not pub or pub < look_lo:
                continue
            nnews += 1
            title = str(fm.get("title") or "")
            text = f"{title}\n{body[:1500]}"
            seen = {term2slug[m.group(1).lower()] for m in master.finditer(text)}
            for slug in seen:
                h = hits.setdefault(slug, {"last": "", "recent": 0, "sample": ""})
                if pub > h["last"]:
                    h["last"] = pub
                    h["sample"] = title[:70]
                if pub >= win_lo:
                    h["recent"] += 1

    if not hits:
        print(f"actor-news-activity: scanned {nnews} news sources, no actor names matched")
        print(json.dumps({"wakeAgent": False}))
        return 0

    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    ranked = sorted(hits.items(), key=lambda kv: (kv[1]["last"], kv[1]["recent"]), reverse=True)
    stamped = 0
    for slug, h in ranked:
        if slug not in idx:
            continue
        title, rel = idx[slug]
        stamp = {"type": "actor", "news_last_seen": h["last"], "recent_news": h["recent"],
                 "last_updated": now_iso}
        if args.dry_run:
            if stamped < 30:
                print(f"  {h['last']}  news={h['recent']:>2}  {str(title)[:26]:26}  ← {h['sample']}")
        else:
            _fm, body = _split(wiki / rel)
            try:
                write_page(wiki, rel, stamp, body, dry_run=False)
            except OSError as e:
                print(f"WARN: stamp {rel}: {e}", file=sys.stderr)
                continue
        stamped += 1

    print(f"actor-news-activity: {nnews} news sources scanned, {len(term2slug)} terms "
          f"({len(ambiguous)} dropped ambiguous), {len(hits)} actors matched "
          f"({'dry-run — nothing written' if args.dry_run else f'{stamped} stamped'})")
    print(json.dumps({"wakeAgent": False}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
