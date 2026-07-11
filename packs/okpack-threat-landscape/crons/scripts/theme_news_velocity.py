#!/usr/bin/env python3
"""okpack-threat-landscape — per-theme NEWS velocity (no_agent, ZERO LLM tokens).

The FAST companion to theme_trends.py. That lane counts ANNUAL REPORTS per theme per YEAR — a slow
structural coverage metric that only moves when new vendor reports land (a few times a year), so a
WEEKLY brief built on it alone reads flat between report drops. This lane grafts a `news_velocity`
block onto each existing `trends/theme-*.md` page: the count of recent security-NEWS sources whose
text matches the theme, THIS rolling window vs the prior window, with a direction — the mid-week
signal a weekly brief needs. Deterministic keyword tally (word-boundary), no model.

Corpus: the deployment's recent security-news raw drop — a dir of `type: source` news pages with a
`published:` date + `title` (whatever ingest the operator runs; point `NEWS_CORPUS` at it). It
GRAFTS — reads each theme page and merges the `news_velocity:` frontmatter + a `## News velocity`
body section, PRESERVING theme_trends.py's annual-report `count_by_year` + Reports body untouched.
Idempotent; skips a theme with no page yet (theme_trends creates them first). Runs DAILY so the
signal tracks the news, not the weekly report cadence.

Env: WIKI_PATH (/opt/vault) · NEWS_WINDOW_DAYS (7) · NEWS_CORPUS (dir of recent news sources under
the vault root, e.g. a `raw/<feed>/` drop — set to your ingest's output path)
Usage: theme_news_velocity.py [--vault DIR] [--dry-run]
"""
from __future__ import annotations

import argparse
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _okf_write import content_root  # noqa: E402  staged beside this script at runtime

# Built-in keyword sets for the common CTI landscape themes (word-boundary matched, case-insensitive;
# `\bai\b` won't hit "email"). A theme with no entry here falls back to its de-slugified name, so the
# lane still works for a pack that tracks other themes.
_KEYWORDS: dict[str, list[str]] = {
    "ai-security": [r"\bai\b", "artificial intelligence", r"\bllm\b", "large language model",
                    "machine learning", "genai", "gen-ai", "chatgpt", "deepfake", "prompt injection",
                    "ai-powered", "ai-enabled", "ai model", r"\bagentic\b", "copilot"],
    "cloud-security": [r"\bcloud\b", r"\baws\b", "amazon web services", r"\bazure\b", r"\bgcp\b",
                       "google cloud", "s3 bucket", "kubernetes", r"\bcontainer\b", r"\bsaas\b",
                       "misconfigur", "serverless", r"\biam\b"],
    "identity-security": [r"\bidentity\b", "credential", "authentication", r"\bmfa\b", "multi-factor",
                          r"\bsso\b", "single sign-on", "account takeover", "session hijack", r"\bokta\b",
                          "active directory", r"\boauth\b", "passwordless", "session token"],
    "ot-ics-security": [r"\bics\b", "ot security", r"\bscada\b", "industrial control", "operational technology",
                        r"\bplc\b", "critical infrastructure", "manufacturing", r"\butilit", "energy grid",
                        "water treatment", r"\biiot\b"],
    "phishing-social-engineering": ["phishing", "social engineering", "spear-phish", r"\bbec\b",
                                    "business email compromise", "smishing", "vishing", "pretexting",
                                    "credential harvest", r"\blure\b"],
    "ransomware": ["ransomware", r"\bransom\b", "extortion", "encryptor", r"\braas\b", "double extortion",
                   "data leak site", "lockbit", "blackcat", r"\balphv\b", "cl0p", "akira"],
    "supply-chain": ["supply chain", "software supply", "third-party", "dependency confusion",
                     "npm package", r"\bpypi\b", r"\bnuget\b", r"\bsbom\b", "upstream compromise",
                     "malicious package", "typosquat"],
    "threat-intelligence": ["threat actor", r"\bapt\b", "nation-state", "threat group", r"\bttp\b",
                            r"\bioc\b", "indicator of compromise", r"\bmalware\b", "botnet",
                            r"\bc2\b", "command and control", "intrusion set", "adversary"],
    "vulnerability-management": ["vulnerability", r"\bcve\b", "zero-day", "0-day", r"\bexploit",
                                 r"\brce\b", "remote code execution", "privilege escalation", r"\bcvss\b",
                                 r"\bkev\b", "actively exploited", "patch tuesday", "buffer overflow"],
}

_FM = re.compile(r"^---\s*\n(.*?)\n---\s*\n(.*)", re.S)
_PUB = re.compile(r"^published:\s*['\"]?(\d{4}-\d{2}-\d{2})", re.M)
_TITLE = re.compile(r"^title:\s*(.+)$", re.M)
_MQ = re.compile(r"^matched_query:\s*(.+)$", re.M)


def _keywords_for(slug: str) -> list[str]:
    return _KEYWORDS.get(slug) or [re.escape(w) for w in slug.replace("-", " ").split() if len(w) > 2]


def _dir(this_c: int, prior_c: int) -> tuple[str, str]:
    """(display, word) — display carries an arrow for the body; word goes in frontmatter."""
    if prior_c == 0:
        return ("↑ new", "new") if this_c else ("· flat", "flat")
    r = this_c / prior_c
    if r >= 1.3:
        return "↑ rising", "rising"
    if r <= 0.77:
        return "↓ falling", "falling"
    return "· flat", "flat"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Per-theme news velocity onto trends/theme-*.md pages.")
    ap.add_argument("--vault", default=os.environ.get("WIKI_PATH", "/opt/vault"))
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)

    window = int(os.environ.get("NEWS_WINDOW_DAYS", "7"))
    vault = content_root(Path(args.vault))                     # <vault>/wiki
    corpus = Path(args.vault) / os.environ.get("NEWS_CORPUS", "raw")   # the raw-drop root; window+keyword filter the rest
    trends = vault / "trends"

    theme_pages = sorted(trends.glob("theme-*.md")) if trends.is_dir() else []
    if not theme_pages:
        print("theme-news-velocity: no trends/theme-*.md pages yet — run theme_trends.py first")
        return 0
    if not corpus.is_dir():
        print(f"theme-news-velocity: news corpus {corpus} not present — nothing to count")
        return 0

    # slug -> compiled keyword regexes, for the themes that actually have pages
    slugs = [p.name[len("theme-"):-len(".md")] for p in theme_pages]
    compiled = {s: [re.compile(k, re.I) for k in _keywords_for(s)] for s in slugs}

    today = datetime.now().date()
    this_lo = today - timedelta(days=window)
    prior_lo = today - timedelta(days=2 * window)

    tally = {s: [0, 0] for s in slugs}
    scanned = 0
    for p in corpus.rglob("*.md"):
        try:
            txt = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        m = _FM.match(txt)
        if not m:
            continue
        head, body = m.group(1), m.group(2)
        pm = _PUB.search(head)
        if not pm:
            continue
        try:
            pub = datetime.strptime(pm.group(1), "%Y-%m-%d").date()
        except ValueError:
            continue
        if pub < prior_lo:
            continue
        bucket = 0 if pub >= this_lo else 1
        scanned += 1
        title = (_TITLE.search(head).group(1) if _TITLE.search(head) else "")
        mq = (_MQ.search(head).group(1) if _MQ.search(head) else "")
        text = f"{title}\n{mq}\n{body[:1200]}"
        for s in slugs:
            if any(rx.search(text) for rx in compiled[s]):
                tally[s][bucket] += 1

    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    grafted = 0
    for p, s in zip(theme_pages, slugs):
        m = _FM.match(p.read_text(encoding="utf-8"))
        if not m:
            continue
        fm = yaml.safe_load(m.group(1)) or {}
        body = m.group(2)
        this_c, prior_c = tally[s]
        disp, word = _dir(this_c, prior_c)
        fm["news_velocity"] = {"window_days": window, "this": this_c, "prior": prior_c,
                               "per_day": round(this_c / window, 1), "direction": word,
                               "as_of": today.isoformat()}
        fm["last_updated"] = now_iso
        body = re.sub(r"\n## News velocity.*?(?=\n## |\Z)", "", body, flags=re.S).rstrip()
        block = (f"\n\n## News velocity ({window}d)\n\n{this_c} security-news sources this window vs "
                 f"{prior_c} prior — **{disp}** (~{this_c / window:.1f}/day). A fast NEWS-flow signal to "
                 f"complement the slower annual-report `count_by_year` above.\n")
        body = body.replace("\n## Reports", block + "\n## Reports", 1) if "\n## Reports" in body else body + block
        head = yaml.safe_dump(fm, sort_keys=False, default_flow_style=False, allow_unicode=True).rstrip()
        if args.dry_run:
            print(f"  [dry-run] theme-{s}: this={this_c} prior={prior_c} {word}")
        else:
            p.write_text(f"---\n{head}\n---\n{body}\n", encoding="utf-8")
        grafted += 1

    print(f"theme-news-velocity: {scanned} news sources in {2*window}d · grafted {grafted} theme page(s) "
          f"({'dry-run' if args.dry_run else 'written'})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
