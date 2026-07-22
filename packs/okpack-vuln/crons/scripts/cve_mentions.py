#!/usr/bin/env python3
"""okpack-vuln — CVE "in the news" signal (no_agent, ZERO LLM tokens).

Answers "which CVEs are actually being talked about" — distinct from the static KEV catalog — by
counting how many source/briefing documents mention each CVE ID in prose or structured `cve`/`cves`
frontmatter. Each document contributes at most once per CVE. Does two things:
  1. STAMPS `report_mentions` (+ `recent_report_mentions`) onto each mentioned CVE page, so the cockpit
     Vulnerabilities tab can rank CVEs by reporting attention.
  2. Writes dashboards/top-cves-by-reporting.md — the top-N ranking.
MERGE-safe / idempotent (re-writes the two fields; body + other frontmatter preserved).

Env: WIKI_PATH (/opt/vault) · CVE_MENTIONS_RECENT_DAYS (120) · CVE_MENTIONS_TOP_N (25)
Usage: cve_mentions.py [--vault DIR] [--top-n N] [--dry-run]
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

_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_FM_RE = re.compile(r"\A---[ \t]*\n(.*?\n)---[ \t]*\n?(.*)\Z", re.S)
_SCAN_DIRS = ("sources", "briefings")


def _content_root(vault: Path) -> Path:
    # some deployments nest content under <vault>/wiki; prefer that when present (matches _okf_write)
    return vault / "wiki" if (vault / "wiki").is_dir() else vault


def _split(p: Path) -> tuple[dict, str]:
    try:
        txt = p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {}, ""  # page moved/deleted by a concurrent lane mid-scan
    m = _FM_RE.match(txt)
    if not m:
        return {}, ""
    try:
        fm = yaml.safe_load(m.group(1))
    except yaml.YAMLError:
        fm = None
    return (fm if isinstance(fm, dict) else {}), (m.group(2) or "")


def _cve_index(wiki: Path) -> dict:
    """CVE-ID (uppercase) -> page Path, over every cves/ page (kev_import writes them canonically)."""
    out: dict[str, Path] = {}
    d = wiki / "cves"
    if d.is_dir():
        for p in d.rglob("*.md"):
            if p.stem.startswith(("INDEX", "_")):
                continue
            fm, _ = _split(p)
            cid = str(fm.get("cve_id") or p.stem).upper()
            if cid.startswith("CVE-"):
                if cid in out and out[cid] != p:
                    raise ValueError(f"duplicate CVE identity {cid}: {out[cid]} and {p}")
                out[cid] = p
    return out


def _structured_cves(fm: dict) -> set[str]:
    """CVE IDs explicitly carried in source/briefing frontmatter."""
    found: set[str] = set()
    for field in ("cve", "cves"):
        value = fm.get(field)
        values = value if isinstance(value, list) else [value]
        for item in values:
            found.update(match.upper() for match in _CVE_RE.findall(str(item or "")))
    return found


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--vault", default=os.environ.get("WIKI_PATH", "/opt/vault"))
    ap.add_argument("--recent-days", type=int, default=int(os.environ.get("CVE_MENTIONS_RECENT_DAYS", "120")))
    ap.add_argument("--top-n", type=int, default=int(os.environ.get("CVE_MENTIONS_TOP_N", "25")))
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)
    wiki = _content_root(Path(args.vault))
    cutoff = (datetime.now(timezone.utc) - timedelta(days=args.recent_days)).strftime("%Y-%m-%d")

    # 1) tally: distinct DOCS mentioning each CVE (a doc that names a CVE 5× is one appearance)
    counts: dict[str, dict] = {}
    ndocs = 0
    for sub in _SCAN_DIRS:
        base = wiki / sub
        if not base.is_dir():
            continue
        for p in base.rglob("*.md"):
            if p.stem.startswith(("INDEX", "_")):
                continue
            fm, body = _split(p)
            if str(fm.get("status") or "").lower() == "tombstoned":
                continue    # a same-story duplicate merged into its winner — don't double-count it
            cves = {m.upper() for m in _CVE_RE.findall(body)} | _structured_cves(fm)
            if not cves:
                continue
            ndocs += 1
            pub = str(fm.get("published") or fm.get("date") or "")[:10]
            recent = bool(pub and pub >= cutoff)
            for cid in cves:
                rec = counts.setdefault(cid, {"total": 0, "recent": 0})
                rec["total"] += 1
                if recent:
                    rec["recent"] += 1

    if not counts:
        print("cve-mentions: no CVE IDs found in sources/briefings — run the ingest lanes first")
        print(json.dumps({"wakeAgent": False}))
        return 0

    try:
        idx = _cve_index(wiki)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    # 2) stamp report_mentions + recent_report_mentions onto each mentioned CVE page (merge in place)
    stamped = 0
    for cid, c in counts.items():
        p = idx.get(cid)
        if p is None:
            continue
        fm, body = _split(p)
        if fm.get("report_mentions") == c["total"] and fm.get("recent_report_mentions") == c["recent"]:
            continue                                    # idempotent: nothing changed
        fm["report_mentions"] = c["total"]
        fm["recent_report_mentions"] = c["recent"]
        if args.dry_run:
            stamped += 1
            continue
        head = yaml.safe_dump(fm, sort_keys=False, allow_unicode=True).rstrip()
        try:
            p.write_text(f"---\n{head}\n---\n\n{body.strip()}\n", encoding="utf-8")
            stamped += 1
        except OSError as e:
            print(f"WARN: stamp {p}: {e}", file=sys.stderr)

    # 3) top-N dashboard
    ranked = sorted(counts.items(), key=lambda kv: (kv[1]["total"], kv[1]["recent"]), reverse=True)
    top = ranked[:args.top_n]
    lines = [f"# Top {len(top)} CVEs by reporting", "",
             f"> Ranked by how many source/briefing documents mention the CVE ID in prose or "
             f"structured `cve`/`cves` frontmatter "
             f"(across {ndocs} reporting docs) — a 'what's in the news' view, distinct from the static "
             "KEV catalog. `recent` = mentioned in reporting published in the last "
             f"{args.recent_days} days. Regenerated `no_agent`.", "",
             "| # | CVE | Reports | Recent |", "|---:|---|---:|---:|"]
    for i, (cid, c) in enumerate(top, 1):
        link = f"[[cves/{idx[cid].stem}|{cid}]]" if cid in idx else cid
        lines.append(f"| {i} | {link} | {c['total']} | {c['recent']} |")
    lines += ["", f"_Generated {today}. See the **Vulnerabilities** tab for the live ranking._"]
    fm = {"type": "dashboard", "id": "top-cves-by-reporting",
          "title": "Top CVEs by reporting", "updated": today}
    dash = wiki / "dashboards" / "top-cves-by-reporting.md"
    if not args.dry_run:
        dash.parent.mkdir(parents=True, exist_ok=True)
        head = yaml.safe_dump(fm, sort_keys=False, allow_unicode=True).rstrip()
        try:
            dash.write_text(f"---\n{head}\n---\n\n" + "\n".join(lines) + "\n", encoding="utf-8")
        except OSError as e:
            print(f"ERROR: write dashboard: {e}", file=sys.stderr)
            return 1

    print(f"cve-mentions: {len(counts)} CVEs mentioned across {ndocs} docs, {stamped} stamped, "
          f"top {len(top)} -> dashboards/top-cves-by-reporting.md")
    print(json.dumps({"wakeAgent": False}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
