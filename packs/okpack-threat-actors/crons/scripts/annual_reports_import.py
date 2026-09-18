#!/usr/bin/env python3
"""okpack-threat-actors — annual security-report ingest (no_agent, ZERO LLM tokens for the import).

Full-TEXT ingest of the awesome-annual-security-reports corpus
(github.com/jacobdjwilson/awesome-annual-security-reports, MIT) — AI-converted markdown of annual
vendor reports (DBIR, M-Trends, ASD, threat-landscape…). Unlike APTnotes (metadata + link), this
seeds real report CONTENT the entity/trend/concept lanes can mine, and matches actor aliases in the
text -> [[actor]] links. THREAT categories only (keyword allowlist) — the market/workforce/survey
reports are landscape material better suited to a separate landscape/market pack.

SOURCE resolution:
  * ANNUAL_REPORTS_DIR set  -> read the LOCAL checkout (<dir>/Markdown Conversions/<year>/*.md). Fast,
    offline — an OPERATOR override for a machine that already has the repo.
  * unset (the pack default) -> fetch the Markdown Conversions from the PUBLIC GitHub repo (tree API
    + raw), so a fresh public install is self-contained. See docs/data-sources.md.

Bounded by default (recent years + a cap) so a fresh install doesn't ingest all ~888 at once; widen
via env. no_agent: the import + actor-linking are zero-token; the agent compile lanes spend later.

Env: WIKI_PATH · ANNUAL_REPORTS_DIR (local override) · ANNUAL_REPORTS_REPO (owner/repo) ·
     ANNUAL_REPORTS_YEARS (default 2024,2025,2026) · ANNUAL_REPORTS_LIMIT (default 80; 0=all) ·
     ANNUAL_REPORTS_MAXCHARS (40000 body cap) · ANNUAL_REPORTS_INCLUDE (threat keyword allowlist)
Usage: annual_reports_import.py [--vault DIR] [--dir LOCAL] [--years 2025,2026] [--limit N] [--dry-run]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _okf_write import content_root, clean, slug, write_page  # noqa: E402
from misp_galaxy_import import index_actors      # noqa: E402

REPO = os.environ.get("ANNUAL_REPORTS_REPO", "jacobdjwilson/awesome-annual-security-reports")
SUBDIR = "Markdown Conversions"
_DEFAULT_INCLUDE = ("threat,ransomware,breach,vulnerab,apt,adversary,intrusion,malware,incident,"
                    "espionage,extortion,ddos,phishing,exploit,attack,nation-state,landscape,m-trends,dbir")
MAXCHARS = int(os.environ.get("ANNUAL_REPORTS_MAXCHARS", "40000"))
MIN_ALIAS = 6


def _get(url: str, timeout: int = 60) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "okpack-threat-actors/annual-reports",
                                               "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310  # nosec B310 (fixed https upstream)
        return r.read()


def _list_local(root: Path, years: set) -> list:
    """(year, filename, text-loader) for local Markdown Conversions/<year>/*.md."""
    base = root / SUBDIR
    out = []
    for y in sorted(years):
        d = base / y
        if not d.is_dir():
            continue
        for p in sorted(d.glob("*.md")):
            out.append((y, p.name, (lambda pp=p: pp.read_text(encoding="utf-8", errors="ignore"))))
    return out


def _list_github(repo: str, years: set) -> list:
    tree = json.loads(_get(f"https://api.github.com/repos/{repo}/git/trees/HEAD?recursive=1"))
    raw = f"https://raw.githubusercontent.com/{repo}/HEAD"
    out = []
    for node in tree.get("tree", []):
        path = node.get("path", "")
        if node.get("type") != "blob" or not path.startswith(f"{SUBDIR}/") or not path.endswith(".md"):
            continue
        parts = path.split("/")
        if len(parts) >= 3 and parts[1] in years:
            url = f"{raw}/" + urllib.parse.quote(path)
            out.append((parts[1], parts[-1], (lambda u=url: _get(u).decode("utf-8", "ignore"))))
    return out


def _wanted(filename: str, include: list) -> bool:
    low = filename.lower()
    return any(k in low for k in include)


def _title(text: str, filename: str) -> str:
    for line in text.splitlines():
        if line.startswith("# "):
            return line[2:].strip()
    return filename.rsplit(".", 1)[0].replace("-", " ")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--vault", default=os.environ.get("WIKI_PATH", "/opt/vault"))
    ap.add_argument("--dir", default=os.environ.get("ANNUAL_REPORTS_DIR", ""))
    ap.add_argument("--years", default=os.environ.get("ANNUAL_REPORTS_YEARS", "2024,2025,2026"))
    ap.add_argument("--limit", type=int, default=int(os.environ.get("ANNUAL_REPORTS_LIMIT", "80")))
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)
    vault = content_root(Path(args.vault))
    years = {y.strip() for y in args.years.split(",") if y.strip()}
    include = [k.strip() for k in os.environ.get("ANNUAL_REPORTS_INCLUDE", _DEFAULT_INCLUDE).split(",") if k.strip()]

    try:
        if args.dir:
            items = _list_local(Path(args.dir).expanduser(), years)
            src = f"local:{args.dir}"
        else:
            items = _list_github(REPO, years)
            src = f"github:{REPO}"
    except Exception as e:                            # noqa: BLE001
        print(f"ERROR: could not list reports ({e})", file=sys.stderr)
        return 1

    items = [it for it in items if _wanted(it[1], include)]
    if args.limit:
        items = items[:args.limit]

    # actor alias matcher (word-boundary, len>=MIN_ALIAS) over report text
    idx = index_actors(vault)
    stems = {a: Path(r).stem for a, r in idx.items() if len(a) >= MIN_ALIAS}
    rx = re.compile(r"\b(" + "|".join(sorted(map(re.escape, stems), key=len, reverse=True)) + r")\b", re.I) \
        if stems else None

    written = linked = errs = 0
    for year, filename, load in items:
        try:
            text = load()
        except Exception as e:                        # noqa: BLE001
            errs += 1
            print(f"WARN: load {filename}: {e}", file=sys.stderr)
            continue
        title = _title(text, filename)
        vendor = filename.split("-", 1)[0]
        mentions = sorted({stems[m.lower()] for m in rx.findall(text[:MAXCHARS])}) if rx else []
        body = clean(text, cap=MAXCHARS)
        if mentions:
            body += "\n\n## Actors named in this report\n\n" + "\n".join(f"- [[{s}]]" for s in mentions)
            linked += 1
        fm = {"type": "source", "source_kind": "threat-report", "source_channel": "annual-report",
              "source_feed": vendor, "publisher": vendor, "title": title, "published": f"{year}-01-01",
              "url": f"https://github.com/{REPO}/blob/HEAD/" + urllib.parse.quote(f"{SUBDIR}/{year}/{filename}"),
              "sources": [vendor, "awesome-annual-security-reports"],
              "mentions_actors": mentions or None}
        rel_path = f"sources/{year}-01-01-{slug(title)}.md"
        try:
            write_page(vault, rel_path, {k: v for k, v in fm.items() if v not in (None, "", [])},
                       body, dry_run=args.dry_run)
            written += 1
        except OSError as e:
            errs += 1
            print(f"WARN: {rel_path}: {e}", file=sys.stderr)

    print(f"annual-reports: {written} threat report(s) from {src} -> sources/, {linked} actor-linked"
          f"{f', {errs} error(s)' if errs else ''}")
    print(json.dumps({"wakeAgent": False}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
