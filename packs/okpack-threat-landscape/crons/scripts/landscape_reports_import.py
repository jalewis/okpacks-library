#!/usr/bin/env python3
"""okpack-threat-landscape — annual security-report ingest (no_agent, ZERO LLM tokens for the import).

Full-TEXT ingest of the awesome-annual-security-reports corpus
(github.com/jacobdjwilson/awesome-annual-security-reports, MIT) — ALL categories (unlike the
threat-actors pack, which takes only the threat subset). Each report becomes a `source` page stamped
with an inferred `report_theme` + its `vendor`, so the landscape lanes (theme_trends, vendor_index) and
the agent trend/metric lanes have structured material. When composed with okpack-threat-actors, report
text is matched against actor aliases -> [[actor]] links (empty/no-op standalone).

SOURCE resolution:
  * ANNUAL_REPORTS_DIR set  -> read the LOCAL checkout (<dir>/Markdown Conversions/<year>/*.md). Operator
    override for a machine that already has the repo.
  * unset (pack default) -> fetch the Markdown Conversions from the PUBLIC GitHub repo. See docs/data-sources.md.

Env: WIKI_PATH · ANNUAL_REPORTS_DIR · ANNUAL_REPORTS_REPO · ANNUAL_REPORTS_YEARS (default 2024,2025,2026) ·
     ANNUAL_REPORTS_LIMIT (default 120; 0=all) · ANNUAL_REPORTS_MAXCHARS (40000) · ANNUAL_REPORTS_INCLUDE
     (default '' = all categories; set a comma keyword list to filter)
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
from itertools import zip_longest
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _okf_write import content_root, clean, slug, write_page  # noqa: E402

REPO = os.environ.get("ANNUAL_REPORTS_REPO", "jacobdjwilson/awesome-annual-security-reports")
SUBDIR = "Markdown Conversions"
MAXCHARS = int(os.environ.get("ANNUAL_REPORTS_MAXCHARS", "40000"))
MIN_ALIAS = 6

# filename/title keyword -> report_theme (first match wins; order = priority). Extensible via schema enum.
_THEME_RULES = [
    ("ransomware", "ransomware"), ("extortion", "ransomware"),
    ("data breach", "data-breach"), ("breach", "data-breach"),
    ("threat intel", "threat-intelligence"), ("threat-intel", "threat-intelligence"),
    ("threat landscape", "threat-intelligence"), ("threat report", "threat-intelligence"),
    ("vulnerab", "vulnerability-management"), ("patch", "vulnerability-management"),
    ("cloud", "cloud-security"), ("saas", "cloud-security"), ("container", "cloud-security"),
    ("identity", "identity-security"), ("non-human", "identity-security"), ("access", "identity-security"),
    ("supply chain", "supply-chain"), ("supply-chain", "supply-chain"), ("third-party", "supply-chain"),
    ("zero trust", "zero-trust"), ("zero-trust", "zero-trust"),
    ("ai ", "ai-security"), ("artificial intelligence", "ai-security"), ("agentic", "ai-security"), ("genai", "ai-security"),
    ("phishing", "phishing-social-engineering"), ("social engineering", "phishing-social-engineering"), ("fraud", "phishing-social-engineering"),
    ("ot ", "ot-ics-security"), ("ics", "ot-ics-security"), ("industrial", "ot-ics-security"),
    ("insider", "insider-threat"),
    ("ddos", "ddos"),
    ("api", "api-security"),
    ("incident response", "incident-response"), ("dfir", "incident-response"),
    ("nation-state", "nation-state"), ("apt", "nation-state"),
]


def _theme(text: str) -> str:
    low = text.lower()
    for kw, theme in _THEME_RULES:
        if kw in low:
            return theme
    return "threat-intelligence"          # generic landscape default


def _get(url: str, timeout: int = 60) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "okpack-threat-landscape/annual-reports",
                                               "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310  # nosec B310 (fixed https upstream)
        return r.read()


def _list_local(root: Path, years: set) -> list:
    base, out = root / SUBDIR, []
    for y in sorted(years):
        d = base / y
        if d.is_dir():
            for p in sorted(d.glob("*.md")):
                out.append((y, p.name, (lambda pp=p: pp.read_text(encoding="utf-8", errors="ignore"))))
    return out


def _list_github(repo: str, years: set) -> list:
    tree = json.loads(_get(f"https://api.github.com/repos/{repo}/git/trees/HEAD?recursive=1"))
    raw, out = f"https://raw.githubusercontent.com/{repo}/HEAD", []
    for node in tree.get("tree", []):
        path = node.get("path", "")
        if node.get("type") != "blob" or not path.startswith(f"{SUBDIR}/") or not path.endswith(".md"):
            continue
        parts = path.split("/")
        if len(parts) >= 3 and parts[1] in years:
            url = f"{raw}/" + urllib.parse.quote(path)
            out.append((parts[1], parts[-1], (lambda u=url: _get(u).decode("utf-8", "ignore"))))
    return out


def _index_actors(vault: Path) -> tuple:
    """Optional: actor alias -> page stem, over composed okpack-threat-actors pages (empty standalone)."""
    stems = {}
    ent = vault / "entities"
    if ent.exists():
        for p in ent.rglob("*.md"):
            txt = p.read_text(encoding="utf-8", errors="ignore")
            if not txt.startswith("---"):
                continue
            end = txt.find("\n---", 3)
            try:
                fm = yaml.safe_load(txt[3:end]) if end != -1 else None
            except yaml.YAMLError:
                fm = None
            if isinstance(fm, dict) and fm.get("type") == "actor":
                for a in [fm.get("title"), fm.get("id")] + list(fm.get("aliases") or []):
                    if a and len(str(a)) >= MIN_ALIAS:
                        stems[str(a).lower()] = p.stem
    rx = re.compile(r"\b(" + "|".join(sorted(map(re.escape, stems), key=len, reverse=True)) + r")\b", re.I) \
        if stems else None
    return rx, stems


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
    ap.add_argument("--limit", type=int, default=int(os.environ.get("ANNUAL_REPORTS_LIMIT", "120")))
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)
    vault = content_root(Path(args.vault))
    years = {y.strip() for y in args.years.split(",") if y.strip()}
    include = [k.strip() for k in os.environ.get("ANNUAL_REPORTS_INCLUDE", "").split(",") if k.strip()]

    try:
        items = _list_local(Path(args.dir).expanduser(), years) if args.dir else _list_github(REPO, years)
        src = f"local:{args.dir}" if args.dir else f"github:{REPO}"
    except Exception as e:                            # noqa: BLE001
        print(f"ERROR: could not list reports ({e})", file=sys.stderr)
        return 1

    if include:                                       # optional category filter (default: ALL categories)
        items = [it for it in items if any(k in it[1].lower() for k in include)]
    # interleave across years so a --limit cap gives BALANCED year coverage (theme_trends depends on it,
    # else taking all of year N before year N+1 makes every theme look like it's declining)
    by_year: dict = {}
    for it in items:
        by_year.setdefault(it[0], []).append(it)
    items = [it for grp in zip_longest(*by_year.values()) for it in grp if it is not None]
    if args.limit:
        items = items[:args.limit]

    rx, stems = _index_actors(vault)
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
        theme = _theme(f"{filename} {title}")
        body = clean(text, cap=MAXCHARS)
        mentions = sorted({stems[m.lower()] for m in rx.findall(text[:MAXCHARS])}) if rx else []
        if mentions:
            body += "\n\n## Actors named in this report\n\n" + "\n".join(f"- [[{s}]]" for s in mentions)
            linked += 1
        fm = {"type": "source", "source_kind": "annual-report", "source_channel": "annual-report",
              "source_feed": vendor, "publisher": vendor, "vendor": vendor, "title": title,
              "year": year, "report_theme": theme, "published": f"{year}-01-01",
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

    print(f"annual-reports: {written} report(s) from {src} -> sources/ (all categories, themed)"
          f"{f', {linked} actor-linked' if linked else ''}{f', {errs} error(s)' if errs else ''}")
    print(json.dumps({"wakeAgent": False}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
