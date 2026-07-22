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
     ANNUAL_REPORTS_LIMIT (default 120 NEW reports/run; 0=all) · ANNUAL_REPORTS_MAXCHARS (40000) ·
     ANNUAL_REPORTS_INCLUDE (default '' = all categories; comma keyword list to filter) ·
     ANNUAL_REPORTS_REPROCESS (re-import already-ingested) · ANNUAL_REPORTS_KEEP_THIN (ingest thin
     reports flagged instead of filtering) · ANNUAL_REPORTS_MIN_WORDS (400) · ANNUAL_REPORTS_MIN_MARKERS (8)
Usage: annual_reports_import.py [--vault DIR] [--dir LOCAL] [--years 2025,2026] [--limit N]
                                [--reprocess] [--keep-thin] [--dry-run]
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
# Thin/synthetic gate: a report is "thin" only when BOTH short AND low-substance — the AI-filler
# profile (generic prose, round numbers, no named entities). A genuinely short report that still
# carries CVEs / URLs / named actors / specific decimal figures clears the bar, so real short reports
# aren't dropped. Both thresholds env-tunable; --keep-thin ingests them flagged instead of filtering.
MIN_WORDS = int(os.environ.get("ANNUAL_REPORTS_MIN_WORDS", "400"))
MIN_MARKERS = int(os.environ.get("ANNUAL_REPORTS_MIN_MARKERS", "8"))
_URL_RE = re.compile(r"https?://")
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{3,}\b", re.I)
_DECNUM_RE = re.compile(r"\b\d+\.\d+\b")            # specific (non-round) figures a real report cites
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
            try:
                txt = p.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue  # page moved/deleted by a concurrent lane mid-scan
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


def _quality(text: str, mentions: list) -> tuple[str, int, int]:
    """Deterministic quality label: 'thin' when a report is SHORT *and* LOW-SUBSTANCE (few URLs,
    CVEs, named actors, or specific decimal figures) — the synthetic/AI-filler profile that would
    otherwise count as equal to a substantive report in theme_trends / vendor_index. A short-but-
    substantive report (real CVEs/URLs/actors) is NOT thin. Returns (label, words, markers)."""
    sample = text[:MAXCHARS]
    words = len(sample.split())
    markers = (len(_URL_RE.findall(sample)) + len(_CVE_RE.findall(sample))
               + len(mentions) + len(_DECNUM_RE.findall(sample)))
    return ("thin" if (words < MIN_WORDS and markers < MIN_MARKERS) else "substantive"), words, markers


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--vault", default=os.environ.get("WIKI_PATH", "/opt/vault"))
    ap.add_argument("--dir", default=os.environ.get("ANNUAL_REPORTS_DIR", ""))
    ap.add_argument("--years", default=os.environ.get("ANNUAL_REPORTS_YEARS", "2024,2025,2026"))
    ap.add_argument("--limit", type=int, default=int(os.environ.get("ANNUAL_REPORTS_LIMIT", "120")),
                    help="max NEW (un-ingested) reports to import per run; 0=no cap. Already-ingested "
                         "reports are skipped and do NOT count against it (see --reprocess)")
    ap.add_argument("--reprocess", action="store_true",
                    help="re-import EVERY report even if its source page already exists (refresh "
                         "content / re-apply theme rules); also ANNUAL_REPORTS_REPROCESS=1. Default "
                         "skips already-ingested so the --limit budget lands NEWLY-added reports")
    ap.add_argument("--keep-thin", action="store_true",
                    help="ingest thin/synthetic reports too (flagged report_quality: thin) instead of "
                         "filtering them out of the corpus; also ANNUAL_REPORTS_KEEP_THIN=1")
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

    # Spend the --limit budget on UN-INGESTED reports rather than re-touching the same
    # alphabetically-first N every week: skip a report whose target source page already exists (keyed
    # on the write-target basename `<year>-01-01-<slug(title)>.md`, stable under the sources/ date
    # sharding). Without this, a newly-added report that sorts past the cap is never reached by the
    # weekly cron (it relied on a manual full `--limit 0` pass). `--reprocess` forces a full refresh
    # (upstream content update / theme-rule change). The read to derive the title is cheap; the
    # expensive per-report actor-alias regex below is what the skip avoids for already-ingested reports.
    reprocess = bool(args.reprocess or os.environ.get("ANNUAL_REPORTS_REPROCESS"))
    keep_thin = bool(args.keep_thin or os.environ.get("ANNUAL_REPORTS_KEEP_THIN"))
    done_names = set() if reprocess else {p.name for p in (vault / "sources").rglob("*.md")}

    rx, stems = _index_actors(vault)
    written = linked = errs = skipped = 0
    thin_skipped: list = []
    for year, filename, load in items:
        if args.limit and written >= args.limit:
            break                                     # this run's NEW-report budget is spent
        try:
            text = load()
        except Exception as e:                        # noqa: BLE001
            errs += 1
            print(f"WARN: load {filename}: {e}", file=sys.stderr)
            continue
        title = _title(text, filename)
        if not reprocess and f"{year}-01-01-{slug(title)}.md" in done_names:
            skipped += 1                              # already ingested — don't re-run the expensive
            continue                                  # actor-alias regex + rewrite
        vendor = filename.split("-", 1)[0]
        theme = _theme(f"{filename} {title}")
        body = clean(text, cap=MAXCHARS)
        mentions = sorted({stems[m.lower()] for m in rx.findall(text[:MAXCHARS])}) if rx else []
        quality, _words, _markers = _quality(text, mentions)
        if quality == "thin" and not keep_thin:
            thin_skipped.append(filename)             # filtered — a thin/synthetic report would
            continue                                  # otherwise count equal to a substantive one
        if mentions:
            body += "\n\n## Actors named in this report\n\n" + "\n".join(f"- [[{s}]]" for s in mentions)
            linked += 1
        fm = {"type": "source", "source_kind": "report", "source_channel": "annual-report",
              "source_feed": vendor, "publisher": vendor, "vendor": vendor, "title": title,
              "year": year, "report_theme": theme, "report_quality": quality,
              "published": f"{year}-01-01", "published_precision": "year",
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

    if thin_skipped:                                  # transparency: never silently drop — name them
        print(f"annual-reports: filtered {len(thin_skipped)} thin/synthetic report(s) "
              f"(<{MIN_WORDS}w & <{MIN_MARKERS} substance markers; --keep-thin to ingest flagged): "
              f"{', '.join(sorted(thin_skipped))}", file=sys.stderr)
    print(f"annual-reports: {written} NEW report(s) imported from {src} -> sources/ (all categories, "
          f"themed){f', {skipped} already-ingested skipped' if skipped else ''}"
          f"{f', {len(thin_skipped)} thin filtered' if thin_skipped else ''}"
          f"{f', {linked} actor-linked' if linked else ''}{f', {errs} error(s)' if errs else ''}")
    print(json.dumps({"wakeAgent": False}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
