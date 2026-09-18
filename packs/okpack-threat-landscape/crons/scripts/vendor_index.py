#!/usr/bin/env python3
"""okpack-threat-landscape — publisher coverage map (no_agent, ZERO LLM tokens).

Builds one `publisher` page per report publisher from the ingested annual reports: how many reports they
put out, across which themes and years, with links to each. The "who is saying what about what" map —
useful for spotting which firms own which parts of the conversation (e.g. a vendor that publishes only
ransomware reports vs one covering the whole field). Reads the `vendor` / `report_theme` / `year`
frontmatter the ingest lane stamps. MERGE-writes.

Env: WIKI_PATH (/opt/vault) · VENDOR_MIN_REPORTS (1)
Usage: vendor_index.py [--vault DIR] [--dry-run]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _okf_write import content_root, slug, write_page  # noqa: E402


def _load_reports(vault: Path):
    src = vault / "sources"
    if not src.exists():
        return
    for p in src.rglob("*.md"):
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
        # exclude thin/synthetic reports so a filler stub doesn't inflate a vendor's coverage count
        # (okengine#259 / ingest quality gate — consistent with theme_trends).
        if (isinstance(fm, dict) and fm.get("source_channel") == "annual-report"
                and fm.get("vendor") and fm.get("report_quality") != "thin"):
            yield fm


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--vault", default=os.environ.get("WIKI_PATH", "/opt/vault"))
    ap.add_argument("--min-reports", type=int, default=int(os.environ.get("VENDOR_MIN_REPORTS", "1")))
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)
    vault = content_root(Path(args.vault))

    vendors: dict[str, dict] = {}
    for fm in _load_reports(vault):
        v = str(fm["vendor"])
        rec = vendors.setdefault(v, {"reports": [], "themes": set(), "years": set()})
        rec["reports"].append((str(fm.get("title") or ""), slug(str(fm.get("title") or ""))))
        if fm.get("report_theme"):
            rec["themes"].add(fm["report_theme"])
        if fm.get("year"):
            rec["years"].add(str(fm["year"])[:4])

    if not vendors:
        print("vendor-index: no annual-report sources yet — run annual_reports_import first")
        print(json.dumps({"wakeAgent": False}))
        return 0

    written = errs = 0
    for vendor, rec in vendors.items():
        if len(rec["reports"]) < args.min_reports:
            continue
        themes = sorted(rec["themes"])
        years = sorted(rec["years"])
        body = [f"# {vendor}", "",
                f"Report publisher tracked in the landscape corpus: **{len(rec['reports'])} report(s)**"
                + (f", {years[0]}–{years[-1]}" if years else "")
                + (f". Themes: {', '.join(themes)}." if themes else "."), "",
                "## Reports", ""]
        for title, s in sorted(set(rec["reports"])):
            body.append(f"- [[{s}|{title}]]" if title else f"- [[{s}]]")
        fm = {"type": "publisher", "id": slug(vendor), "title": vendor,
              "report_count": len(rec["reports"]), "report_theme": themes or None,
              "years_active": years or None}
        try:
            write_page(vault, f"entities/{slug(vendor)}.md",
                       {k: v for k, v in fm.items() if v not in (None, "", [])},
                       "\n".join(body), dry_run=args.dry_run)
            written += 1
        except OSError as e:
            errs += 1
            print(f"WARN: {vendor}: {e}", file=sys.stderr)

    print(f"vendor-index: {len(vendors)} vendor(s) seen, {written} vendor page(s) written"
          f"{f', {errs} error(s)' if errs else ''}")
    print(json.dumps({"wakeAgent": False}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
