#!/usr/bin/env python3
"""okpack-threat-landscape — cross-report theme emergence (no_agent, ZERO LLM tokens).

The landscape analog of the actor pack's TTP-diffusion idea: count how many annual reports address
each THEME per year, and surface which themes are RISING or FADING across the field. When "AI security"
goes from 2 reports in 2023 to 20 in 2025, that's a measurable landscape shift — computed from the
`report_theme` + `year` frontmatter the ingest lane stamps, no model needed. Writes one `trend` page
per theme with a year-by-year count and a direction.

Env: WIKI_PATH (/opt/vault) · THEME_MIN_TOTAL (3 = skip themes with too few reports to trend)
Usage: theme_trends.py [--vault DIR] [--dry-run]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _okf_write import content_root, slug, write_page  # noqa: E402

_REPORTS_PER_YEAR = 12   # cap the per-year source list; a busy theme links its top N, notes "+K more"


def _load_reports(vault: Path):
    src = vault / "sources"
    if not src.exists():
        return
    for p in src.rglob("*.md"):
        txt = p.read_text(encoding="utf-8", errors="ignore")
        if not txt.startswith("---"):
            continue
        end = txt.find("\n---", 3)
        try:
            fm = yaml.safe_load(txt[3:end]) if end != -1 else None
        except yaml.YAMLError:
            fm = None
        if isinstance(fm, dict) and fm.get("source_channel") == "annual-report" and fm.get("report_theme"):
            # yield the source's wiki key too, so the trend page can LINK the reports it counts
            # (else it names N sources with nothing to click, and the graph has no edge to it).
            yield (fm.get("report_theme"), str(fm.get("year") or "")[:4],
                   p.relative_to(vault).as_posix()[:-3])


def _direction(by_year: dict) -> str:
    yrs = sorted(y for y in by_year if y.isdigit())
    if len(yrs) < 2:
        return "emerging" if yrs else "flat"
    prev, last = by_year[yrs[-2]], by_year[yrs[-1]]
    if last >= max(2, prev * 1.4):
        return "up"
    if last <= prev * 0.6:
        return "down"
    return "flat"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--vault", default=os.environ.get("WIKI_PATH", "/opt/vault"))
    ap.add_argument("--min-total", type=int, default=int(os.environ.get("THEME_MIN_TOTAL", "3")))
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)
    vault = content_root(Path(args.vault))

    themes: dict[str, dict] = {}
    for theme, year, key in _load_reports(vault):
        t = themes.setdefault(theme, {"by_year": {}, "reports": {}})
        t["by_year"][year] = t["by_year"].get(year, 0) + 1
        t["reports"].setdefault(year, []).append(key)

    if not themes:
        print("theme-trends: no themed annual-report sources yet — run annual_reports_import first")
        print(json.dumps({"wakeAgent": False}))
        return 0

    written = errs = 0
    for theme, tdata in themes.items():
        by_year, reports = tdata["by_year"], tdata["reports"]
        total = sum(by_year.values())
        if total < args.min_total:
            continue
        yrs = sorted(y for y in by_year if y.isdigit())
        if not yrs:
            continue
        period = f"{yrs[0]}..{yrs[-1]}"
        direction = _direction(by_year)
        counts = " · ".join(f"{y}: {by_year[y]}" for y in yrs)
        arrow = {"up": "▲ rising", "down": "▼ fading", "emerging": "◆ emerging", "flat": "→ steady"}[direction]
        # LINK the reports counted (grouped by year, capped) so the count is navigable evidence and
        # every cited source shows this trend in its backlinks — not a dead-end number.
        report_lines = ["## Reports", ""]
        for y in yrs:
            keys = reports.get(y, [])
            links = ", ".join(f"[[{k}]]" for k in keys[:_REPORTS_PER_YEAR])
            extra = f" _+{len(keys) - _REPORTS_PER_YEAR} more_" if len(keys) > _REPORTS_PER_YEAR else ""
            report_lines.append(f"- **{y}** ({len(keys)}) — {links}{extra}")
        body = [f"# {theme.replace('-', ' ').title()} — landscape trend ({arrow})", "",
                f"Reports addressing **{theme}** across the tracked annual-report corpus, by year:", "",
                f"> {counts}  (total {total})", "",
                *report_lines, "",
                "> Computed no_agent from `report_theme` frequency across vendor reports — a coverage/"
                "attention signal (how much the field is publishing on this theme), not a threat-volume "
                "measurement.", ""]
        fm = {"type": "trend", "id": f"theme-{slug(theme)}", "title": f"{theme.replace('-', ' ').title()} coverage trend",
              "period": period, "direction": direction, "report_theme": theme,
              "count_by_year": {y: by_year[y] for y in yrs}, "updated": f"{yrs[-1]}-01-01"}
        try:
            # trend_status: the cockpit watchlist buckets trends by it — unstamped themes all
            # land in "Needs status" and "Active trends" stays empty. This lane asserts the
            # themes it maintains are ACTIVE; an analyst (or a future lane) may set
            # reversed/dormant, which write_page MERGE-preserves on later runs.
            fm.setdefault("trend_status", "active")
            # last_thesis_update drives the cockpit "Recently updated" trends section. Stamp on
            # CREATE only (setdefault): a new theme IS a new thesis; a stats refresh is not — an
            # every-run stamp would make the section vacuous. Analysts/lanes bump it on real revisions.
            fm.setdefault("last_thesis_update", datetime.now(timezone.utc).strftime("%Y-%m-%d"))
            fm["last_updated"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            write_page(vault, f"trends/theme-{slug(theme)}.md", fm, "\n".join(body), dry_run=args.dry_run)
            written += 1
        except OSError as e:
            errs += 1
            print(f"WARN: {theme}: {e}", file=sys.stderr)

    print(f"theme-trends: {len(themes)} theme(s) seen, {written} trend page(s) written"
          f"{f', {errs} error(s)' if errs else ''}")
    print(json.dumps({"wakeAgent": False}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
