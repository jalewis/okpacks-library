#!/usr/bin/env python3
"""okpack-threat-landscape — cross-report theme emergence (no_agent, ZERO LLM tokens).

The landscape analog of the actor pack's TTP-diffusion idea: count how many annual reports address
each THEME per year, and surface which themes are RISING or FADING across the field. When "AI security"
goes from 2 reports in 2023 to 20 in 2025, that's a measurable landscape shift — computed from the
`report_theme` + `year` frontmatter the ingest lane stamps, no model needed. Writes one `trend` page
per theme with a year-by-year count and a direction.

Env: WIKI_PATH (/opt/vault) · THEME_MIN_TOTAL (3 = skip themes with too few reports to trend)
Usage: theme_trends.py [--vault DIR] [--as-of YYYY-MM-DD] [--dry-run]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import date, datetime, timezone
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _okf_write import content_root, slug, write_page  # noqa: E402

_REPORTS_PER_YEAR = 12   # cap the per-year source list; a busy theme links its top N, notes "+K more"

# `report_theme` is agent-stamped free text (ai-security, ot-ics-security, …). A naive `.title()`
# mangles acronyms — "ai-security" -> "Ai Security", "ot-ics" -> "Ot Ics". Map each lowercase slug
# word to its display form (mixed-case initialisms like IoT/SaaS spelled out); anything not listed
# title-cases normally. Extend as the corpus surfaces new acronyms.
_ACRONYM = {
    "ai": "AI", "ml": "ML", "llm": "LLM", "genai": "GenAI", "ot": "OT", "ics": "ICS",
    "iot": "IoT", "iiot": "IIoT", "scada": "SCADA", "api": "API", "apis": "APIs",
    "cve": "CVE", "cves": "CVEs", "kev": "KEV", "apt": "APT", "ddos": "DDoS", "c2": "C2",
    "mfa": "MFA", "2fa": "2FA", "vpn": "VPN", "dns": "DNS", "tls": "TLS", "ssl": "SSL",
    "ioc": "IOC", "iocs": "IOCs", "ttp": "TTP", "ttps": "TTPs", "siem": "SIEM", "edr": "EDR",
    "xdr": "XDR", "mdr": "MDR", "soc": "SOC", "soar": "SOAR", "saas": "SaaS", "iaas": "IaaS",
    "paas": "PaaS", "pii": "PII", "gdpr": "GDPR", "cisa": "CISA", "nist": "NIST", "mitre": "MITRE",
    "raas": "RaaS", "bec": "BEC", "osint": "OSINT", "cti": "CTI", "sbom": "SBOM", "ztna": "ZTNA",
    "sase": "SASE", "waf": "WAF", "rce": "RCE", "xss": "XSS", "iam": "IAM", "pam": "PAM", "grc": "GRC",
}


def _titleize(theme: str) -> str:
    """Title-case a hyphenated theme slug while preserving acronyms/initialisms a naive `.title()`
    mangles: `ai-security` -> "AI Security", `ot-ics-security` -> "OT ICS Security" (not "Ai"/"Ot Ics")."""
    return " ".join(_ACRONYM.get(w, w.capitalize()) for w in theme.replace("-", " ").split())


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
        # exclude thin/synthetic reports (report_quality: thin) so a filler stub doesn't count equal
        # to a substantive report in the theme coverage trend (okengine#259 / ingest quality gate).
        if (isinstance(fm, dict) and fm.get("source_channel") == "annual-report"
                and fm.get("report_theme") and fm.get("report_quality") != "thin"):
            # yield the source's wiki key too, so the trend page can LINK the reports it counts
            # (else it names N sources with nothing to click, and the graph has no edge to it).
            published = str(fm.get("published") or "")[:10]
            precision = str(fm.get("published_precision") or "").lower()
            # Historic pages did not declare precision. A non-Jan-01 ISO date is safe to treat as
            # day-precise; Jan 1 plus only a `year` is the importer's year-only placeholder.
            try:
                pub_date = date.fromisoformat(published)
            except ValueError:
                pub_date = None
            precise = bool(pub_date and (precision in ("day", "date") or
                                         (not precision and published[5:] != "01-01")))
            yield (fm.get("report_theme"), str(fm.get("year") or published)[:4],
                   p.relative_to(vault).as_posix()[:-3], pub_date, precise)


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
    ap.add_argument("--as-of", default="", help="UTC date override for deterministic replay/tests")
    args = ap.parse_args(argv)
    vault = content_root(Path(args.vault))

    as_of = date.fromisoformat(args.as_of) if args.as_of else datetime.now(timezone.utc).date()
    themes: dict[str, dict] = {}
    for theme, year, key, pub_date, precise in _load_reports(vault):
        t = themes.setdefault(theme, {"by_year": {}, "reports": {}, "dated": {}})
        t["by_year"][year] = t["by_year"].get(year, 0) + 1
        t["reports"].setdefault(year, []).append(key)
        t["dated"].setdefault(year, []).append((pub_date, precise))

    if not themes:
        print("theme-trends: no themed annual-report sources yet — run annual_reports_import first")
        print(json.dumps({"wakeAgent": False}))
        return 0

    written = errs = 0
    for theme, tdata in themes.items():
        by_year, reports, dated = tdata["by_year"], tdata["reports"], tdata["dated"]
        total = sum(by_year.values())
        if total < args.min_total:
            continue
        yrs = sorted(y for y in by_year if y.isdigit())
        if not yrs:
            continue
        period = f"{yrs[0]}..{yrs[-1]}"
        prior_year = str(as_of.year - 1)
        current_year = str(as_of.year)
        comparable = all(dated.get(y) for y in (prior_year, current_year)) and \
                     all(precise and pub is not None
                         for y in (prior_year, current_year)
                         for pub, precise in dated.get(y, []))
        ytd = {y: sum(1 for pub, _ in dated.get(y, [])
                      if pub and (pub.month, pub.day) <= (as_of.month, as_of.day))
               for y in (prior_year, current_year)} if comparable else {}
        comparison = ("ytd" if comparable else
                      "partial-period" if current_year in by_year else
                      "full-period")
        direction = _direction(ytd if comparison == "ytd" else by_year)
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
        body = [f"# {_titleize(theme)} — landscape trend ({arrow})", "",
                f"Reports addressing **{theme}** across the tracked annual-report corpus, by year:", "",
                f"> {counts}  (total {total})", "",
                *report_lines, "",
                "> Computed no_agent from `report_theme` frequency across vendor reports — a coverage/"
                "attention signal (how much the field is publishing on this theme), not a threat-volume "
                "measurement.", ""]
        fm = {"type": "trend", "id": f"theme-{slug(theme)}", "title": f"{_titleize(theme)} reporting-volume trend",
              "period": period, "direction": direction, "report_theme": theme,
              "comparison": comparison,
              "count_by_year": {y: by_year[y] for y in yrs}, "updated": f"{yrs[-1]}-01-01"}
        if comparison == "ytd":
            fm["comparison_as_of"] = as_of.strftime("%m-%d")
            fm["count_ytd_by_year"] = ytd
        else:
            # Explicit nulls delete stale YTD fields when write_page merges with an older page.
            fm["comparison_as_of"] = None
            fm["count_ytd_by_year"] = None
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
