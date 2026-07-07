#!/usr/bin/env python3
"""okpack-vuln — NVD / CVE enrichment (no_agent, ZERO LLM tokens).

Adds authoritative CVSS + CWE to `cve` pages from the NVD 2.0 API. Deliberately BOUNDED: it does
NOT bulk-import ~250k CVEs. Default scope = CVEs *modified in the last N days* (default 7). By
DEFAULT it is ENRICH-ONLY — it adds CVSS/CWE to pages that already exist (seeded by kev_import) and
creates NO new pages, keeping the vault's actively-exploited (KEV) focus. `--stub-new` opts into
creating pages for HIGH/CRITICAL CVEs in the window (`--all-severities` widens that to any severity).
Deterministic JSON -> markdown; no agent calls. MERGE-safe: never clobbers KEV/curated fields.

Set `NVD_API_KEY` for a real sync (NVD rate-limits hard: ~5 req/30s anon, 50 with a key).

License: NVD data is US-Gov public domain — pages stamp `sources: [NVD]`.

Env: WIKI_PATH (/opt/vault) · NVD_API_KEY · NVD_DAYS (default 7)
Usage: nvd_import.py [--days N] [--stub-new] [--all-severities] [--max-pages N] [--vault DIR] [--dry-run]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import okf_migrate  # engine cron lib, staged alongside pack scripts in /opt/data/scripts (okengine#54)

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_HIGH = {"HIGH", "CRITICAL"}
_ENRICHED = ("cvss_base", "cvss_version", "severity", "cwe")   # the fields THIS lane owns


def _content_root(v):
    # WIKI_PATH is the vault ROOT; content lives under wiki/ — match the engine's `WIKI = VAULT/"wiki"`.
    return Path(v) / "wiki"


def _load_fm(path: Path) -> dict:
    if not path.exists():
        return {}
    txt = path.read_text(encoding="utf-8", errors="ignore")
    if not txt.startswith("---"):
        return {}
    end = txt.find("\n---", 3)
    try:
        fm = yaml.safe_load(txt[3:end]) if end != -1 else None
    except yaml.YAMLError:
        fm = None
    return fm if isinstance(fm, dict) else {}


def _fetch_page(start: int, since: str, until: str, key: str | None) -> dict:
    qs = urllib.parse.urlencode({
        "lastModStartDate": since, "lastModEndDate": until,
        "resultsPerPage": 2000, "startIndex": start})
    req = urllib.request.Request(f"{NVD_API}?{qs}", headers={"User-Agent": "okpack-vuln/nvd_import"})
    if key:
        req.add_header("apiKey", key)
    with urllib.request.urlopen(req, timeout=90) as r:   # noqa: S310 (fixed https host)  # nosec B310 (fixed https upstream)
        return json.loads(r.read().decode("utf-8"))


def _cvss(metrics: dict) -> tuple[float | None, str | None, str | None]:
    """Best CVSS from the NVD metrics block: prefer v3.1 > v3.0 > v2."""
    for key, ver in (("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")):
        arr = metrics.get(key) or []
        if arr:
            data = arr[0].get("cvssData") or {}
            score = data.get("baseScore")
            sev = (data.get("baseSeverity") or arr[0].get("baseSeverity") or "").upper() or None
            return (float(score) if isinstance(score, (int, float)) else None), ver, sev
    return None, None, None


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--vault", default=os.environ.get("WIKI_PATH", "/opt/vault"))
    ap.add_argument("--days", type=int, default=int(os.environ.get("NVD_DAYS", "7")))
    ap.add_argument("--stub-new", action="store_true",
                    help="also CREATE pages for new HIGH/CRITICAL CVEs (default: enrich existing only)")
    ap.add_argument("--all-severities", action="store_true",
                    help="with --stub-new, stub every severity in the window, not just HIGH/CRITICAL")
    ap.add_argument("--max-pages", type=int, default=5, help="page cap (2000 CVEs/page) — the bound")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)
    vault = _content_root(args.vault)
    root = Path(args.vault)                # vault ROOT (WIKI_PATH); vault == root/"wiki"
    key = os.environ.get("NVD_API_KEY") or None

    now = datetime.now(timezone.utc)
    since = (now - timedelta(days=max(1, args.days))).strftime("%Y-%m-%dT%H:%M:%S.000")
    until = now.strftime("%Y-%m-%dT%H:%M:%S.000")

    enriched = stubbed = errs = 0
    start, total = 0, None
    pages = 0
    while pages < args.max_pages:
        try:
            resp = _fetch_page(start, since, until, key)
        except Exception as e:                           # noqa: BLE001 — best-effort lane
            print(f"WARN: NVD fetch (startIndex {start}): {e}", file=sys.stderr)
            errs += 1
            break
        total = resp.get("totalResults", 0) if total is None else total
        vulns = resp.get("vulnerabilities") or []
        if not vulns:
            break
        for item in vulns:
            cve = item.get("cve") or {}
            cid = (cve.get("id") or "").strip().upper()
            if not _CVE_RE.match(cid):
                continue
            base, ver, sev = _cvss(cve.get("metrics") or {})
            cwe = None
            for w in cve.get("weaknesses") or []:
                for d in w.get("description") or []:
                    if str(d.get("value", "")).startswith("CWE-"):
                        cwe = d["value"]
                        break
                if cwe:
                    break
            # locate the CVE wherever it lives (shard OR stale flat). The old flat-only probe
            # missed every already-sharded KEV page, silently skipping enrichment (okengine#54).
            prev_path = okf_migrate.find_page(root, "cves", cid)
            prev = _load_fm(prev_path) if prev_path else {}
            exists = bool(prev)
            if not exists:
                # ENRICH-ONLY by default — keep the vault KEV-curated. --stub-new opts into
                # creating pages, gated to HIGH/CRITICAL unless --all-severities.
                if not args.stub_new or not (args.all_severities or sev in _HIGH):
                    continue
            add = {"cvss_base": base, "cvss_version": ver, "severity": (sev or "").lower() or None,
                   "cwe": cwe}
            add = {k: v for k, v in add.items() if v not in (None, "", [])}
            if exists and all(prev.get(k) == v for k, v in add.items()):
                continue                                 # already current — idempotent, skip
            if args.dry_run:
                enriched += 1 if exists else 0
                stubbed += 0 if exists else 1
                continue
            desc = ""
            for d in cve.get("descriptions") or []:
                if d.get("lang") == "en":
                    desc = (d.get("value") or "").strip()
                    break
            fm = dict(prev) if exists else {
                "type": "cve", "id": cid, "cve_id": cid, "title": cid,
                "exploitation_status": "reported", "sources": ["NVD"],
                "url": f"https://nvd.nist.gov/vuln/detail/{cid}"}
            fm.update(add)                               # THIS lane owns the enrichment fields
            if not exists and "NVD" not in (fm.get("sources") or []):
                fm.setdefault("sources", []).append("NVD")
            fm = {k: v for k, v in fm.items() if v not in (None, "", [], {})}
            body = (f"# {cid}\n\n{desc}\n\n> Enriched no_agent from the NVD 2.0 API "
                    f"(CVSS {ver or '?'} base {base if base is not None else '?'}, "
                    f"{(sev or 'unrated').lower()}).").rstrip()
            # canonical shard the reshelve drain would choose; drop any stale copy elsewhere.
            dest = vault / (okf_migrate.canonical_key(root, "cves", cid, fm) + ".md")
            try:
                dest.parent.mkdir(parents=True, exist_ok=True)
                head = yaml.safe_dump(fm, sort_keys=False, allow_unicode=True).rstrip()
                dest.write_text(f"---\n{head}\n---\n\n{body}\n", encoding="utf-8")
                if prev_path and prev_path != dest:
                    prev_path.unlink()
                enriched += 1 if exists else 0
                stubbed += 0 if exists else 1
            except OSError as e:
                errs += 1
                print(f"WARN: write {cid}: {e}", file=sys.stderr)
        start += len(vulns)
        pages += 1
        if total is not None and start >= total:
            break
        if not key:
            time.sleep(6)                                # anon rate limit: ~5 req / 30s

    capped = (total is not None and start < total)
    print(f"nvd-import: {enriched} CVE(s) enriched, {stubbed} new HIGH/CRITICAL stub(s) "
          f"(window {args.days}d, {start}/{total if total is not None else '?'} scanned"
          f"{', CAPPED — raise --max-pages' if capped else ''})"
          f"{f', {errs} error(s)' if errs else ''}")
    print(json.dumps({"wakeAgent": False}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
