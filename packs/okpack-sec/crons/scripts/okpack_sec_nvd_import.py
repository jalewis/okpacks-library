#!/usr/bin/env python3
"""okpack-sec — NVD / CVE importer, BOUNDED by default (no_agent, ZERO LLM tokens).

Enriches `vulnerability` pages with authoritative CVSS + CWE from the NVD API 2.0.
Deliberately bounded: it does NOT bulk-import ~250k CVEs. Default scope = CVEs
*modified in the last N days* (default 7); within that window it ENRICHES pages
that already exist (from feeds / KEV) and only STUBS new ones that are HIGH/CRITICAL
(so noise doesn't flood the vault). Deterministic JSON -> markdown: no agent calls.

Full / wider sync is opt-in (`--days`, `--all-severities`) and should use an
`NVD_API_KEY` (NVD rate-limits hard: ~5 req/30s anon, 50 with a key).

Usage: okpack_sec_nvd_import.py [--days N] [--all-severities] [--vault DIR] [--dry-run]
Env: WIKI_PATH (default /opt/vault), NVD_API_KEY, OKPACK_SEC_NVD_DAYS.
"""
from __future__ import annotations

import argparse
import json
import lzma
import os
import re
import sys
import time
import urllib.parse
import urllib.request
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from okpack_run_report import record_run  # noqa: E402

NVD_API ="https://services.nvd.nist.gov/rest/json/cves/2.0"
_FM = re.compile(r"\A---[ \t]*\n(.*?\n)---[ \t]*\n?(.*)\Z", re.S)
_OWNED = ("severity", "cvss_base", "cvss_version", "cwe", "last_updated")
_HIGH = {"high", "critical"}
_STRICT = False   # set in main() from --strict / OKPACK_STRICT_IMPORT; when on, a fetch/parse/write
                  # failure exits nonzero instead of best-effort skip (okpacks-library#16)


def _yaml_str(v: str) -> str:
    if v == "" or re.search(r'[:#\[\]{}",&*!|>%@`]|^\s|\s$', v):
        return '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return v


def nvd_record(cve: dict) -> dict:
    """Flatten one NVD `cve` object to the fields we store (best CVSS available)."""
    cid = (cve.get("id") or "").strip().upper()
    desc = ""
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            desc = (d.get("value") or "").strip()
            break
    metrics = cve.get("metrics", {})
    score = sev = ver = None
    for mk in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(mk):
            c = metrics[mk][0].get("cvssData", {})
            score, ver = c.get("baseScore"), c.get("version")
            sev = (c.get("baseSeverity") or metrics[mk][0].get("baseSeverity") or "").lower() or None
            break
    cwes = sorted({w2["value"] for w in cve.get("weaknesses", [])
                   for w2 in w.get("description", [])
                   if re.match(r"^CWE-\d+$", w2.get("value", ""))})
    return {"cve_id": cid, "description": desc, "severity": sev,
            "cvss_base": score, "cvss_version": ver, "cwes": cwes}


def page_path(vault: str | os.PathLike, cve_id: str) -> Path:
    slug = cve_id.lower()
    return Path(vault) / "wiki" / "entities" / slug[0] / f"{slug}.md"


def _owned_lines(rec: dict, today: str) -> list[str]:
    lines = []
    if rec["severity"]:
        lines.append(f"severity: {rec['severity']}")
    if rec["cvss_base"] is not None:
        lines.append(f"cvss_base: {rec['cvss_base']}")
        if rec["cvss_version"]:
            lines.append(f"cvss_version: '{rec['cvss_version']}'")
    if rec["cwes"]:
        lines.append("cwe: [" + ", ".join(rec["cwes"]) + "]")
    lines.append(f"last_updated: '{today}'")
    return lines


def render_new_page(rec: dict, today: str) -> str:
    fm = ["type: vulnerability", f"cve_id: {rec['cve_id']}", "tlp: clear"] \
        + _owned_lines(rec, today) + ["version: 1"]
    body = rec["description"] or f"{rec['cve_id']} — see NVD."
    note = ("\n\n> CVSS/CWE imported no_agent from NVD. Analysis below is maintained "
            "by the ingest agent.")
    return "---\n" + "\n".join(fm) + "\n---\n" + body + note + "\n"


def merge_existing(text: str, rec: dict, today: str) -> str | None:
    m = _FM.match(text)
    fm_text, body = (m.group(1), m.group(2)) if m else ("", text)
    kept = [ln for ln in fm_text.splitlines()
            if ln.strip() and ln.split(":", 1)[0].strip() not in _OWNED]
    new_owned = _owned_lines(rec, today)
    old_owned = [ln for ln in fm_text.splitlines()
                 if ln.split(":", 1)[0].strip() in _OWNED]
    sig = lambda ls: [ln for ln in ls if not ln.startswith("last_updated")]  # noqa: E731
    if sig(old_owned) == sig(new_owned):
        return None
    return "---\n" + "\n".join(kept + new_owned) + "\n---\n" + body


def import_cves(records: list[dict], vault: str | os.PathLike, today: str,
                all_severities: bool = False, dry_run: bool = False) -> dict:
    counts = {"enriched": 0, "created": 0, "unchanged": 0, "skipped_lowsev": 0, "total": 0}
    for rec in records:
        if not rec["cve_id"]:
            continue
        counts["total"] += 1
        p = page_path(vault, rec["cve_id"])
        if p.exists():
            new = merge_existing(p.read_text(encoding="utf-8", errors="replace"), rec, today)
            if new is None:
                counts["unchanged"] += 1
                continue
            if not dry_run:
                p.write_text(new, encoding="utf-8")
            counts["enriched"] += 1
        elif all_severities or (rec["severity"] in _HIGH):
            if not dry_run:
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(render_new_page(rec, today), encoding="utf-8")
            counts["created"] += 1
        else:
            counts["skipped_lowsev"] += 1
    return counts


# ── observation mode (multi-source MDM; okengine#38 / okpacks-library#6) ─────────────
SOURCE = "nvd"   # source_registry key + observations/<SOURCE>/ subdir + `source:` stamp


def _registry_admiralty(vault: str | os.PathLike, default=("A", "2")) -> tuple[str, str]:
    """(reliability, credibility) for this source from schema.yaml `source_registry`."""
    rel, cred = default
    try:
        import yaml
        sch = yaml.safe_load((Path(vault) / "schema.yaml").read_text(encoding="utf-8")) or {}
        entry = (sch.get("source_registry") or {}).get(SOURCE) or {}
        rel = str(entry.get("reliability") or rel)
        cred = str(entry.get("credibility_default") or cred)
    except Exception:
        pass
    return rel, cred


def observation_path(vault: str | os.PathLike, slug: str) -> Path:
    return Path(vault) / "wiki" / "observations" / SOURCE / slug[0] / f"{slug}.md"


def render_observation(rec: dict, reliability: str, credibility: str, today: str) -> str:
    """NVD's per-source record for a CVE — authoritative CVSS/CWE. `canonical` is the CVE id
    itself (no alias resolution). The assembler fuses severity/CVSS onto the canonical, preserving
    a KEV-vs-NVD disagreement."""
    import yaml
    fm = {"type": "vulnerability", "source": SOURCE, "reliability": reliability,
          "credibility": credibility, "canonical": rec["cve_id"].lower(),
          "cve_id": rec["cve_id"], "tlp": "clear"}
    if rec["severity"]:
        fm["severity"] = rec["severity"]
    if rec["cvss_base"] is not None:
        fm["cvss_base"] = rec["cvss_base"]
        if rec["cvss_version"]:
            fm["cvss_version"] = rec["cvss_version"]
    if rec["cwes"]:
        fm["cwe"] = rec["cwes"]
    fm["last_updated"] = today
    fm["version"] = 1
    body = rec["description"] or f"{rec['cve_id']} — see NVD."
    note = ("\n\n> NVD per-source record (authoritative CVSS/CWE). Fused into the canonical "
            "vulnerability by canonical_assemble.")
    head = yaml.safe_dump(fm, sort_keys=False, allow_unicode=True,
                          default_flow_style=False).rstrip("\n")
    return "---\n" + head + "\n---\n" + body + note + "\n"


def import_observations(records: list[dict], vault: str | os.PathLike, today: str,
                        all_severities: bool = False, dry_run: bool = False) -> dict:
    """One observations/nvd/<cve>.md per CVE (canonical = the CVE id). Keeps the legacy noise
    bound: only HIGH/CRITICAL CVEs get an observation unless `all_severities` (a lone low-sev NVD
    record would mint an orphan canonical). Idempotent; no merge."""
    reliability, credibility = _registry_admiralty(vault)
    counts = {"written": 0, "skipped_lowsev": 0, "total": 0}
    for rec in records:
        if not rec["cve_id"]:
            continue
        counts["total"] += 1
        if not (all_severities or rec["severity"] in _HIGH):
            counts["skipped_lowsev"] += 1
            continue
        p = observation_path(vault, rec["cve_id"].lower())
        try:
            if not dry_run:
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(render_observation(rec, reliability, credibility, today),
                             encoding="utf-8")
        except OSError:
            if _STRICT:
                raise
            continue
        counts["written"] += 1
    return counts


def fetch_recent(days: int, api_key: str | None = None,
                 now: datetime | None = None) -> list[dict]:
    """Page through NVD for CVEs modified in the last `days`, rate-limited. Returns
    flattened records. Any HTTP/parse error stops paging and returns what we have."""
    now = now or datetime.now(timezone.utc)
    start = (now - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S.000")
    end = now.strftime("%Y-%m-%dT%H:%M:%S.000")
    headers = {"User-Agent": "okpack-sec-nvd-import"}
    if api_key:
        headers["apiKey"] = api_key
    delay = 0.7 if api_key else 6.5      # NVD: 50 vs 5 req / 30s
    out, idx, per = [], 0, 2000
    while True:
        q = urllib.parse.urlencode({"lastModStartDate": start, "lastModEndDate": end,
                                    "resultsPerPage": per, "startIndex": idx})
        try:
            req = urllib.request.Request(f"{NVD_API}?{q}", headers=headers)
            with urllib.request.urlopen(req, timeout=60) as r:   # noqa: S310 (trusted NVD host)
                data = json.loads(r.read().decode("utf-8"))
        except Exception as e:  # noqa: BLE001
            print(f"nvd-import: WARN fetch stopped at index {idx} ({e})", file=sys.stderr)
            break
        for item in data.get("vulnerabilities", []):
            out.append(nvd_record(item.get("cve", {})))
        total = data.get("totalResults", 0)
        idx += per
        if idx >= total or not data.get("vulnerabilities"):
            break
        time.sleep(delay)
    return out


def _iter_bulk_files(paths: list[str]):
    """Expand --bulk paths to feed files: a dir yields its CVE-*.json[.xz], a file yields itself."""
    for pth in paths:
        p = Path(pth)
        if p.is_dir():
            yield from sorted(p.glob("CVE-*.json*"))
        else:
            yield p


def read_bulk(paths: list[str], cve_filter: set | None = None) -> list[dict]:
    """Read FKIE-CAD bulk feed files (per-year `CVE-<YEAR>.json[.xz]`, top-level `cve_items` of
    API-2.0 `cve` objects), optionally filtered to a set of lowercased CVE ids. Offline / no NVD
    rate limit. Reuses `nvd_record` — FKIE items ARE the cve object. okengine#40 backfill path."""
    out: list[dict] = []
    for f in _iter_bulk_files(paths):
        fs = str(f)
        raw = (lzma.open(f, "rt", encoding="utf-8").read() if fs.endswith(".xz")
               else Path(f).read_text(encoding="utf-8"))
        for item in json.loads(raw).get("cve_items", []):
            if cve_filter is not None and (item.get("id") or "").strip().lower() not in cve_filter:
                continue
            out.append(nvd_record(item))
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Import NVD CVSS/CWE (no_agent, bounded).")
    ap.add_argument("--days", type=int,
                    default=int(os.environ.get("OKPACK_SEC_NVD_DAYS") or 7))
    ap.add_argument("--all-severities", action="store_true",
                    help="also stub new CVEs below high severity (noisier)")
    ap.add_argument("--vault", default=os.environ.get("WIKI_PATH", "/opt/vault"))
    ap.add_argument("--src", help="local JSON file (NVD API shape) instead of the live API")
    ap.add_argument("--bulk", nargs="+", metavar="PATH",
                    help="FKIE-CAD bulk feed files/dirs (CVE-YYYY.json[.xz]); offline, no rate "
                         "limit. Use with --cve-list to backfill a target set (okengine#40).")
    ap.add_argument("--cve-list", help="only import CVE ids listed in this file (one per line), "
                                       "e.g. the KEV set — for multi-source fusion backfill")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--observations", action="store_true",
                    help="write per-source observations/nvd/ (MDM; okengine#38) instead of "
                         "legacy enrich-in-place into entities/")
    ap.add_argument("--strict", action="store_true",
                    help="exit nonzero on fetch/parse/write failure instead of best-effort skip "
                         "(also OKPACK_STRICT_IMPORT=1); default is best-effort for scheduled crons")
    args = ap.parse_args(argv)
    global _STRICT
    _STRICT = bool(args.strict or os.environ.get("OKPACK_STRICT_IMPORT"))
    _started = datetime.now(timezone.utc)
    try:
        if args.bulk:
            cve_filter = None
            if args.cve_list:
                cve_filter = {ln.strip().lower() for ln in
                              Path(args.cve_list).read_text(encoding="utf-8").splitlines() if ln.strip()}
            records = read_bulk(args.bulk, cve_filter)
            scope = f"bulk{f' [{len(cve_filter)} in cve-list]' if args.cve_list else ''}"
        elif args.src:
            data = json.loads(Path(args.src).read_text(encoding="utf-8"))
            records = [nvd_record(v.get("cve", {})) for v in data.get("vulnerabilities", [])]
            scope = "src"
        else:
            records = fetch_recent(args.days, os.environ.get("NVD_API_KEY"))
            scope = f"last {args.days}d"
    except Exception as e:  # noqa: BLE001 — best-effort by default; strict -> nonzero
        print(f"nvd-import: {'ERROR' if _STRICT else 'WARN'} could not load CVEs ({e})"
              f"{'' if _STRICT else ' — skipping this run'}", file=sys.stderr)
        record_run(args.vault, "nvd", _started, "failed" if _STRICT else "degraded",
                   error=str(e), dry_run=getattr(args, "dry_run", False))
        return 1 if _STRICT else 0
    today = date.today().isoformat()
    if args.observations or os.environ.get("OKPACK_SEC_OBSERVATIONS"):
        c = import_observations(records, args.vault, today, args.all_severities, args.dry_run)
        print(f"nvd-import[obs]: {c['total']} CVEs ({scope}) -> {c['written']} "
              f"observations/{SOURCE}/, skipped {c['skipped_lowsev']} low-sev"
              f"{' [dry-run]' if args.dry_run else ''}")
        record_run(args.vault, "nvd", _started, "success", counts=c, dry_run=args.dry_run)
        return 0
    c = import_cves(records, args.vault, today, args.all_severities, args.dry_run)
    print(f"nvd-import: {c['total']} CVEs ({scope}) — enriched {c['enriched']}, "
          f"created {c['created']}, unchanged {c['unchanged']}, "
          f"skipped {c['skipped_lowsev']} low-sev{' [dry-run]' if args.dry_run else ''}")
    record_run(args.vault, "nvd", _started, "success", counts=c, dry_run=args.dry_run)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
