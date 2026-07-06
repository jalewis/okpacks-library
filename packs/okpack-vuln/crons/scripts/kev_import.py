#!/usr/bin/env python3
"""okpack-vuln — CISA Known Exploited Vulnerabilities (KEV) importer (no_agent, ZERO LLM tokens).

Seeds one canonical page per ACTIVELY-EXPLOITED CVE from CISA's KEV catalog — the high-signal subset
that matters (~1200 CVEs), NOT all 200k+ of NVD. Each page is `type: cve` under cves/, so an adversary
pack's [[cve/CVE-...]] links resolve here (composition) and each CVE gains automatic backlinks to the
actors/malware that exploit it. MERGE-safe: preserves any fields other lanes/packs added.

License: CISA KEV is public-domain US-Gov work — pages stamp `sources: [CISA KEV]`.

Env: WIKI_PATH (/opt/vault) · KEV_URL (default the CISA KEV JSON feed)
Usage: kev_import.py [--vault DIR] [--dry-run]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.request
from pathlib import Path

import yaml

KEV_URL = os.environ.get(
    "KEV_URL",
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")


def _fetch(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "okpack-vuln/kev_import"})
    with urllib.request.urlopen(req, timeout=90) as r:  # noqa: S310 (fixed https host)  # nosec B310 (fixed https upstream)
        return json.loads(r.read().decode("utf-8"))


def _load_existing_fm(path: Path) -> dict:
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


def _content_root(v):
    # WIKI_PATH is the vault ROOT; content lives under wiki/ — match the engine's `WIKI = VAULT/"wiki"`.
    return Path(v) / "wiki"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--vault", default=os.environ.get("WIKI_PATH", "/opt/vault"))
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)
    vault = _content_root(args.vault)

    try:
        cat = _fetch(KEV_URL)
    except Exception as e:                            # noqa: BLE001
        print(f"ERROR: CISA KEV fetch failed: {e}", file=sys.stderr)
        return 1

    out = vault / "cves"
    written = errs = 0
    for v in cat.get("vulnerabilities", []):
        cid = (v.get("cveID") or "").strip().upper()
        if not _CVE_RE.match(cid):
            continue
        ransomware = (v.get("knownRansomwareCampaignUse") or "").strip().lower() == "known"
        fm = {
            "type": "cve", "id": cid, "cve_id": cid,
            "title": v.get("vulnerabilityName") or cid,
            "vendor": v.get("vendorProject") or None,
            "product": v.get("product") or None,
            "date_added": (v.get("dateAdded") or "")[:10] or None,
            "due_date": (v.get("dueDate") or "")[:10] or None,
            "exploitation_status": "actively-exploited",   # every KEV entry, by definition
            "kev": True,
            "known_ransomware": ransomware or None,
            "sources": ["CISA KEV"],
            "url": f"https://nvd.nist.gov/vuln/detail/{cid}",
        }
        # MERGE: preserve fields other packs/lanes set (e.g. curated cvss_score, exploited_by)
        prev = _load_existing_fm(out / f"{cid}.md")
        for k, val in prev.items():
            if k not in fm:
                fm[k] = val
        fm = {k: val for k, val in fm.items() if val not in (None, "", [], {})}

        body_parts = [f"# {cid} — {v.get('vulnerabilityName') or ''}".rstrip(" —"), ""]
        if v.get("shortDescription"):
            body_parts += [v["shortDescription"].strip(), ""]
        if v.get("requiredAction"):
            body_parts += ["## Required action", "", v["requiredAction"].strip(), ""]
        if ransomware:
            body_parts += ["> **Known ransomware campaign use.**", ""]
        body_parts.append("> Seeded no_agent from the CISA KEV catalog (actively exploited in the wild).")
        body = "\n".join(body_parts)

        if args.dry_run:
            written += 1
            continue
        try:
            out.mkdir(parents=True, exist_ok=True)
            head = yaml.safe_dump(fm, sort_keys=False, allow_unicode=True).rstrip()
            (out / f"{cid}.md").write_text(f"---\n{head}\n---\n\n{body.rstrip()}\n", encoding="utf-8")
            written += 1
        except OSError as e:
            errs += 1
            print(f"WARN: write {cid}: {e}", file=sys.stderr)

    print(f"kev-import: {written} actively-exploited CVE(s) -> cves/"
          f"{f', {errs} write error(s)' if errs else ''}")
    print(json.dumps({"wakeAgent": False}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
