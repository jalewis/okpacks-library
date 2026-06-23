#!/usr/bin/env python3
"""okpack-sec — CISA KEV importer (no_agent, ZERO LLM tokens).

Fetches the CISA Known Exploited Vulnerabilities catalog (~1,600 entries) and
marks the matching `vulnerability` pages as actively-exploited — KEV is ground
truth that a CVE is being exploited in the wild, the single highest-priority
signal for a defender. Existing pages are FLAGGED (kev fields added, body + other
frontmatter preserved); KEV CVEs not yet in the vault get a lean stub. Deterministic
JSON -> markdown: no agent, no model calls. Small + fast -> runs daily.

Usage: okpack_sec_kev_import.py [--src URL|PATH] [--vault DIR] [--dry-run]
Env: WIKI_PATH (default /opt/vault), OKPACK_SEC_KEV_SRC (override the URL).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.request
from datetime import date, datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from okpack_run_report import record_run  # noqa: E402

KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")
_FM = re.compile(r"\A---[ \t]*\n(.*?\n)---[ \t]*\n?(.*)\Z", re.S)
_OWNED = ("kev", "kev_date_added", "exploitation_status", "kev_ransomware",
          "last_updated")
_STRICT = False   # set in main() from --strict / OKPACK_STRICT_IMPORT; when on, a fetch/parse/write
                  # failure exits nonzero instead of best-effort skip (okpacks-library#16)


def _yaml_str(v: str) -> str:
    if v == "" or re.search(r'[:#\[\]{}",&*!|>%@`]|^\s|\s$', v):
        return '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return v


def kev_records(data: dict) -> list[dict]:
    out = []
    for v in data.get("vulnerabilities", []):
        cid = (v.get("cveID") or "").strip().upper()
        if not re.match(r"^CVE-\d{4}-\d+$", cid):
            continue
        out.append({
            "cve_id": cid,
            "title": (v.get("vulnerabilityName") or cid).strip(),
            "vendor": (v.get("vendorProject") or "").strip(),
            "product": (v.get("product") or "").strip(),
            "date_added": (v.get("dateAdded") or "").strip(),
            "ransomware": (v.get("knownRansomwareCampaignUse") or "").strip().lower() == "known",
            "description": (v.get("shortDescription") or "").strip(),
        })
    return out


def page_path(vault: str | os.PathLike, cve_id: str) -> Path:
    slug = cve_id.lower()
    return Path(vault) / "wiki" / "entities" / slug[0] / f"{slug}.md"


def _kev_lines(rec: dict, today: str) -> list[str]:
    lines = ["kev: true", "exploitation_status: actively-exploited",
             f"kev_date_added: '{rec['date_added']}'"]
    if rec["ransomware"]:
        lines.append("kev_ransomware: true")
    lines.append(f"last_updated: '{today}'")
    return lines


def render_new_page(rec: dict, today: str) -> str:
    fm = ["type: vulnerability", f"cve_id: {rec['cve_id']}",
          f"title: {_yaml_str(rec['title'])}", "tlp: clear"]
    if rec["vendor"]:
        fm.append(f"vendor: {_yaml_str(rec['vendor'])}")
    if rec["product"]:
        fm.append(f"product: {_yaml_str(rec['product'])}")
    fm += _kev_lines(rec, today) + ["version: 1"]
    body = rec["description"] or f"{rec['cve_id']} — CISA Known Exploited Vulnerability."
    note = ("\n\n> On the CISA KEV catalog (known exploited in the wild). Imported "
            "no_agent from CISA; analysis below is maintained by the ingest agent.")
    return "---\n" + "\n".join(fm) + "\n---\n" + body + note + "\n"


def merge_existing(text: str, rec: dict, today: str) -> str | None:
    """Add/refresh ONLY the KEV-owned frontmatter keys on an existing vulnerability
    page; preserve every other key and the whole body. None if already current."""
    m = _FM.match(text)
    fm_text, body = (m.group(1), m.group(2)) if m else ("", text)
    kept = [ln for ln in fm_text.splitlines()
            if ln.strip() and ln.split(":", 1)[0].strip() not in _OWNED]
    new_owned = _kev_lines(rec, today)
    old_owned = [ln for ln in fm_text.splitlines()
                 if ln.split(":", 1)[0].strip() in _OWNED]
    sig = lambda ls: [ln for ln in ls if not ln.startswith("last_updated")]  # noqa: E731
    if sig(old_owned) == sig(new_owned):
        return None
    return "---\n" + "\n".join(kept + new_owned) + "\n---\n" + body


def import_kev(data: dict, vault: str | os.PathLike, today: str,
               dry_run: bool = False) -> dict:
    counts = {"created": 0, "flagged": 0, "unchanged": 0, "total": 0, "ransomware": 0}
    for rec in kev_records(data):
        counts["total"] += 1
        if rec["ransomware"]:
            counts["ransomware"] += 1
        p = page_path(vault, rec["cve_id"])
        if p.exists():
            new = merge_existing(p.read_text(encoding="utf-8", errors="replace"), rec, today)
            if new is None:
                counts["unchanged"] += 1
                continue
            if not dry_run:
                p.write_text(new, encoding="utf-8")
            counts["flagged"] += 1
        else:
            if not dry_run:
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(render_new_page(rec, today), encoding="utf-8")
            counts["created"] += 1
    return counts


def load_kev(src: str) -> dict:
    if "://" not in src:
        return json.loads(Path(src).read_text(encoding="utf-8"))
    req = urllib.request.Request(src, headers={"User-Agent": "okpack-sec-kev-import"})
    with urllib.request.urlopen(req, timeout=60) as r:   # noqa: S310 (trusted CISA host)
        return json.loads(r.read().decode("utf-8"))


# ── observation mode (multi-source MDM; okengine#38 / okpacks-library#6) ─────────────
SOURCE = "cisa-kev"   # source_registry key + observations/<SOURCE>/ subdir + `source:` stamp


def _registry_admiralty(vault: str | os.PathLike, default=("A", "1")) -> tuple[str, str]:
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
    """CISA KEV's per-source record for a CVE — actively-exploited + ransomware use. `canonical`
    is the CVE id itself (the natural key; no alias resolution). The assembler fuses
    `kev`/`exploitation_status` onto the canonical vulnerability."""
    import yaml
    fm = {"type": "vulnerability", "source": SOURCE, "reliability": reliability,
          "credibility": credibility, "canonical": rec["cve_id"].lower(),
          "cve_id": rec["cve_id"], "title": rec["title"], "tlp": "clear"}
    if rec["vendor"]:
        fm["vendor"] = rec["vendor"]
    if rec["product"]:
        fm["product"] = rec["product"]
    fm["kev"] = True
    fm["exploitation_status"] = "actively-exploited"
    if rec["date_added"]:
        fm["kev_date_added"] = rec["date_added"]
    if rec["ransomware"]:
        fm["kev_ransomware"] = True
    fm["last_updated"] = today
    fm["version"] = 1
    body = rec["description"] or f"{rec['cve_id']} — CISA Known Exploited Vulnerability."
    note = ("\n\n> CISA KEV per-source record (known exploited in the wild). Fused into the "
            "canonical vulnerability by canonical_assemble.")
    head = yaml.safe_dump(fm, sort_keys=False, allow_unicode=True,
                          default_flow_style=False).rstrip("\n")
    return "---\n" + head + "\n---\n" + body + note + "\n"


def import_observations(data: dict, vault: str | os.PathLike, today: str,
                        dry_run: bool = False) -> dict:
    """One observations/cisa-kev/<cve>.md per KEV entry (canonical = the CVE id). Idempotent;
    no merge — the assembler fuses across sources."""
    reliability, credibility = _registry_admiralty(vault)
    counts = {"written": 0, "total": 0, "ransomware": 0}
    for rec in kev_records(data):
        counts["total"] += 1
        if rec["ransomware"]:
            counts["ransomware"] += 1
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


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Import the CISA KEV catalog (no_agent).")
    ap.add_argument("--src", default=os.environ.get("OKPACK_SEC_KEV_SRC") or KEV_URL)
    ap.add_argument("--vault", default=os.environ.get("WIKI_PATH", "/opt/vault"))
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--observations", action="store_true",
                    help="write per-source observations/cisa-kev/ (MDM; okengine#38) instead of "
                         "legacy flag-in-place into entities/")
    ap.add_argument("--strict", action="store_true",
                    help="exit nonzero on fetch/parse/write failure instead of best-effort skip "
                         "(also OKPACK_STRICT_IMPORT=1); default is best-effort for scheduled crons")
    args = ap.parse_args(argv)
    global _STRICT
    _STRICT = bool(args.strict or os.environ.get("OKPACK_STRICT_IMPORT"))
    _started = datetime.now(timezone.utc)
    try:
        data = load_kev(args.src)
    except Exception as e:  # noqa: BLE001 — best-effort by default; strict -> nonzero
        print(f"kev-import: {'ERROR' if _STRICT else 'WARN'} could not load KEV ({e})"
              f"{'' if _STRICT else ' — skipping this run'}", file=sys.stderr)
        record_run(args.vault, "kev", _started, "failed" if _STRICT else "degraded",
                   error=str(e), dry_run=getattr(args, "dry_run", False))
        return 1 if _STRICT else 0
    today = date.today().isoformat()
    if args.observations or os.environ.get("OKPACK_SEC_OBSERVATIONS"):
        c = import_observations(data, args.vault, today, args.dry_run)
        print(f"kev-import[obs]: {c['total']} KEV entries -> {c['written']} observations/{SOURCE}/ "
              f"({c['ransomware']} ransomware-linked){' [dry-run]' if args.dry_run else ''}")
        record_run(args.vault, "kev", _started, "success", counts=c, dry_run=args.dry_run)
        return 0
    c = import_kev(data, args.vault, today, args.dry_run)
    print(f"kev-import: {c['total']} KEV entries — flagged {c['flagged']} existing, "
          f"created {c['created']} stubs, unchanged {c['unchanged']} "
          f"({c['ransomware']} ransomware-linked){' [dry-run]' if args.dry_run else ''}")
    record_run(args.vault, "kev", _started, "success", counts=c, dry_run=args.dry_run)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
