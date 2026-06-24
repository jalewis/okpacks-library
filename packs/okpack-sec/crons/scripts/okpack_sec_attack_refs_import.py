#!/usr/bin/env python3
"""okpack-sec — ATT&CK bibliography -> citing `source` pages importer (no_agent, ZERO LLM tokens).

Every MITRE ATT&CK group object ships a curated reference bibliography (`external_references`:
publisher + URL + description) — the authoritative reporting ATT&CK built the actor profile from.
The catalog importer strips these as `(Citation: …)` noise; this importer mints them as conformant
`type: source` pages (~728 unique reports across ~174 groups) that LINK to the actor(s) they cite
(`rels.related-to` -> STIX `report.object_refs`).

That backlink is what turns a flagship actor from "0 citing sources" into a graph of real,
Admiralty-scored provenance — the material the page-enrich agent needs to write *sourced* prose
under the no-fabrication rule (okpacks-library#2; unblocks #10). This is a deterministic,
no-fabrication backfill: every field is derived from data ATT&CK already publishes (the body is
MITRE's own citation description). Publisher/reliability are inferred from the source domain and an
analyst may refine them. Changes ~2-3x/year with ATT&CK -> weekly.

Non-destructive: CREATE-if-absent only — an existing source page (e.g. agent-authored from a live
feed) is never overwritten.

Usage: okpack_sec_attack_refs_import.py [--bundle URL|PATH] [--vault DIR] [--dry-run]
Env: WIKI_PATH (default /opt/vault), OKPACK_SEC_ATTACK_BUNDLE (override the URL).
"""
from __future__ import annotations

import argparse
import hashlib
import os
import re
import sys
from datetime import date, datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

# Reuse the catalog importer's fetch + group parsing (slug/alias logic stays in one place).
sys.path.insert(0, str(Path(__file__).resolve().parent))
from okpack_sec_attack_import import (  # noqa: E402
    kebab, load_bundle, is_deprecated, mitre_id_of, ATTACK_URL,
)
from okpack_run_report import record_run  # noqa: E402

_STRICT = False   # set in main() from --strict / OKPACK_STRICT_IMPORT; when on, a fetch/parse/write
                  # failure exits nonzero instead of best-effort skip (okpacks-library#16)

# ── publisher / Admiralty inference from the source domain ───────────────────
# Registrable domains of recognized FIRST-PARTY threat-intel labs (Admiralty A: vendor lab on own
# telemetry) -> display publisher. Suffix-matched, so subdomains (blog.talos…, unit42.palo…) hit.
_VENDOR_A = {
    "crowdstrike.com": "CrowdStrike", "mandiant.com": "Mandiant", "fireeye.com": "FireEye",
    "microsoft.com": "Microsoft", "securelist.com": "Kaspersky (Securelist)",
    "kaspersky.com": "Kaspersky", "kasperskycontenthub.com": "Kaspersky",
    "secureworks.com": "Secureworks", "paloaltonetworks.com": "Palo Alto Networks (Unit 42)",
    "talosintelligence.com": "Cisco Talos", "welivesecurity.com": "ESET", "eset.com": "ESET",
    "proofpoint.com": "Proofpoint", "trendmicro.com": "Trend Micro", "symantec.com": "Symantec",
    "security.com": "Symantec", "securityintelligence.com": "IBM X-Force",
    "checkpoint.com": "Check Point Research", "dragos.com": "Dragos", "volexity.com": "Volexity",
    "sentinelone.com": "SentinelOne", "clearskysec.com": "ClearSky", "intezer.com": "Intezer",
    "cybereason.com": "Cybereason", "recordedfuture.com": "Recorded Future",
    "sophos.com": "Sophos", "bitdefender.com": "Bitdefender", "group-ib.com": "Group-IB",
    "ptsecurity.com": "Positive Technologies", "zscaler.com": "Zscaler", "fortinet.com": "Fortinet",
    "mcafee.com": "McAfee", "accenture.com": "Accenture", "lookout.com": "Lookout",
    "malwarebytes.com": "Malwarebytes", "cisco.com": "Cisco", "google.com": "Google",
    "withgoogle.com": "Google Threat Intelligence", "amnesty.org": "Amnesty International",
    "citizenlab.ca": "Citizen Lab", "blog.google": "Google",
    "nccgroup.com": "NCC Group", "redcanary.com": "Red Canary", "anomali.com": "Anomali",
    "pwc.co.uk": "PwC", "pwc.com": "PwC", "ibm.com": "IBM", "blackberry.com": "BlackBerry",
    "forcepoint.com": "Forcepoint", "rapid7.com": "Rapid7", "riskiq.com": "RiskIQ",
    "threatconnect.com": "ThreatConnect", "morphisec.com": "Morphisec", "novetta.com": "Novetta",
    "sygnia.co": "Sygnia", "intel471.com": "Intel 471", "domaintools.com": "DomainTools",
    "team-cymru.com": "Team Cymru", "360.net": "Qihoo 360", "fb.com": "Meta",
    "fox-it.com": "Fox-IT", "nozominetworks.com": "Nozomi Networks",
    "cylance.com": "Cylance", "objective-see.com": "Objective-See",
}
# Government / CERT (Admiralty A: official confirmation) -> publisher.
_GOV_A = {
    "cisa.gov": "CISA", "us-cert.gov": "US-CERT", "justice.gov": "US DoJ", "fbi.gov": "FBI",
    "ic3.gov": "FBI IC3", "treasury.gov": "US Treasury", "state.gov": "US State Dept",
    "ncsc.gov.uk": "NCSC UK", "cyber.gov.au": "ACSC", "cyber.gc.ca": "CCCS",
    "europa.eu": "EU (ENISA)", "ncsc.gov.ie": "NCSC IE", "jpcert.or.jp": "JPCERT/CC",
    "cert.pl": "CERT Polska",
}
# Reputable news / press (Admiralty C).
_NEWS_C = {
    "krebsonsecurity.com": "Krebs on Security", "bleepingcomputer.com": "BleepingComputer",
    "thehackernews.com": "The Hacker News", "wired.com": "WIRED", "arstechnica.com": "Ars Technica",
    "reuters.com": "Reuters", "zdnet.com": "ZDNet", "cyberscoop.com": "CyberScoop",
    "therecord.media": "The Record", "theregister.com": "The Register", "vice.com": "VICE",
    "nytimes.com": "The New York Times", "washingtonpost.com": "The Washington Post",
    "darkreading.com": "Dark Reading", "securityaffairs.co": "Security Affairs",
    "securityaffairs.com": "Security Affairs", "securityweek.com": "SecurityWeek",
    "scmagazine.com": "SC Media", "infosecurity-magazine.com": "Infosecurity Magazine",
}
_MONTHS = {m: i for i, m in enumerate(
    ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"], 1)}
# Wayback snapshot URL: capture date (1-3) + the original it wrapped (4). Tolerates the modifier
# suffix (…if_/, …id_/), a single-slash scheme (https:/…), and a scheme-less inner URL.
_ARCHIVE_RE = re.compile(r"web\.archive\.org/web/(\d{4})(\d{2})(\d{2})\d*(?:[a-z]{2}_)?/(.+)$", re.I)
_DATE_RE = re.compile(r"\b(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\.?\s+(\d{4})", re.I)
_YEAR_RE = re.compile(r"\b(20\d{2}|19\d{2})\b")


def _unwrap(url: str) -> str:
    """A web.archive.org snapshot URL -> the original it captured (so we attribute the real
    publisher, not the Wayback Machine). Normalizes a single-slash or absent scheme so the netloc
    parses. Non-archive URLs pass through unchanged."""
    m = _ARCHIVE_RE.search(url or "")
    if not m:
        return url or ""
    tail = re.sub(r"^(https?):/(?!/)", r"\1://", m.group(4))   # https:/ -> https://
    return tail if tail.startswith("http") else "http://" + tail


def _domain(url: str) -> str:
    d = (urlparse(url).netloc or "").lower()
    return d[4:] if d.startswith("www.") else d


def _match(domain: str, table: dict) -> str | None:
    for known, pub in table.items():
        if domain == known or domain.endswith("." + known):
            return pub
    return None


def classify(url: str) -> dict:
    """Infer (publisher, reliability, credibility, source_kind, bias_flags) from the source domain.
    Conservative fallback for unrecognized domains: single-analyst/unverified (D), a blog."""
    dom = _domain(_unwrap(url))
    pub = _match(dom, _GOV_A)
    if pub or re.search(r"(^|\.)gov(\.|$)", dom) or dom.endswith((".mil", ".gc.ca")):
        return {"publisher": pub or dom, "reliability": "A", "credibility": 2,
                "source_kind": "advisory", "bias_flags": []}
    pub = _match(dom, _VENDOR_A)
    if pub:
        return {"publisher": pub, "reliability": "A", "credibility": 3,
                "source_kind": "vendor-research", "bias_flags": ["vendor-commercial"]}
    pub = _match(dom, _NEWS_C)
    if pub:
        return {"publisher": pub, "reliability": "C", "credibility": 3,
                "source_kind": "news", "bias_flags": []}
    label = dom.split(".")[-2] if dom.count(".") >= 1 else dom
    return {"publisher": label.replace("-", " ").title() or "Unknown", "reliability": "D",
            "credibility": 3, "source_kind": "blog", "bias_flags": []}


def parse_published(source_name: str, raw_url: str) -> str:
    """Best-effort publication date, in descending precision, ALWAYS grounded in stated data (never
    invented): an explicit 'Month YYYY' in the citation label -> YYYY-MM-01; a Wayback capture
    timestamp -> that date; a bare year -> YYYY-01-01. None found -> '' (the field is omitted)."""
    m = _DATE_RE.search(source_name or "")
    if m:
        return f"{int(m.group(2)):04d}-{_MONTHS[m.group(1).lower()[:3]]:02d}-01"
    a = _ARCHIVE_RE.search(raw_url or "")
    if a:
        return f"{a.group(1)}-{a.group(2)}-{a.group(3)}"
    y = _YEAR_RE.search(source_name or "")
    return f"{y.group(1)}-01-01" if y else ""


# ── aggregate the bibliography: one record per unique report, all citing actors ──
def parse_group_refs(bundle: dict, include_deprecated: bool = False) -> list[dict]:
    """Collapse every group's `external_references` into one record per unique report URL (deduped
    by the unwrapped original), carrying the set of actor slugs that cite it. Deterministic order."""
    by_url: dict[str, dict] = {}
    for o in bundle.get("objects", []):
        if o.get("type") != "intrusion-set":
            continue
        if is_deprecated(o) and not include_deprecated:
            continue
        name = (o.get("name") or mitre_id_of(o) or "").strip()
        if not name:
            continue
        actor_slug = kebab(name)
        for r in o.get("external_references", []):
            url, sname = r.get("url"), (r.get("source_name") or "").strip()
            if not url or sname == "mitre-attack":
                continue
            key = _unwrap(url)
            rec = by_url.get(key)
            if rec is None:
                meta = classify(url)
                rec = by_url[key] = {
                    "url": url, "name": sname or _domain(key),
                    "description": (r.get("description") or "").strip(),
                    "published": parse_published(sname, url), "actors": [],
                    **meta,
                }
            if actor_slug not in rec["actors"]:
                rec["actors"].append(actor_slug)
            # prefer the most descriptive label/body seen for this URL (longest non-empty)
            if len(sname) > len(rec["name"]):
                rec["name"] = sname
            if len(r.get("description") or "") > len(rec["description"]):
                rec["description"] = (r.get("description") or "").strip()
            if not rec["published"]:
                rec["published"] = parse_published(sname, url)
    out = list(by_url.values())
    for rec in out:
        rec["actors"].sort()
    out.sort(key=lambda r: (r["published"] or "0000", r["name"]))
    return out


def source_slug(rec: dict) -> str:
    """Stable, unique slug: date + kebab(label), disambiguated by a short hash of the URL so two
    distinct reports never collide and a re-run is idempotent."""
    h = hashlib.blake2s(rec["url"].encode("utf-8"), digest_size=3).hexdigest()
    stem = kebab(rec["name"])[:56].strip("-") or "report"
    prefix = (rec["published"][:10] + "-") if rec["published"] else ""
    return f"{prefix}{stem}-{h}"


def source_path(vault: Path, rec: dict, slug: str) -> Path:
    if rec["published"]:
        y, m = rec["published"][:4], rec["published"][5:7]
        return vault / "wiki" / "sources" / y / m / f"{slug}.md"
    return vault / "wiki" / "sources" / "undated" / f"{slug}.md"


def render_source(rec: dict, today: str) -> str:
    import yaml
    fm = {"type": "source", "name": rec["name"], "source_kind": rec["source_kind"],
          "publisher": rec["publisher"]}
    if rec["published"]:
        fm["published"] = rec["published"]
    fm["url"] = rec["url"]
    fm["reliability"] = rec["reliability"]
    fm["credibility"] = rec["credibility"]
    fm["tlp"] = "clear"
    if rec["bias_flags"]:
        fm["bias_flags"] = rec["bias_flags"]
    fm["rels"] = {"related-to": [f"[[{a}]]" for a in rec["actors"]]}
    fm["tags"] = ["attack-bibliography"]
    fm["last_updated"] = today
    fm["version"] = 1
    head = yaml.safe_dump(fm, sort_keys=False, allow_unicode=True,
                          default_flow_style=False).rstrip("\n")
    cited = "\n".join(f"- [[{a}]]" for a in rec["actors"])
    summary = rec["description"] or (
        f"{rec['name']} — reporting referenced by MITRE ATT&CK as a primary source for the "
        "actor(s) below.")
    note = ("> Citing-source stub minted no_agent from the MITRE ATT&CK group bibliography "
            "(okpacks-library#2). Provides provenance + an enrich anchor — not a fetched copy of "
            "the report. Publisher/reliability are inferred from the source domain; an analyst may "
            "refine them.")
    return (f"---\n{head}\n---\n## Summary\n{summary}\n\n"
            f"## Cited by ATT&CK for\n{cited}\n\n{note}\n")


def import_sources(bundle: dict, vault: Path, today: str, dry_run: bool = False,
                   include_deprecated: bool = False) -> dict:
    counts = {"created": 0, "exists": 0, "total": 0, "actors_linked": 0}
    for rec in parse_group_refs(bundle, include_deprecated):
        counts["total"] += 1
        p = source_path(vault, rec, source_slug(rec))
        if p.exists():                       # never clobber an agent-authored source page
            counts["exists"] += 1
            continue
        try:
            if not dry_run:
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(render_source(rec, today), encoding="utf-8")
        except OSError:
            if _STRICT:
                raise
            counts["exists"] += 1
            continue
        counts["created"] += 1
        counts["actors_linked"] += len(rec["actors"])
    return counts


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Mint citing source pages from the MITRE ATT&CK group bibliography (no_agent).")
    ap.add_argument("--bundle", default=os.environ.get("OKPACK_SEC_ATTACK_BUNDLE") or ATTACK_URL)
    ap.add_argument("--vault", default=os.environ.get("WIKI_PATH", "/opt/vault"))
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--include-deprecated", action="store_true",
                    help="also mint references for deprecated/revoked groups")
    ap.add_argument("--strict", action="store_true",
                    help="exit nonzero on fetch/parse/write failure instead of best-effort skip "
                         "(also OKPACK_STRICT_IMPORT=1); default is best-effort for scheduled crons")
    args = ap.parse_args(argv)
    global _STRICT
    _STRICT = bool(args.strict or os.environ.get("OKPACK_STRICT_IMPORT"))
    _started = datetime.now(timezone.utc)
    try:
        bundle = load_bundle(args.bundle)
    except Exception as e:  # noqa: BLE001 — best-effort by default; strict -> nonzero
        print(f"attack-refs-import: {'ERROR' if _STRICT else 'WARN'} could not load bundle ({e})"
              f"{'' if _STRICT else ' — skipping this run'}", file=sys.stderr)
        record_run(args.vault, "attack-refs", _started, "failed" if _STRICT else "degraded",
                   error=str(e), dry_run=getattr(args, "dry_run", False))
        return 1 if _STRICT else 0
    today = date.today().isoformat()
    c = import_sources(bundle, Path(args.vault), today, args.dry_run, args.include_deprecated)
    print(f"attack-refs-import: {c['total']} unique ATT&CK references — created {c['created']} "
          f"source pages ({c['actors_linked']} actor links), {c['exists']} already present"
          f"{' [dry-run]' if args.dry_run else ''}")
    record_run(args.vault, "attack-refs", _started, "success", counts=c, dry_run=args.dry_run)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
