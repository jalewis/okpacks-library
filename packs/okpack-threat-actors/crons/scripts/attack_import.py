#!/usr/bin/env python3
"""okpack-threat-actors — MITRE ATT&CK bulk importer (no_agent, ZERO LLM tokens).

The CENTERPIECE ingest lane. Pulls the public ATT&CK STIX bundles (Enterprise + Mobile + ICS)
and seeds the whole adversary graph from authoritative, curated data — with alias arrays already
populated, which is what makes the "APT29 = Cozy Bear = Midnight Blizzard" reconciliation work out
of the box. Zero model spend; re-run picks up new ATT&CK releases (MERGE-writes, so it never
clobbers attribution_confidence / related_actors set by the enrich + correlation lanes).

STIX object -> page:
  intrusion-set  -> entities/<slug>.md        type: actor       (aliases, ATT&CK G####)
  campaign       -> entities/<slug>.md        type: campaign    (C####, first/last_seen, attributed-to)
  malware        -> entities/<slug>.md        type: malware     (S####, x_mitre_aliases, platforms)
  tool           -> entities/<slug>.md        type: tool        (S####, platforms)
  attack-pattern -> techniques/<T-id>.md      type: technique   (T####, tactic[], sub-technique parent)
  course-of-action (mitigation) -> concepts/<slug>.md  type: concept  concept_kind: mitigation (M####)
relationship -> [[wikilinks]] on the source page:
  uses (actor/campaign -> malware/tool/technique), attributed-to (campaign -> actor),
  subtechnique-of (technique -> parent), mitigates (mitigation -> technique).

License: ATT&CK is free to use WITH ATTRIBUTION (MITRE ATT&CK Terms of Use); every page stamps
`sources: [MITRE ATT&CK]` + the object URL for provenance.

Env: WIKI_PATH (/opt/vault) · ATTACK_DOMAINS (default enterprise,mobile,ics) ·
     ATTACK_STIX_BASE (default the mitre-attack/attack-stix-data raw GitHub base) · ATTACK_LIMIT (0=all)
Usage: attack_import.py [--domains enterprise,mobile,ics] [--limit N] [--vault DIR] [--dry-run]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _okf_write import content_root, clean, slug, write_page  # noqa: E402

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)

STIX_BASE = os.environ.get(
    "ATTACK_STIX_BASE",
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master")
DOMAIN_FILE = {"enterprise": "enterprise-attack/enterprise-attack.json",
               "mobile": "mobile-attack/mobile-attack.json",
               "ics": "ics-attack/ics-attack.json"}
FETCH_TIMEOUT = 180
UA = "okpack-threat-actors/attack_import (+https://attack.mitre.org)"


def _fetch(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT) as r:  # noqa: S310 (fixed https host)  # nosec B310 (fixed https upstream)
        return json.loads(r.read().decode("utf-8"))


def _attack_id(obj: dict) -> str:
    """The ATT&CK external id (G0016 / S0002 / T1566 / C0001 / M1234) from external_references."""
    for ref in obj.get("external_references") or []:
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return ref["external_id"]
    return ""


def _url(obj: dict) -> str:
    for ref in obj.get("external_references") or []:
        if ref.get("source_name") == "mitre-attack" and ref.get("url"):
            return ref["url"]
    return ""


def _live(obj: dict) -> bool:
    return not (obj.get("revoked") or obj.get("x_mitre_deprecated"))


def _cves(obj: dict) -> list[str]:
    """CVE ids referenced by a STIX object (external_references external_id/url). These become the
    COMPOSE SEAM: [[CVE-...]] links that dangle standalone and resolve to okpack-vuln's cve pages."""
    out = set()
    for ref in obj.get("external_references") or []:
        for field in (ref.get("external_id"), ref.get("url"), ref.get("source_name")):
            for m in _CVE_RE.findall(str(field or "")):
                out.add(m.upper())
    return sorted(out)


# STIX type -> (page_type, namespace). attack-pattern/course-of-action handled specially.
_ENTITY_KIND = {"intrusion-set": "actor", "campaign": "campaign", "malware": "malware", "tool": "tool"}


def build_records(bundles: list[dict]) -> tuple[dict, dict]:
    """Index every live object into a page record; return (records_by_stixid, wikilink_by_stixid)."""
    records: dict[str, dict] = {}
    link: dict[str, str] = {}                       # stix_id -> "[[key|Name]]" for relationship wiring

    def _register(stix_id, ptype, key, path, name, fm, desc):
        records[stix_id] = {"ptype": ptype, "key": key, "path": path, "name": name,
                            "fm": fm, "desc": desc, "links": {}}
        link[stix_id] = f"[[{key}|{name}]]"

    for b in bundles:
        for o in b.get("objects", []):
            if o.get("type") == "relationship" or not _live(o):
                continue
            t, name, aid = o.get("type"), (o.get("name") or "").strip(), _attack_id(o)
            desc = clean(o.get("description") or "")
            if t in _ENTITY_KIND:
                ptype = _ENTITY_KIND[t]
                key = slug(name)
                fm = {"type": ptype, "id": aid or key, "title": name, "attack_id": aid,
                      "aliases": [a for a in (o.get("aliases") or o.get("x_mitre_aliases") or [])
                                  if a and a != name],
                      "platforms": o.get("x_mitre_platforms") or None,
                      "first_seen": (o.get("first_seen") or "")[:10] or None,
                      "last_seen": (o.get("last_seen") or "")[:10] or None,
                      "sources": ["MITRE ATT&CK"], "url": _url(o),
                      "needs_review": True}
                _register(o["id"], ptype, key, f"entities/{key}.md", name, fm, desc)
            elif t == "attack-pattern":
                key = aid or slug(name)
                tactics = [p.get("phase_name") for p in (o.get("kill_chain_phases") or [])
                           if p.get("kill_chain_name") == "mitre-attack" and p.get("phase_name")]
                fm = {"type": "technique", "id": aid or key, "title": name, "attack_id": aid,
                      "tactic": tactics or None,
                      "is_subtechnique": bool(o.get("x_mitre_is_subtechnique")) or None,
                      "platforms": o.get("x_mitre_platforms") or None,
                      "sources": ["MITRE ATT&CK"], "url": _url(o), "needs_review": True}
                _register(o["id"], "technique", key, f"techniques/{key}.md", name, fm, desc)
            elif t == "course-of-action":
                key = slug(name)
                fm = {"type": "concept", "id": aid or key, "title": name, "concept_kind": "mitigation",
                      "attack_id": aid, "sources": ["MITRE ATT&CK"], "url": _url(o)}
                _register(o["id"], "concept", key, f"concepts/{key}.md", name, fm, desc)
            cves = _cves(o)                          # COMPOSE SEAM: link exploited CVEs (resolve via okpack-vuln)
            if cves and o.get("id") in records:
                records[o["id"]]["fm"]["exploits_cve"] = cves
                records[o["id"]]["links"].setdefault("Exploits", []).extend(f"[[{c}]]" for c in cves)
    return records, link


# relationship_type -> (section heading, direction) applied to the SOURCE page
_REL_SECTION = {"uses": "Uses", "attributed-to": "Attributed to",
                "subtechnique-of": "Sub-technique of", "mitigates": "Mitigates"}


def wire_relationships(bundles: list[dict], records: dict, link: dict) -> None:
    for b in bundles:
        for o in b.get("objects", []):
            if o.get("type") != "relationship" or not _live(o):
                continue
            rtype = o.get("relationship_type")
            src, tgt = records.get(o.get("source_ref")), link.get(o.get("target_ref"))
            if not src or not tgt or rtype not in _REL_SECTION:
                continue
            src["links"].setdefault(_REL_SECTION[rtype], []).append(tgt)
            tgt_rec = records.get(o.get("target_ref"))
            if rtype == "subtechnique-of" and tgt_rec:
                src["fm"]["parent_technique"] = tgt_rec["fm"].get("attack_id")
            elif rtype == "uses" and tgt_rec and src["ptype"] in ("actor", "campaign"):
                # structured lists for the correlation lane (idf-weighted actor overlap reads these)
                if tgt_rec["ptype"] == "technique":
                    src["fm"].setdefault("techniques", []).append(tgt_rec["fm"].get("attack_id") or tgt_rec["key"])
                elif tgt_rec["ptype"] in ("malware", "tool"):
                    src["fm"].setdefault("software", []).append(tgt_rec["key"])


def render_body(rec: dict) -> str:
    lines = [f"# {rec['name']}", ""]
    if rec["fm"].get("attack_id"):
        lines.append(f"**ATT&CK {rec['fm']['attack_id']}**"
                     + (f" · {rec['fm'].get('url')}" if rec["fm"].get("url") else ""))
        lines.append("")
    if rec["desc"]:
        lines += [rec["desc"], ""]
    for heading, refs in rec["links"].items():
        uniq = sorted(set(refs))
        lines += [f"## {heading}", ""] + [f"- {r}" for r in uniq] + [""]
    lines.append("> Seeded no_agent from MITRE ATT&CK. Attribution reflects ATT&CK's assessment; "
                 "treat as a starting point, not a verdict.")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--domains", default=os.environ.get("ATTACK_DOMAINS", "enterprise,mobile,ics"))
    ap.add_argument("--limit", type=int, default=int(os.environ.get("ATTACK_LIMIT", "0")))
    ap.add_argument("--vault", default=os.environ.get("WIKI_PATH", "/opt/vault"))
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)
    vault = content_root(Path(args.vault))

    domains = [d.strip() for d in args.domains.split(",") if d.strip() in DOMAIN_FILE]
    bundles, fetch_errs = [], 0
    for d in domains:
        try:
            bundles.append(_fetch(f"{STIX_BASE}/{DOMAIN_FILE[d]}"))
        except Exception as e:                       # noqa: BLE001 — one bad domain must not kill the run
            fetch_errs += 1
            print(f"WARN: fetch {d} failed: {e}", file=sys.stderr)
    if not bundles:
        print("ERROR: no ATT&CK bundles fetched — is the network/STIX base reachable?", file=sys.stderr)
        return 1

    records, link = build_records(bundles)
    wire_relationships(bundles, records, link)

    recs = list(records.values())
    if args.limit:
        recs = recs[:args.limit]
    counts, errs = {}, 0
    def _dedup(v):
        if isinstance(v, list):
            seen, out = set(), []
            for x in v:
                if str(x).lower() not in seen:
                    seen.add(str(x).lower())
                    out.append(x)
            return out
        return v
    for rec in recs:
        rec["fm"] = {k: _dedup(v) for k, v in rec["fm"].items() if v not in (None, "", [], {})}
        try:
            action = write_page(vault, rec["path"], rec["fm"], render_body(rec), dry_run=args.dry_run)
        except OSError as e:                          # one unwritable page must not abort the run
            errs += 1
            print(f"WARN: write {rec['path']}: {e}", file=sys.stderr)
            continue
        counts[rec["ptype"]] = counts.get(rec["ptype"], 0) + 1
        _ = action
    summary = ", ".join(f"{n} {t}" for t, n in sorted(counts.items()))
    print(f"attack-import: {len(bundles)} domain bundle(s) -> {summary or 'nothing'}"
          f"{f', {fetch_errs} fetch error(s)' if fetch_errs else ''}"
          f"{f', {errs} write error(s)' if errs else ''}")
    print(json.dumps({"wakeAgent": False}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
