#!/usr/bin/env python3
"""okpack-detections — MITRE ATT&CK mitigations -> course-of-action pages (no_agent, ZERO LLM tokens).

Seeds one `course-of-action` page per ATT&CK mitigation (M####) from the public ATT&CK STIX bundles
(Enterprise + Mobile + ICS), and wires the `mitigates` relationships so each mitigation links the
ATT&CK technique(s) it addresses as `[[T####]]` — the mitigate side of the detection-coverage map
(the detect side is Sigma via sigma_import). Deterministic STIX -> markdown; no agent calls,
MERGE-safe. Runs on any composed vault whose techniques come from ATT&CK (e.g. the okpack-cti bundle,
where okpack-threat-actors mints the technique pages).

License: MITRE ATT&CK is ATT&CK Terms of Use (free with attribution) — pages stamp `sources: [MITRE ATT&CK]`.

Env: WIKI_PATH (/opt/vault) · ATTACK_STIX_BASE · ATTACK_DOMAINS (default enterprise,mobile,ics) · ATTACK_LIMIT (0=all)
Usage: attack_mitigations_import.py [--domains ...] [--limit N] [--vault DIR] [--dry-run]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _okf_write import content_root, clean, slug, write_page   # noqa: E402

STIX_BASE = os.environ.get("ATTACK_STIX_BASE",
                           "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master")
DOMAIN_FILE = {"enterprise": "enterprise-attack/enterprise-attack.json",
               "mobile": "mobile-attack/mobile-attack.json",
               "ics": "ics-attack/ics-attack.json"}
UA = "okpack-detections/attack_mitigations_import (+https://attack.mitre.org)"


def _fetch(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=180) as r:   # noqa: S310 (fixed https host)  # nosec B310 (fixed https upstream)
        return json.loads(r.read().decode("utf-8"))


def _attack_id(obj: dict) -> str:
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


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--vault", default=os.environ.get("WIKI_PATH", "/opt/vault"))
    ap.add_argument("--domains", default=os.environ.get("ATTACK_DOMAINS", "enterprise,mobile,ics"))
    ap.add_argument("--limit", type=int, default=int(os.environ.get("ATTACK_LIMIT", "0")))
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)
    vault = content_root(Path(args.vault))
    domains = [d.strip() for d in args.domains.split(",") if d.strip() in DOMAIN_FILE]

    bundles = []
    for d in domains:
        try:
            bundles.append(_fetch(f"{STIX_BASE}/{DOMAIN_FILE[d]}"))
        except Exception as e:                           # noqa: BLE001 — best-effort seed lane
            print(f"WARN: ATT&CK {d} fetch failed: {e}", file=sys.stderr)

    # index: mitigation stix_id -> record; technique stix_id -> its M#### id
    coa: dict[str, dict] = {}
    tech_id: dict[str, str] = {}
    for b in bundles:
        for o in b.get("objects", []):
            if not _live(o):
                continue
            aid = _attack_id(o)
            if o.get("type") == "course-of-action" and aid.startswith("M"):
                coa[o["id"]] = {"attack_id": aid, "name": (o.get("name") or "").strip(),
                                "desc": o.get("description") or "", "url": _url(o), "mitigates": []}
            elif o.get("type") == "attack-pattern" and aid.startswith("T"):
                tech_id[o["id"]] = aid

    # wire `mitigates` (course-of-action -> attack-pattern) into each mitigation's technique list
    for b in bundles:
        for o in b.get("objects", []):
            if o.get("type") != "relationship" or o.get("relationship_type") != "mitigates":
                continue
            src, tgt = coa.get(o.get("source_ref")), tech_id.get(o.get("target_ref"))
            if src is not None and tgt and tgt not in src["mitigates"]:
                src["mitigates"].append(tgt)

    written = errs = 0
    for i, rec in enumerate(sorted(coa.values(), key=lambda r: r["attack_id"])):
        if args.limit and i >= args.limit:
            break
        techs = sorted(rec["mitigates"])
        body = [f"# {rec['name']} ({rec['attack_id']})", "", clean(rec["desc"]), ""]
        if techs:
            body += ["## Mitigates", "", *[f"- [[{t}]]" for t in techs], ""]
        body.append("> Seeded no_agent from MITRE ATT&CK (course-of-action / mitigation).")
        fm = {"type": "course-of-action", "id": rec["attack_id"], "attack_id": rec["attack_id"],
              "title": rec["name"], "mitigates_techniques": techs or None,
              "sources": ["MITRE ATT&CK"], "url": rec["url"] or None}
        try:
            key = slug(rec["name"])
            if write_page(vault, f"entities/{key[:1] or '_'}/{key}.md",
                          {k: v for k, v in fm.items() if v not in (None, "", [])},
                          "\n".join(body), dry_run=args.dry_run) != "dry":
                written += 1
        except OSError as e:
            errs += 1
            print(f"WARN: {rec['attack_id']}: {e}", file=sys.stderr)

    print(f"attack-mitigations: {written} course-of-action page(s) from {len(coa)} ATT&CK mitigation(s)"
          f"{f', {errs} error(s)' if errs else ''}")
    print(json.dumps({"wakeAgent": False}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
