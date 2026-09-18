#!/usr/bin/env python3
"""okpack-incidents — VERIS Community Database (VCDB) seed (no_agent, ZERO LLM tokens).

Seeds `incident` + `identity` pages from the open VERIS Community Database (github.com/vz-risk/VCDB) —
~10k validated, publicly-documented security incidents in VERIS format. BOUNDED: fetches the repo tree
once (1 GitHub API call), takes the most-recent N validated records, pulls each via the raw CDN. Each
incident page carries the victim (→ an `identity` page), the action categories (hacking/malware/misuse/
…), the actor kind, and the year — so the vault binds adversaries to real outcomes. no_agent,
deterministic JSON -> markdown, MERGE-safe.

License: VCDB is CC BY-SA 4.0 — pages stamp `sources: [VCDB]` + the record id.

Env: WIKI_PATH (/opt/vault) · VCDB_LIMIT (default 80) · GITHUB_TOKEN (optional, lifts the API limit)
Usage: vcdb_import.py [--limit N] [--vault DIR] [--dry-run]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _okf_write import content_root, slug, write_page   # noqa: E402
from naics_sector import naics_sector                    # noqa: E402

_TREE = "https://api.github.com/repos/vz-risk/VCDB/git/trees/master?recursive=1"
_RAW = "https://raw.githubusercontent.com/vz-risk/VCDB/master/"
_ACTIONS = ("malware", "hacking", "social", "misuse", "physical", "error", "environmental")


def _get(url: str, token: str | None) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "okpack-incidents/vcdb_import"})
    if token and "api.github.com" in url:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=90) as r:   # noqa: S310 (fixed https hosts)  # nosec B310 (fixed https upstream)
        return r.read()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--vault", default=os.environ.get("WIKI_PATH", "/opt/vault"))
    ap.add_argument("--limit", type=int, default=int(os.environ.get("VCDB_LIMIT", "80")))
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)
    vault = content_root(Path(args.vault))
    token = os.environ.get("GITHUB_TOKEN") or None

    try:
        tree = json.loads(_get(_TREE, token))
    except Exception as e:                               # noqa: BLE001 — best-effort seed lane
        print(f"ERROR: VCDB tree fetch failed: {e}", file=sys.stderr)
        return 1
    paths = sorted(n["path"] for n in (tree.get("tree") or [])
                   if n.get("type") == "blob"
                   and n["path"].startswith("data/json/validated/") and n["path"].endswith(".json"))
    # take the LAST N (the newest-added records) rather than the alphabetical head
    paths = paths[-max(1, args.limit):]

    incidents = idents = errs = 0
    seen_ids: set[str] = set()
    for rel in paths:
        try:
            d = json.loads(_get(_RAW + rel, token))
        except Exception as e:                           # noqa: BLE001
            errs += 1
            print(f"WARN: fetch {rel}: {e}", file=sys.stderr)
            continue
        iid = str(d.get("incident_id") or Path(rel).stem)
        victim = d.get("victim") or {}
        vname = str(victim.get("victim_id") or "").strip()
        year = ((d.get("timeline") or {}).get("incident") or {}).get("year")
        tl = (d.get("timeline") or {}).get("incident") or {}
        idate = (f"{tl['year']:04d}-{int(tl.get('month') or 1):02d}-{int(tl.get('day') or 1):02d}"
                 if tl.get("year") else None)
        actions = [a for a in _ACTIONS if a in (d.get("action") or {})]
        actor_kinds = list((d.get("actor") or {}).keys())
        vslug = slug(vname) if vname else None
        body = [f"# Incident {iid}", "", str(d.get("summary") or "").strip(), ""]
        if vname:
            body.append(f"- **Victim:** [[{vslug}]]" + (f" ({victim.get('industry')})" if victim.get("industry") else ""))
        if actions:
            body.append(f"- **Action:** {', '.join(actions)}")
        if actor_kinds:
            body.append(f"- **Actor:** {', '.join(actor_kinds)}")
        if year:
            body.append(f"- **Year:** {year}")
        body += ["", "> Seeded no_agent from the VERIS Community Database (CC BY-SA 4.0)."]
        fm = {"type": "incident", "id": f"incident:{iid}", "incident_id": iid,
              "title": (d.get("summary") or f"Incident {iid}")[:80],
              "incident_type": (actions[0] if actions else "unknown"),
              "incident_date": idate, "victim": vname or None,
              "action_categories": actions or None, "actor_kind": actor_kinds or None,
              "industry": victim.get("industry") or None,
              "sector": naics_sector(victim.get("industry")),
              "country": (victim.get("country") or [None])[0],
              "sources": ["VCDB"]}
        try:
            if write_page(vault, f"security-incidents/{year or '0000'}/{iid}.md",
                          {k: v for k, v in fm.items() if v not in (None, "", [])},
                          "\n".join(body), dry_run=args.dry_run) != "dry":
                incidents += 1
            if vslug and vslug not in seen_ids:
                seen_ids.add(vslug)
                if not args.dry_run:
                    write_page(vault, f"entities/{vslug[:1] or '_'}/{vslug}.md",
                               {"type": "identity", "id": vslug, "title": vname,
                                "identity_class": "government" if victim.get("government") not in (None, ["NA"]) else "organization",
                                "industry": victim.get("industry") or None,
                                "sector": naics_sector(victim.get("industry")),
                                "country": (victim.get("country") or [None])[0], "sources": ["VCDB"]},
                               f"# {vname}\n\nAn organization/party involved in recorded security incidents "
                               f"(VERIS Community Database). Referenced by the incidents it appears in.")
                    idents += 1
        except OSError as e:
            errs += 1
            print(f"WARN: write {iid}: {e}", file=sys.stderr)

    print(f"vcdb-import: {incidents} incident(s) + {idents} identity page(s) -> security-incidents/,entities/ "
          f"(of {len(paths)} pulled){f', {errs} error(s)' if errs else ''}")
    print(json.dumps({"wakeAgent": False}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
