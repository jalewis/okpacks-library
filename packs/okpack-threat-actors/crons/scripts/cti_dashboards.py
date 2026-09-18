#!/usr/bin/env python3
"""okpack-threat-actors — CTI research dashboards (no_agent, ZERO LLM tokens).

Generates the analyst-facing dashboard pages from the graph the ingest/analysis lanes build — no model
spend. Four views, each answering a real CTI question:
  1. actors-by-sector      — who targets my sector? (actor `target_sector` from MISP galaxy)
  2. attack-tactic-coverage — where in the kill chain is the tracked activity? (technique `tactic`)
  3. top-exploited-cves     — which KEV CVEs are tied to tracked actors, and how many? (the actor↔vuln
                              seam: actor→technique→exploits_cve, cross-referenced to okpack-vuln's KEV pages)
  4. top-tooling           — the landscape's most-used malware/tools, proprietary vs commodity
                              (shared_tooling's `used_by_count`/`sharing_class`)
All write to dashboards/ (generated, not curated). MERGE-safe / idempotent.

Env: WIKI_PATH (/opt/vault) · CTI_DASH_TOP (20 rows/section)
Usage: cti_dashboards.py [--vault DIR] [--dry-run]
"""
from __future__ import annotations

import argparse
import collections
import glob
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _okf_write import content_root, write_page  # noqa: E402

# ATT&CK Enterprise kill-chain order; unknown (mobile/ics) tactics append after.
_KILL_CHAIN = ["reconnaissance", "resource-development", "initial-access", "execution", "persistence",
               "privilege-escalation", "defense-evasion", "credential-access", "discovery",
               "lateral-movement", "collection", "command-and-control", "exfiltration", "impact"]


def _fm(p: str) -> dict:
    try:
        t = open(p, encoding="utf-8", errors="ignore").read()
    except OSError:
        return {}  # page moved/deleted by a concurrent lane mid-scan
    if not t.startswith("---"):
        return {}
    e = t.find("\n---", 3)
    try:
        d = yaml.safe_load(t[3:e]) if e > 0 else {}
    except yaml.YAMLError:
        d = {}
    return d if isinstance(d, dict) else {}


def _load(wiki: Path):
    def rd(sub):
        return {Path(p).stem: _fm(p) for p in glob.glob(f"{wiki}/{sub}/**/*.md", recursive=True)}
    ents = rd("entities")
    actors = {k: v for k, v in ents.items() if v.get("type") == "actor"}
    software = {k: v for k, v in ents.items() if v.get("type") in ("malware", "tool")}
    techs = rd("techniques")
    techs = {k: v for k, v in techs.items() if v.get("type") == "technique"}
    cves = rd("cves")
    return actors, software, techs, cves


def _name(fm: dict, slug: str) -> str:
    return fm.get("title") or slug


def _table(header: list[str], rows: list[list[str]]) -> list[str]:
    out = ["| " + " | ".join(header) + " |",
           "|" + "|".join("---" for _ in header) + "|"]
    out += ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]
    return out


def build(wiki: Path, top: int) -> list[tuple[str, dict, str]]:
    actors, software, techs, cves = _load(wiki)
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    pages = []

    # 1) actors by target sector
    by_sector: dict[str, list] = collections.defaultdict(list)
    for slug, a in actors.items():
        for s in (a.get("target_sector") or []):
            by_sector[str(s).lower()].append((int(a.get("recent_reports") or 0), _name(a, slug), slug))
    body = ["# Actors by target sector", "",
            "> Which tracked actors target each sector (from MISP-galaxy targeting data), most-recently-"
            "active first. Answers \"who threatens my sector.\"", ""]
    for sector, lst in sorted(by_sector.items(), key=lambda kv: -len(kv[1])):
        lst.sort(reverse=True)
        names = ", ".join(f"[[{s}|{n}]]" for _, n, s in lst[:top])
        body += [f"## {sector.title()}  ({len(lst)} actors)", "", names, ""]
    pages.append(("dashboards/actors-by-sector.md",
                  {"type": "dashboard", "id": "actors-by-sector", "title": "Actors by target sector",
                   "updated": today}, "\n".join(body)))

    # 2) ATT&CK tactic coverage
    tac_tech = collections.Counter()
    tech_tactics = {}
    for slug, t in techs.items():
        tacs = [str(x) for x in (t.get("tactic") or [])]
        tech_tactics[t.get("attack_id") or slug] = tacs
        for x in tacs:
            tac_tech[x] += 1
    tac_actors: dict[str, set] = collections.defaultdict(set)
    for slug, a in actors.items():
        for tid in (a.get("techniques") or []):
            for x in tech_tactics.get(str(tid), []):
                tac_actors[x].add(slug)
    ordered = [t for t in _KILL_CHAIN if t in tac_tech] + \
              [t for t in tac_tech if t not in _KILL_CHAIN]
    rows = [[i + 1, t.replace("-", " ").title(), tac_tech[t], len(tac_actors.get(t, ()))]
            for i, t in enumerate(ordered)]
    body = ["# ATT&CK tactic coverage", "",
            "> Tracked techniques + distinct actors per kill-chain tactic (Enterprise order). Where the "
            "adversary activity concentrates.", ""] + _table(["#", "Tactic", "Techniques", "Actors"], rows)
    pages.append(("dashboards/attack-tactic-coverage.md",
                  {"type": "dashboard", "id": "attack-tactic-coverage", "title": "ATT&CK tactic coverage",
                   "updated": today}, "\n".join(body)))

    # 3) top exploited CVEs by actor reach (actor -> technique -> exploits_cve, joined to KEV pages)
    tech_cves = {}
    for slug, t in techs.items():
        cs = [str(c).upper() for c in (t.get("exploits_cve") or [])]
        if cs:
            tech_cves[t.get("attack_id") or slug] = cs
    cve_actors: dict[str, set] = collections.defaultdict(set)
    for slug, a in actors.items():
        for tid in (a.get("techniques") or []):
            for c in tech_cves.get(str(tid), []):
                cve_actors[c].add(_name(a, slug))
    # also direct exploits_cve on any page (some actors/campaigns carry it)
    for slug, a in {**actors, **software}.items():
        for c in (a.get("exploits_cve") or []):
            cve_actors[str(c).upper()].add(_name(a, slug))
    rows = []
    for cve, actset in sorted(cve_actors.items(), key=lambda kv: -len(kv[1])):
        cfm = cves.get(cve, {})
        kev = "✓" if cfm.get("kev") else ""
        rw = "✓" if cfm.get("known_ransomware") else ""
        title = (cfm.get("title") or "")[:60]
        link = f"[[{cve}]]" if cfm else cve
        rows.append([link, len(actset), kev, rw, title])
    body = ["# Top exploited CVEs (by tracked-actor reach)", "",
            "> CVEs reachable through tracked actors' techniques, joined to CISA KEV (the actor↔vuln "
            "seam). `KEV` = in the Known-Exploited catalog; `RW` = known ransomware use. Prioritize the "
            "top rows for patching.", ""] + _table(["CVE", "Actor reach", "KEV", "RW", "Name"], rows[:top * 2])
    pages.append(("dashboards/top-exploited-cves.md",
                  {"type": "dashboard", "id": "top-exploited-cves", "title": "Top exploited CVEs",
                   "updated": today}, "\n".join(body)))

    # 4) most-used tooling (proprietary vs commodity)
    tooled = [(int(s.get("used_by_count") or 0), s.get("sharing_class") or "?", _name(s, k), k)
              for k, s in software.items() if s.get("used_by_count")]
    tooled.sort(reverse=True)
    rows = [[i + 1, f"[[{slug}|{name}]]", n, klass] for i, (n, klass, name, slug) in enumerate(tooled[:top * 2])]
    body = ["# Most-used malware & tools", "",
            "> Ranked by how many tracked actors use each — `commodity` (many actors: a shared/RaaS "
            "platform, weak attribution signal) vs `proprietary` (one or two actors: an identity signal). "
            "See shared_tooling.", ""] + _table(["#", "Tool", "Actors", "Class"], rows)
    pages.append(("dashboards/top-tooling.md",
                  {"type": "dashboard", "id": "top-tooling", "title": "Most-used malware & tools",
                   "updated": today}, "\n".join(body)))

    return pages


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--vault", default=os.environ.get("WIKI_PATH", "/opt/vault"))
    ap.add_argument("--top", type=int, default=int(os.environ.get("CTI_DASH_TOP", "20")))
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)
    wiki = content_root(Path(args.vault))

    n = errs = 0
    for rel, fm, body in build(wiki, args.top):
        try:
            write_page(wiki, rel, fm, body, dry_run=args.dry_run)
            n += 1
        except OSError as e:
            errs += 1
            print(f"WARN: {rel}: {e}", file=sys.stderr)
    print(f"cti-dashboards: {n} dashboard(s) written -> dashboards/{f', {errs} error(s)' if errs else ''}")
    print(json.dumps({"wakeAgent": False}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
