#!/usr/bin/env python3
"""okpack-threat-actors — shared-tooling / RaaS-affiliate disambiguation (no_agent, ZERO LLM tokens).

The honest fix for correlation's false-merge risk. Two actors sharing a tool means very different
things depending on the tool:
  * a malware used by MANY actors is a shared SERVICE (RaaS platform, commodity loader) -> the actors
    are AFFILIATES / coincidental, NOT one group;
  * a malware used by ONE or TWO actors is PROPRIETARY -> a real identity signal.

So this lane (a) classifies each malware/tool by how many actors use it — proprietary / shared /
commodity — stamping `sharing_class` + `used_by_count` on the software page; and (b) on each actor
page, lists the other actors it shares PROPRIETARY tooling with (the strong same-group lead, distinct
from technique-overlap correlation). Reuses actor_correlation.load_actors. MERGE-writes.

Env: WIKI_PATH (/opt/vault) · TOOL_PROPRIETARY_MAX (2) · TOOL_COMMODITY_MIN (8)
Usage: shared_tooling.py [--vault DIR] [--dry-run]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _okf_write import content_root, write_page          # noqa: E402
from actor_correlation import load_actors  # noqa: E402


def _software(feat: set) -> set:
    return {f[2:] for f in feat if f.startswith("S:")}


def index_software_pages(vault: Path) -> dict:
    """malware/tool page STEM (== the software slug used in actor `software:` lists) -> rel path."""
    idx = {}
    ent = vault / "entities"
    if not ent.exists():
        return idx
    for p in ent.rglob("*.md"):
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
        if isinstance(fm, dict) and fm.get("type") in ("malware", "tool"):
            idx[p.stem] = str(p.relative_to(vault))
    return idx


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--vault", default=os.environ.get("WIKI_PATH", "/opt/vault"))
    ap.add_argument("--proprietary-max", type=int, default=int(os.environ.get("TOOL_PROPRIETARY_MAX", "2")))
    ap.add_argument("--commodity-min", type=int, default=int(os.environ.get("TOOL_COMMODITY_MIN", "8")))
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)
    vault = content_root(Path(args.vault))

    actors = load_actors(vault)
    if len(actors) < 3:
        print(f"shared-tooling: only {len(actors)} actor(s) with tradecraft — nothing to classify yet")
        print(json.dumps({"wakeAgent": False}))
        return 0

    # software -> set of actor names that use it
    users: dict[str, set] = {}
    for a in actors.values():
        for s in _software(a["features"]):
            users.setdefault(s, set()).add(a["name"])

    def _klass(n: int) -> str:
        if n <= args.proprietary_max:
            return "proprietary"
        if n >= args.commodity_min:
            return "commodity"
        return "shared"

    # (a) classify each software page
    sw_idx = index_software_pages(vault)
    classified = errs = 0
    for slug, actor_set in users.items():
        rel = sw_idx.get(slug)
        if not rel:
            continue
        try:
            write_page(vault, rel, {"type": _page_type(vault / rel),
                                    "sharing_class": _klass(len(actor_set)),
                                    "used_by_count": len(actor_set)},
                       _keep_body(vault / rel), dry_run=args.dry_run)
            classified += 1
        except OSError as e:
            errs += 1
            print(f"WARN: {rel}: {e}", file=sys.stderr)

    # (b) actor <-> actor PROPRIETARY-tooling links (the strong same-group signal)
    proprietary = {s: u for s, u in users.items() if len(u) <= args.proprietary_max and len(u) > 1}
    by_actor: dict[str, dict] = {}
    for slug, actor_set in proprietary.items():
        for name in actor_set:
            for other in actor_set:
                if other != name:
                    by_actor.setdefault(name, {}).setdefault(other, []).append(slug)

    name_to_rel = {a["name"]: rel for rel, a in actors.items()}
    linked = 0
    for name, others in by_actor.items():
        rel = name_to_rel.get(name)
        if not rel:
            continue
        peers = sorted(others.items(), key=lambda kv: -len(kv[1]))
        body = ["## Shared proprietary tooling", "",
                "> Actors sharing malware/tools that FEW groups use — a strong same-group / close-relationship "
                "lead (commodity/RaaS tooling is excluded, so this is not coincidental overlap). A lead to "
                "verify, not a merge.", ""]
        for other, tools in peers:
            body.append(f"- **{other}** — via {', '.join(sorted(tools))}")
        try:
            _merge_shared(vault, rel, [o for o, _ in peers], "\n".join(body), dry_run=args.dry_run)
            linked += 1
        except OSError as e:
            errs += 1
            print(f"WARN: {rel}: {e}", file=sys.stderr)

    print(f"shared-tooling: {classified} software page(s) classified, {linked} actor(s) with "
          f"proprietary-tooling links{f', {errs} error(s)' if errs else ''}")
    print(json.dumps({"wakeAgent": False}))
    return 0


def _page_type(path: Path) -> str:
    txt = path.read_text(encoding="utf-8", errors="ignore")
    end = txt.find("\n---", 3)
    try:
        fm = yaml.safe_load(txt[3:end]) if end != -1 else {}
    except yaml.YAMLError:
        fm = {}
    return (fm or {}).get("type", "malware")


def _keep_body(path: Path) -> str:
    txt = path.read_text(encoding="utf-8")
    end = txt.find("\n---", 3)
    return txt[end + 4:].lstrip("\n") if end != -1 else ""


def _merge_shared(vault: Path, rel: str, peers: list, sh_body: str, *, dry_run: bool) -> None:
    path = vault / rel
    txt = path.read_text(encoding="utf-8")
    end = txt.find("\n---", 3)
    body = txt[end + 4:].lstrip("\n") if end != -1 else ""
    marker = "## Shared proprietary tooling"
    base = body.split(marker, 1)[0].rstrip() if marker in body else body.rstrip()
    new_body = f"{base}\n\n{sh_body}" if base else sh_body
    write_page(vault, rel, {"type": "actor", "shared_proprietary_tooling_with": peers},
               new_body, dry_run=dry_run)


if __name__ == "__main__":
    sys.exit(main())
