#!/usr/bin/env python3
"""okpack-threat-actors — actor↔actor correlation (no_agent, ZERO LLM tokens).

Finds candidate links between actors from SHARED tradecraft — but rarity-weighted, because naive
overlap is noise: everyone uses Cobalt Strike and T1566 (phishing). Weight each shared technique/
software by inverse document frequency (idf = ln(N / df)), so a shared RARE custom backdoor scores
high and a shared ubiquitous tool ≈ 0. The output is a low-trust, evidence-cited `related_actors`
block on each actor page (needs_review) — a research lead, NOT an attribution claim.

Reads the structured `techniques:` / `software:` / `target_sector:` frontmatter that attack_import
stamps on actor pages. Writes back via the MERGE-writer, so it never clobbers other lanes' fields.

Env: WIKI_PATH (/opt/vault) · CORR_MIN_SCORE (1.5) · CORR_TOP_K (6) · CORR_MIN_SHARED (2)
Usage: actor_correlation.py [--vault DIR] [--min-score F] [--top-k N] [--dry-run]
"""
from __future__ import annotations

import argparse
import json
import math
import os
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _okf_write import content_root, write_page  # noqa: E402


def load_actors(vault: Path) -> dict:
    """rel_path -> {name, features:set, sectors:set} for every type:actor page with tradecraft."""
    actors = {}
    ent = vault / "entities"
    if not ent.exists():
        return actors
    for p in ent.rglob("*.md"):
        txt = p.read_text(encoding="utf-8", errors="ignore")
        if not txt.startswith("---"):
            continue
        end = txt.find("\n---", 3)
        try:
            fm = yaml.safe_load(txt[3:end]) if end != -1 else None
        except yaml.YAMLError:
            fm = None
        if not isinstance(fm, dict) or fm.get("type") != "actor":
            continue
        feats = {f"T:{t}" for t in (fm.get("techniques") or [])} | \
                {f"S:{s}" for s in (fm.get("software") or [])}
        actors[str(p.relative_to(vault))] = {
            "name": fm.get("title") or fm.get("id") or p.stem,
            "features": feats,
            "sectors": {str(s).lower() for s in (fm.get("target_sector") or [])},
        }
    return {k: v for k, v in actors.items() if v["features"]}   # need tradecraft to correlate


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--vault", default=os.environ.get("WIKI_PATH", "/opt/vault"))
    ap.add_argument("--min-score", type=float, default=float(os.environ.get("CORR_MIN_SCORE", "1.5")))
    ap.add_argument("--top-k", type=int, default=int(os.environ.get("CORR_TOP_K", "6")))
    ap.add_argument("--min-shared", type=int, default=int(os.environ.get("CORR_MIN_SHARED", "2")))
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)
    vault = content_root(Path(args.vault))

    actors = load_actors(vault)
    n = len(actors)
    if n < 3:
        print(f"actor-correlation: only {n} actor(s) with tradecraft — nothing to correlate yet")
        print(json.dumps({"wakeAgent": False}))
        return 0

    # document frequency per feature -> idf (rare shared feature = strong signal)
    df: dict[str, int] = {}
    for a in actors.values():
        for f in a["features"]:
            df[f] = df.get(f, 0) + 1
    idf = {f: math.log(n / c) for f, c in df.items()}

    rels, errs = 0, 0
    for rel, a in actors.items():
        scored = []
        for orel, b in actors.items():
            if orel == rel:
                continue
            shared = a["features"] & b["features"]
            if len(shared) < args.min_shared:
                continue
            score = sum(idf[f] for f in shared)              # rarity-weighted overlap
            if a["sectors"] & b["sectors"]:
                score *= 1.15                                # small boost for shared targeting
            if score >= args.min_score:
                top = sorted(shared, key=lambda f: idf[f], reverse=True)[:5]
                # carry orel (the correlated actor's wiki key) so the body can LINK it, not just name it
                scored.append((score, b["name"], orel, [f.split(":", 1)[1] for f in top]))
        if not scored:
            continue
        scored.sort(reverse=True)
        related = [{"actor": name, "rel": orel[:-3] if orel.endswith(".md") else orel,
                    "score": round(s, 2), "shared": ev}
                   for s, name, orel, ev in scored[:args.top_k]]
        body_lines = ["## Correlated actors", "",
                      "> Rarity-weighted shared-tradecraft leads (idf-weighted). A research signal, "
                      "NOT an attribution claim — common tooling is discounted; verify before linking.", ""]
        for r in related:
            body_lines.append(f"- [[{r['rel']}|{r['actor']}]] (score {r['score']}) — "
                              f"shared: {', '.join(r['shared'])}")
        try:
            _merge_related(vault, rel, related, "\n".join(body_lines), dry_run=args.dry_run)
            rels += 1
        except OSError as e:
            errs += 1
            print(f"WARN: {rel}: {e}", file=sys.stderr)

    print(f"actor-correlation: {n} actors, {rels} with correlated leads (idf-weighted)"
          f"{f', {errs} error(s)' if errs else ''}")
    print(json.dumps({"wakeAgent": False}))
    return 0


def _merge_related(vault: Path, rel: str, related: list, corr_body: str, *, dry_run: bool) -> None:
    """Set related_actors frontmatter + replace the '## Correlated actors' body section only."""
    path = vault / rel
    txt = path.read_text(encoding="utf-8")
    end = txt.find("\n---", 3)
    body = txt[end + 4:].lstrip("\n") if end != -1 else ""
    marker = "## Correlated actors"
    base = body.split(marker, 1)[0].rstrip() if marker in body else body.rstrip()
    new_body = f"{base}\n\n{corr_body}" if base else corr_body
    # related_actors is a PRESERVE_IF_SET-adjacent field; pass it explicitly so the writer stores it.
    write_page(vault, rel, {"type": "actor", "related_actors": [r["actor"] for r in related]},
               new_body, dry_run=dry_run)


if __name__ == "__main__":
    sys.exit(main())
