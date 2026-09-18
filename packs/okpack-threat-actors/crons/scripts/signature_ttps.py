#!/usr/bin/env python3
"""okpack-threat-actors — signature-TTP profiling (no_agent, ZERO LLM tokens).

The INVERSE of actor_correlation. Correlation asks "who shares tradecraft?"; this asks "what is
DISTINCTIVE about this actor?" — the techniques it uses that few others do (low document-frequency /
high idf). Those rare TTPs are the detection-engineering signal: hunt for THESE to catch THIS actor.

Writes `signature_techniques` (frontmatter) + a `distinctiveness_score` (mean idf of the actor's
techniques — actors with lots of rare tradecraft score high) + a `## Signature tradecraft` body
section citing each technique's rarity (used by N of M actors). MERGE-writes (never clobbers other
lanes' fields). Reuses actor_correlation.load_actors so the graph reader stays in one place.

Env: WIKI_PATH (/opt/vault) · SIG_TOP_K (10) · SIG_MAX_SHARE (0.25 = a signature TTP is used by
     <=25% of actors) · SIG_MIN_TECHNIQUES (4 = skip actors with too little tradecraft to profile)
Usage: signature_ttps.py [--vault DIR] [--top-k N] [--dry-run]
"""
from __future__ import annotations

import argparse
import json
import math
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _okf_write import content_root, write_page          # noqa: E402
from actor_correlation import load_actors  # reuse the proven graph loader  # noqa: E402


def _techniques(feat: set) -> set:
    return {f[2:] for f in feat if f.startswith("T:")}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--vault", default=os.environ.get("WIKI_PATH", "/opt/vault"))
    ap.add_argument("--top-k", type=int, default=int(os.environ.get("SIG_TOP_K", "10")))
    ap.add_argument("--max-share", type=float, default=float(os.environ.get("SIG_MAX_SHARE", "0.25")))
    ap.add_argument("--min-techniques", type=int, default=int(os.environ.get("SIG_MIN_TECHNIQUES", "4")))
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)
    vault = content_root(Path(args.vault))

    actors = load_actors(vault)
    n = len(actors)
    if n < 3:
        print(f"signature-ttps: only {n} actor(s) with tradecraft — nothing to profile yet")
        print(json.dumps({"wakeAgent": False}))
        return 0

    # document frequency of each technique across actors
    df: dict[str, int] = {}
    for a in actors.values():
        for t in _techniques(a["features"]):
            df[t] = df.get(t, 0) + 1
    max_sharers = max(2, int(n * args.max_share))     # a "signature" TTP is used by few actors

    profiled = errs = 0
    for rel, a in actors.items():
        techs = _techniques(a["features"])
        if len(techs) < args.min_techniques:
            continue
        # rank the actor's OWN techniques by rarity (ascending df); keep the rare ones
        ranked = sorted(techs, key=lambda t: df[t])
        signature = [t for t in ranked if df[t] <= max_sharers][:args.top_k]
        distinctiveness = round(sum(math.log(n / df[t]) for t in techs) / len(techs), 2)
        if not signature:
            continue
        body = ["## Signature tradecraft", "",
                "> Rare techniques few other tracked actors use (idf-ranked) — the distinctive "
                "detection-engineering signal for this actor. `distinctiveness` = mean rarity of all "
                "its techniques.", ""]
        for t in signature:
            # LINK each technique to its page (stem == attack_id, e.g. T1583.001) so the signature
            # is navigable and each technique shows this actor in its backlinks — not bold dead text.
            body.append(f"- [[techniques/{t}|{t}]] — used by {df[t]} of {n} tracked actors")
        try:
            _merge_signature(vault, rel, signature, distinctiveness, "\n".join(body), dry_run=args.dry_run)
            profiled += 1
        except OSError as e:
            errs += 1
            print(f"WARN: {rel}: {e}", file=sys.stderr)

    print(f"signature-ttps: {n} actors, {profiled} profiled (rarity-ranked)"
          f"{f', {errs} error(s)' if errs else ''}")
    print(json.dumps({"wakeAgent": False}))
    return 0


def _merge_signature(vault: Path, rel: str, signature: list, distinctiveness: float,
                     sig_body: str, *, dry_run: bool) -> None:
    """Set signature_techniques + distinctiveness_score frontmatter, replace the body section only."""
    path = vault / rel
    txt = path.read_text(encoding="utf-8")
    end = txt.find("\n---", 3)
    body = txt[end + 4:].lstrip("\n") if end != -1 else ""
    marker = "## Signature tradecraft"
    base = body.split(marker, 1)[0].rstrip() if marker in body else body.rstrip()
    new_body = f"{base}\n\n{sig_body}" if base else sig_body
    write_page(vault, rel, {"type": "actor", "signature_techniques": signature,
                            "distinctiveness_score": distinctiveness}, new_body, dry_run=dry_run)


if __name__ == "__main__":
    sys.exit(main())
