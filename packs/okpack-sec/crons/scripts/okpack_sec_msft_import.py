#!/usr/bin/env python3
"""okpack-sec — Microsoft / Rosetta Stone threat-actor mapping importer (no_agent, ZERO LLM tokens).

Imports Microsoft's PublicFeeds `ThreatActorNaming/MicrosoftMapping.json` — the Microsoft +
CrowdStrike "Rosetta Stone" cross-vendor actor naming map (~160 actors: weather-suffix
Microsoft names + their "Other names" aliases) — as per-source `observations/microsoft/`
intrusion-set records (multi-source MDM; okengine#38).

This is the cross-vendor ALIAS BACKBONE: each record ties a Microsoft name (e.g.
"Aqua Blizzard") and its other names (Gamaredon, PRIMITIVE BEAR, APT44, …) to a canonical
entity, so a feed mention under ANY vendor's name resolves to one golden record. The
`Origin/Threat` column is split into a `suspected_origin` country (consensus-fused) and
`motivation` descriptors (union-fused). Deterministic JSON -> markdown; no agent. The
mapping changes infrequently -> weekly.

Data + attribution: Microsoft Security threat-actor naming taxonomy, published under
github.com/microsoft/mstic (MIT). Each page records the source.

Usage: okpack_sec_msft_import.py [--src URL|PATH] [--vault DIR] [--dry-run]
Env: WIKI_PATH (default /opt/vault), OKPACK_SEC_MSFT_SRC (override the URL).
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

MSFT_URL = ("https://raw.githubusercontent.com/microsoft/mstic/master/"
            "PublicFeeds/ThreatActorNaming/MicrosoftMapping.json")
# The maintained human-readable naming taxonomy (per-actor URLs are not in the feed).
MSFT_NAMING_URL = ("https://learn.microsoft.com/en-us/unified-secops-platform/"
                   "microsoft-threat-actor-naming")

SOURCE = "microsoft"   # source_registry key + observations/<SOURCE>/ subdir + `source:` stamp
_STRICT = False   # set in main() from --strict / OKPACK_STRICT_IMPORT; when on, a fetch/parse/write
                  # failure exits nonzero instead of best-effort skip (okpacks-library#16)

# `Origin/Threat` country tokens -> canonical origin string (full names, matching TGC so the
# assembler's consensus fuse sees the same value across sources).
_ORIGIN = {"China", "Russia", "Iran", "North Korea", "South Korea", "Lebanon", "Vietnam",
           "Israel", "Ukraine", "Pakistan", "Belarus", "United States", "India",
           "Austria", "Singapore", "United Arab Emirates", "Turkey"}
# Microsoft's bare "Korea" means South Korea (it lists DPRK separately as "North Korea"); map it
# to match TGC's "KR -> South Korea" so the assembler doesn't see a false cross-source conflict
# (okpacks-library#11). Türkiye -> Turkey likewise.
_ORIGIN_FIX = {"Korea": "South Korea", "Türkiye": "Turkey", "Turkiye": "Turkey"}
# Non-country `Origin/Threat` descriptors that map to a union-fused motivation line.
_MOTIVATION = {"Financially motivated": "financially motivated",
               "Influence operations": "influence operations",
               "Private sector offensive actor": "private sector offensive actor"}
# Pure record-nature markers (a tracking placeholder, not an attribute of the actor) — ignored:
#   "Group in development" (temporary Storm-#### designation), "Covert network".


def kebab(s: str) -> str:
    s = re.sub(r"[^\w\s-]", "", (s or "").lower())
    return re.sub(r"[\s_]+", "-", s).strip("-") or "x"


def split_origin_threat(s: str) -> tuple[str, list[str]]:
    """Microsoft's `Origin/Threat` is a comma list of a country and/or a category
    (e.g. 'China', 'Financially motivated', 'Russia, Influence operations'). Return
    (origin, motivations): the first country token, plus recognized motivation descriptors."""
    origin, motivations = "", []
    for tok in (t.strip() for t in (s or "").split(",")):
        if not tok:
            continue
        tok = _ORIGIN_FIX.get(tok, tok)
        if tok in _ORIGIN:
            origin = origin or tok
        elif tok in _MOTIVATION and _MOTIVATION[tok] not in motivations:
            motivations.append(_MOTIVATION[tok])
    return origin, motivations


def msft_records(data: list) -> list[dict]:
    """One record per actor: name, aliases (from 'Other names'), origin, motivation."""
    out = []
    for r in data:
        if not isinstance(r, dict):
            continue
        name = (r.get("Threat actor name") or "").strip()
        if not name:
            continue
        origin, motivation = split_origin_threat(r.get("Origin/Threat") or "")
        aliases, seen = [], set()
        for a in (r.get("Other names") or "").split(","):
            a = a.strip()
            k = a.lower()
            if a and k != name.lower() and k not in seen:
                seen.add(k)
                aliases.append(a)
        out.append({"name": name, "aliases": aliases, "origin": origin,
                    "motivation": motivation})
    return out


# ── observation mode (multi-source MDM; okengine#38) ─────────────────────────
def observation_path(vault: Path, slug: str) -> Path:
    return vault / "wiki" / "observations" / SOURCE / slug[0] / f"{slug}.md"


def _registry_reliability(vault: Path, default: str = "A") -> str:
    try:
        import yaml
        sch = yaml.safe_load((vault / "schema.yaml").read_text(encoding="utf-8")) or {}
        r = ((sch.get("source_registry") or {}).get(SOURCE) or {}).get("reliability")
        return str(r) if r else default
    except Exception:
        return default


def _summary_body(name: str, aliases: list[str], origin: str, motivation: list[str]) -> str:
    """A token-free one-line profile synthesized from the mapping row."""
    s = name
    aka = aliases[:8]
    if aka:
        s += " (aka " + ", ".join(aka) + ")"
    s += f" is a {origin}-based adversary group" if origin else " is a tracked adversary group"
    if motivation:
        s += ", " + ", ".join(motivation)
    s += ", per Microsoft's threat-actor naming taxonomy."
    return s


def render_observation(rec: dict, canonical_slug: str, reliability: str, today: str) -> str:
    """Microsoft's per-source record for an actor — its own view, never merged with others.
    `canonical` ties it to the golden record the assembler fuses into."""
    import yaml
    fm = {"type": "intrusion-set", "source": SOURCE, "reliability": reliability,
          "canonical": canonical_slug, "name": rec["name"], "tlp": "clear"}
    if rec["aliases"]:
        fm["aliases"] = rec["aliases"]
    if rec["origin"]:
        fm["suspected_origin"] = rec["origin"]
    if rec["motivation"]:
        fm["motivation"] = rec["motivation"]
    fm["refs"] = [{"std": "url", "id": rec["name"], "url": MSFT_NAMING_URL}]
    fm["last_updated"] = today
    fm["version"] = 1
    body = _summary_body(rec["name"], rec["aliases"], rec["origin"], rec["motivation"])
    note = ("\n\n> Microsoft threat-actor naming per-source record. Fused into the canonical "
            "by canonical_assemble; synthesis is maintained on the canonical page.")
    head = yaml.safe_dump(fm, sort_keys=False, allow_unicode=True,
                          default_flow_style=False).rstrip("\n")
    return "---\n" + head + "\n---\n" + body + note + "\n"


def import_observations(data: list, vault: Path, today: str, dry_run: bool = False) -> dict:
    """Write one observations/microsoft/<slug>.md per actor. The canonical slug is resolved by
    alias-match against existing canonical entities; otherwise minted from the Microsoft name.
    Files are written under the source's OWN slug, so distinct records never collide (the
    assembler groups by `canonical:`). Idempotent; no merge."""
    import mdm_resolve
    idx = mdm_resolve.build_canonical_index(vault, {"intrusion-set"})
    trusted = mdm_resolve.load_trusted_coref(vault)   # prior Microsoft records vouch their aliases
    reliability = _registry_reliability(vault)
    counts = {"written": 0, "total": 0, "flagged": 0}
    for rec in msft_records(data):
        counts["total"] += 1
        # over-merge-guarded resolve (okengine#39): merge only on primary-name or >=2 shared
        # keys; a lone shared alias mints a distinct canonical and is flagged for review unless
        # the Microsoft co-reference seed vouches for it.
        src_slug = kebab(rec["name"]).lower()
        res = mdm_resolve.resolve(idx, rec["name"], rec["aliases"], trusted)
        canonical = res.slug if res.merged else src_slug
        if not res.merged and res.evidence == "single-alias" and res.ambiguous:
            mdm_resolve.flag_over_merge(vault, src_slug, rec["name"], res.ambiguous, SOURCE, today)
            counts["flagged"] += 1
        p = observation_path(vault, src_slug)
        try:
            if not dry_run:
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(render_observation(rec, canonical, reliability, today),
                             encoding="utf-8")
        except OSError:
            if _STRICT:
                raise
            continue
        counts["written"] += 1
    return counts


def load_mapping(src: str) -> list:
    if "://" not in src:
        data = json.loads(Path(src).read_text(encoding="utf-8"))
    else:
        req = urllib.request.Request(src, headers={"User-Agent": "okpack-sec-msft-import"})
        with urllib.request.urlopen(req, timeout=120) as r:   # noqa: S310 (trusted GitHub raw host)
            data = json.loads(r.read().decode("utf-8"))
    if isinstance(data, dict):           # tolerate a future {"actors": [...]} wrapper
        for v in data.values():
            if isinstance(v, list):
                return v
        return []
    return data if isinstance(data, list) else []


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Import the Microsoft / Rosetta Stone threat-actor mapping (no_agent).")
    ap.add_argument("--src", default=os.environ.get("OKPACK_SEC_MSFT_SRC") or MSFT_URL)
    ap.add_argument("--vault", default=os.environ.get("WIKI_PATH", "/opt/vault"))
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--strict", action="store_true",
                    help="exit nonzero on fetch/parse/write failure instead of best-effort skip "
                         "(also OKPACK_STRICT_IMPORT=1); default is best-effort for scheduled crons")
    args = ap.parse_args(argv)
    global _STRICT
    _STRICT = bool(args.strict or os.environ.get("OKPACK_STRICT_IMPORT"))
    _started = datetime.now(timezone.utc)
    try:
        data = load_mapping(args.src)
    except Exception as e:  # noqa: BLE001 — best-effort by default; strict -> nonzero
        print(f"msft-import: {'ERROR' if _STRICT else 'WARN'} could not load mapping ({e})"
              f"{'' if _STRICT else ' — skipping this run'}", file=sys.stderr)
        record_run(args.vault, "msft", _started, "failed" if _STRICT else "degraded",
                   error=str(e), dry_run=getattr(args, "dry_run", False))
        return 1 if _STRICT else 0
    today = date.today().isoformat()
    c = import_observations(data, Path(args.vault), today, args.dry_run)
    print(f"msft-import[obs]: {c['total']} Microsoft actors -> {c['written']} "
          f"observations/{SOURCE}/ ({c.get('flagged', 0)} over-merge-flagged)"
          f"{' [dry-run]' if args.dry_run else ''}")
    record_run(args.vault, "msft", _started, "success", counts=c, dry_run=args.dry_run)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
