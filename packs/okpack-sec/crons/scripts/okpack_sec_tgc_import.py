#!/usr/bin/env python3
"""okpack-sec — ThaiCERT Threat Group Cards importer (no_agent, ZERO LLM tokens).

Imports ETDA/ThaiCERT's "Threat Group Cards" adversary encyclopedia (MISP-galaxy
JSON, ~514 actors / ~1,600 aliases) into `intrusion-set` pages. ENRICHES existing
groups (ATT&CK-imported or feed-derived) matched by name OR any alias — unioning
aliases and filling country/motivation/sectors without clobbering curated values —
and CREATES the many groups not yet in the vault. Deterministic JSON -> markdown;
no agent. Changes infrequently -> weekly.

Data + attribution: ThaiCERT/ETDA "Threat Group Cards: A Threat Actor Encyclopedia"
(https://apt.etda.or.th/), free for the community. Each page records the source.

Usage: okpack_sec_tgc_import.py [--src URL|PATH] [--vault DIR] [--dry-run]
Env: WIKI_PATH (default /opt/vault), OKPACK_SEC_TGC_SRC (override the URL).
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

TGC_URL ="https://apt.etda.or.th/cgi-bin/getmisp.cgi?o=g"
_FM = re.compile(r"\A---[ \t]*\n(.*?\n)---[ \t]*\n?(.*)\Z", re.S)
_STRICT = False   # set in main() from --strict / OKPACK_STRICT_IMPORT; when on, a fetch/parse or
                  # observation-write failure exits nonzero instead of best-effort skip (#16)
_OWNED = ("aliases", "suspected_origin", "motivation", "target_sectors",
          "tgc_card", "last_updated")
_ISO = {"CN": "China", "RU": "Russia", "IR": "Iran", "KP": "North Korea",
        "US": "United States", "IN": "India", "PK": "Pakistan", "LB": "Lebanon",
        "VN": "Vietnam", "KR": "South Korea", "IL": "Israel", "SY": "Syria",
        "TR": "Turkey", "AE": "United Arab Emirates", "GB": "United Kingdom",
        "FR": "France", "NG": "Nigeria", "RO": "Romania", "BR": "Brazil",
        "UA": "Ukraine", "BY": "Belarus", "SA": "Saudi Arabia"}


def _yaml_str(v: str) -> str:
    if v == "" or re.search(r'[:#\[\]{}",&*!|>%@`]|^\s|\s$', v):
        return '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return v


def _ylist(items) -> str:
    return "[" + ", ".join(_yaml_str(str(x)) for x in items) + "]"


def _read_fm(path: Path) -> dict:
    try:
        m = _FM.match(path.read_text(encoding="utf-8", errors="replace"))
    except OSError:
        return {}
    if not m:
        return {}
    try:
        import yaml
        d = yaml.safe_load(m.group(1))
        return d if isinstance(d, dict) else {}
    except Exception:
        return {}


def norm(s: str) -> str:
    """Match key: lowercase alphanumerics only, so 'APT 28' == 'APT28'."""
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


def _as_list(v) -> list[str]:
    if v is None:
        return []
    return [str(x).strip() for x in (v if isinstance(v, list) else [v]) if str(x).strip()]


def tgc_records(data: dict) -> list[dict]:
    out = []
    for v in data.get("values", []):
        name = (v.get("value") or "").strip()
        if not name:
            continue
        meta = v.get("meta", {}) or {}
        syns = [s for s in _as_list(meta.get("synonyms")) if s.lower() != name.lower()]
        cc = (meta.get("country") or "").strip().upper()
        refs = _as_list(meta.get("refs"))
        card = next((r for r in refs if "etda.or.th" in r), refs[0] if refs else "")
        out.append({
            "name": name,
            "aliases": syns,
            "origin": _ISO.get(cc, cc) if cc and cc != "[UNKNOWN]" else "",
            "motivation": ", ".join(_as_list(meta.get("motivation"))),
            "sectors": _as_list(meta.get("cfr-target-category")),
            "card": card,
        })
    return out


def kebab(s: str) -> str:
    s = re.sub(r"[^\w\s-]", "", (s or "").lower())
    return re.sub(r"[\s_]+", "-", s).strip("-") or "x"


def page_path(vault: Path, name: str) -> Path:
    slug = kebab(name)
    return vault / "wiki" / "entities" / slug[0] / f"{slug}.md"


def build_alias_index(vault: Path) -> dict[str, Path]:
    """{normalized name/alias -> page} over every intrusion-set page, so a TGC actor
    can be matched to an existing group by any of its names. First writer wins on a
    collision (rare)."""
    idx: dict[str, Path] = {}
    ents = vault / "wiki" / "entities"
    if not ents.is_dir():
        return idx
    for p in ents.rglob("*.md"):
        if p.name.startswith(("_", ".")):
            continue
        fm = _read_fm(p)
        if str(fm.get("type", "")).strip() != "intrusion-set":
            continue
        keys = [fm.get("name") or p.stem] + _as_list(fm.get("aliases"))
        for k in keys:
            idx.setdefault(norm(k), p)
    return idx


def _owned_lines(rec: dict, aliases: list[str], origin: str, motivation: str,
                 sectors: list[str], today: str) -> list[str]:
    lines = []
    if aliases:
        lines.append(f"aliases: {_ylist(sorted(aliases))}")
    if origin:
        lines.append(f"suspected_origin: {_yaml_str(origin)}")
    if motivation:
        lines.append(f"motivation: {_yaml_str(motivation)}")
    if sectors:
        lines.append(f"target_sectors: {_ylist(sectors)}")
    if rec["card"]:
        lines.append(f"tgc_card: {rec['card']}")
    lines.append(f"last_updated: '{today}'")
    return lines


_NOTE = ("\n\n> Imported no_agent from ThaiCERT/ETDA Threat Group Cards. "
         "Sightings/relationships below are maintained by the ingest agent.")
# Pages still carrying the old bare placeholder body are un-enriched and safe to upgrade
# in place to the synthesized summary below.
_STUB_MARK = "is a tracked adversary group catalogued by ThaiCERT"


def _summary_body(name: str, aliases: list[str], origin: str, motivation: str,
                  sectors: list[str], card: str) -> str:
    """A readable one-line profile synthesized from the TGC metadata (token-free), plus a
    link to the full ThaiCERT card — so the page reads as a summary, not a placeholder."""
    s = name
    aka = aliases[:6]
    if aka:
        s += " (aka " + ", ".join(aka) + ")"
    s += f" is a {origin}-based adversary group" if origin else " is a tracked adversary group"
    if motivation:
        s += " motivated by " + motivation[:1].lower() + motivation[1:]
    if sectors:
        s += ", observed targeting " + ", ".join(sectors[:8])
    s += "."
    if card:
        s += f"\n\nFull profile: [ThaiCERT Threat Group Card]({card})."
    return s


def render_new(rec: dict, today: str) -> str:
    fm = ["type: intrusion-set", f"name: {_yaml_str(rec['name'])}", "tlp: clear"]
    fm += _owned_lines(rec, rec["aliases"], rec["origin"], rec["motivation"],
                       rec["sectors"], today) + ["version: 1"]
    body = _summary_body(rec["name"], rec["aliases"], rec["origin"], rec["motivation"],
                         rec["sectors"], rec["card"])
    return "---\n" + "\n".join(fm) + "\n---\n" + body + _NOTE + "\n"


def merge_existing(text: str, rec: dict, today: str) -> str | None:
    """Enrich a matched intrusion-set: UNION aliases, FILL origin/motivation/sectors
    only when absent (never clobber curated values), set tgc_card. Preserve body +
    all other frontmatter. None if nothing changes."""
    m = _FM.match(text)
    fm_text, body = (m.group(1), m.group(2)) if m else ("", text)
    fm = _read_fm_from_text(fm_text)
    name = str(fm.get("name") or "")
    aliases = sorted({a for a in _as_list(fm.get("aliases")) + rec["aliases"]
                      if a.lower() != name.lower()})
    origin = fm.get("suspected_origin") or rec["origin"]            # fill-only
    motivation = fm.get("motivation") or rec["motivation"]          # fill-only
    sectors = _as_list(fm.get("target_sectors")) or rec["sectors"]  # fill-only
    new_owned = _owned_lines(rec, aliases, str(origin or ""), str(motivation or ""),
                             sectors, today)
    kept = [ln for ln in fm_text.splitlines()
            if ln.strip() and ln.split(":", 1)[0].strip() not in _OWNED]
    old_owned = [ln for ln in fm_text.splitlines()
                 if ln.split(":", 1)[0].strip() in _OWNED]
    sig = lambda ls: [x for x in ls if not x.startswith("last_updated")]  # noqa: E731
    # Upgrade a bare placeholder body to the synthesized summary — but ONLY when the page
    # carries no agent-added sections (a `## ` heading), so curated content is never lost.
    new_body = body
    if _STUB_MARK in body and "\n## " not in body:
        new_body = _summary_body(name or rec["name"], aliases, str(origin or ""),
                                 str(motivation or ""), sectors, rec["card"]) + _NOTE + "\n"
    if sig(old_owned) == sig(new_owned) and new_body == body:
        return None
    return "---\n" + "\n".join(kept + new_owned) + "\n---\n" + new_body


def _read_fm_from_text(fm_text: str) -> dict:
    try:
        import yaml
        d = yaml.safe_load(fm_text)
        return d if isinstance(d, dict) else {}
    except Exception:
        return {}


def import_tgc(data: dict, vault: Path, today: str, dry_run: bool = False) -> dict:
    idx = build_alias_index(vault)
    counts = {"enriched": 0, "created": 0, "unchanged": 0, "total": 0}
    for rec in tgc_records(data):
        counts["total"] += 1
        keys = [norm(rec["name"])] + [norm(a) for a in rec["aliases"]]
        match = next((idx[k] for k in keys if k in idx), None)
        if match:
            try:                       # tolerate concurrent reshelve/reshard moving the page
                cur = match.read_text(encoding="utf-8", errors="replace")
            except OSError:
                counts["unchanged"] += 1
                continue
            new = merge_existing(cur, rec, today)
            if new is None:
                counts["unchanged"] += 1
                continue
            try:
                if not dry_run:
                    match.write_text(new, encoding="utf-8")
            except OSError:
                counts["unchanged"] += 1
                continue
            counts["enriched"] += 1
        else:
            p = page_path(vault, rec["name"])
            if p.exists():            # same slug, different/no type — don't stomp it
                counts["unchanged"] += 1
                continue
            try:
                if not dry_run:
                    p.parent.mkdir(parents=True, exist_ok=True)
                    p.write_text(render_new(rec, today), encoding="utf-8")
            except OSError:
                counts["unchanged"] += 1
                continue
            counts["created"] += 1
            idx.setdefault(norm(rec["name"]), p)
            for a in rec["aliases"]:
                idx.setdefault(norm(a), p)
    return counts


def load_galaxy(src: str) -> dict:
    if "://" not in src:
        return json.loads(Path(src).read_text(encoding="utf-8"))
    req = urllib.request.Request(src, headers={"User-Agent": "okpack-sec-tgc-import"})
    with urllib.request.urlopen(req, timeout=120) as r:   # noqa: S310 (trusted ETDA host)  # nosec B310
        return json.loads(r.read().decode("utf-8"))


# ── observation mode (multi-source MDM; okengine#38) ─────────────────────────
SOURCE = "thaicert"   # source_registry key + observations/<SOURCE>/ subdir + `source:` stamp


def _registry_reliability(vault: Path, default: str = "B") -> str:
    try:
        import yaml
        sch = yaml.safe_load((vault / "schema.yaml").read_text(encoding="utf-8")) or {}
        r = ((sch.get("source_registry") or {}).get(SOURCE) or {}).get("reliability")
        return str(r) if r else default
    except Exception:
        return default


def observation_path(vault: Path, slug: str) -> Path:
    return vault / "wiki" / "observations" / SOURCE / slug[0] / f"{slug}.md"


def render_observation(rec: dict, canonical_slug: str, reliability: str, today: str) -> str:
    """ThaiCERT's per-source record for an actor — its own view, never merged with others.
    `canonical` ties it to the golden record the assembler fuses into."""
    import yaml
    fm = {"type": "intrusion-set", "source": SOURCE, "reliability": reliability,
          "canonical": canonical_slug, "name": rec["name"], "tlp": "clear"}
    if rec["aliases"]:
        fm["aliases"] = sorted(rec["aliases"])
    if rec["origin"]:
        fm["suspected_origin"] = rec["origin"]
    if rec["motivation"]:
        # multi-valued: store as a list so the assembler UNIONs across cards (the joined
        # string had different subsets per card and produced false conflicts)
        fm["motivation"] = [s.strip() for s in rec["motivation"].split(",") if s.strip()]
    if rec["sectors"]:
        fm["target_sectors"] = rec["sectors"]
    if rec["card"]:
        fm["refs"] = [{"std": "misp", "id": norm(rec["name"]), "url": rec["card"]}]
    fm["last_updated"] = today
    fm["version"] = 1
    body = _summary_body(rec["name"], rec["aliases"], rec["origin"], rec["motivation"],
                         rec["sectors"], rec["card"])
    head = yaml.safe_dump(fm, sort_keys=False, allow_unicode=True,
                          default_flow_style=False).rstrip("\n")
    return "---\n" + head + "\n---\n" + body + _NOTE + "\n"


def import_observations(data: dict, vault: Path, today: str, dry_run: bool = False) -> dict:
    """Write one observations/thaicert/<slug>.md per actor. The canonical slug is resolved by
    an over-merge-guarded match against existing canonicals (okengine#39): MITRE's APT29 and
    ThaiCERT's APT29 land on the same canonical (primary-name match), but a card that only
    shares a single ambiguous alias mints its own canonical and is flagged for review.
    Idempotent; no merge."""
    import mdm_resolve
    idx = mdm_resolve.build_canonical_index(vault, {"intrusion-set"})
    trusted = mdm_resolve.load_trusted_coref(vault)   # Microsoft mapping vouches cross-vendor aliases
    reliability = _registry_reliability(vault)
    counts = {"written": 0, "total": 0, "flagged": 0}
    for rec in tgc_records(data):
        counts["total"] += 1
        # Resolve the CANONICAL slug, but write the file under the SOURCE's OWN slug — so two
        # ThaiCERT cards that map to one canonical (e.g. APT29 + UNC3524) stay distinct files;
        # the assembler groups by `canonical:`.
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


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Import ThaiCERT Threat Group Cards (no_agent).")
    ap.add_argument("--src", default=os.environ.get("OKPACK_SEC_TGC_SRC") or TGC_URL)
    ap.add_argument("--vault", default=os.environ.get("WIKI_PATH", "/opt/vault"))
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--observations", action="store_true",
                    help="write per-source observations/thaicert/ (multi-source MDM; okengine#38) "
                         "instead of legacy merge-in-place into entities/")
    ap.add_argument("--strict", action="store_true",
                    help="exit nonzero on fetch/parse/write failure instead of best-effort skip "
                         "(also OKPACK_STRICT_IMPORT=1); default is best-effort for scheduled crons")
    args = ap.parse_args(argv)
    global _STRICT
    _STRICT = bool(args.strict or os.environ.get("OKPACK_STRICT_IMPORT"))
    _started = datetime.now(timezone.utc)
    try:
        data = load_galaxy(args.src)
    except Exception as e:  # noqa: BLE001 — best-effort by default; strict -> nonzero
        print(f"tgc-import: {'ERROR' if _STRICT else 'WARN'} could not load galaxy ({e})"
              f"{'' if _STRICT else ' — skipping this run'}", file=sys.stderr)
        record_run(args.vault, "tgc", _started, "failed" if _STRICT else "degraded",
                   error=str(e), dry_run=getattr(args, "dry_run", False))
        return 1 if _STRICT else 0
    today = date.today().isoformat()
    if args.observations or os.environ.get("OKPACK_SEC_OBSERVATIONS"):
        c = import_observations(data, Path(args.vault), today, args.dry_run)
        print(f"tgc-import[obs]: {c['total']} TGC actors -> {c['written']} "
              f"observations/{SOURCE}/ ({c.get('flagged', 0)} over-merge-flagged)"
              f"{' [dry-run]' if args.dry_run else ''}")
        record_run(args.vault, "tgc", _started, "success", counts=c, dry_run=args.dry_run)
        return 0
    c = import_tgc(data, Path(args.vault), today, args.dry_run)
    print(f"tgc-import: {c['total']} TGC actors — enriched {c['enriched']} existing, "
          f"created {c['created']} new, unchanged {c['unchanged']}"
          f"{' [dry-run]' if args.dry_run else ''}")
    record_run(args.vault, "tgc", _started, "success", counts=c, dry_run=args.dry_run)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
