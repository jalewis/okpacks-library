#!/usr/bin/env python3
"""okpack-sec — ThaiCERT Threat Group Cards *Tools* importer (no_agent, ZERO LLM tokens).

Companion to okpack_sec_tgc_import.py (which imports the ETDA/ThaiCERT *actor*
encyclopedia). This imports the "Threat Group Cards - Tools" MISP-galaxy JSON
(~2,200 entries) into `malware` and `tool` pages:

  TGC category   ->  okf-sec type
  ------------       ------------
  Malware            malware
  Tools              tool
  Exploits           tool
  Other              (skipped — too generic to type)

ENRICHES existing malware/tool/software pages matched by name OR any alias —
unioning aliases, recording the TGC sub-type(s) and card URL without clobbering
curated values — and CREATES the many tools/families not yet in the vault.
Deterministic JSON -> markdown; no agent. Changes infrequently -> weekly.

The free-text TGC sub-type list (Backdoor / Loader / Credential stealer / …) is
stored in `malware_type` rather than `category`, because `category` is enum-checked
by the pack schema and these values are open vocabulary.

Data + attribution: ThaiCERT/ETDA "Threat Group Cards: A Threat Actor Encyclopedia"
(https://apt.etda.or.th/), free for the community. Each page records the source.

Usage: okpack_sec_tgc_tools_import.py [--src URL|PATH] [--vault DIR] [--dry-run]
Env: WIKI_PATH (default /opt/vault), OKPACK_SEC_TGC_TOOLS_SRC (override the URL).
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

TGC_URL ="https://apt.etda.or.th/cgi-bin/getmisp.cgi?o=t"
_FM = re.compile(r"\A---[ \t]*\n(.*?\n)---[ \t]*\n?(.*)\Z", re.S)
_STRICT = False   # set in main() from --strict / OKPACK_STRICT_IMPORT; when on, a fetch/parse or
                  # observation-write failure exits nonzero instead of best-effort skip (#16)
_OWNED = ("aliases", "malware_type", "tgc_card", "last_updated")
# TGC `category` -> okf-sec page type. "Other" is intentionally absent (skipped).
_CAT2TYPE = {"malware": "malware", "tools": "tool", "exploits": "tool"}
# Existing page types a TGC tool may already exist as (the "Malware & tooling" group).
_MATCH_TYPES = {"malware", "tool", "software"}


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
    return _read_fm_from_text(m.group(1))


def _read_fm_from_text(fm_text: str) -> dict:
    try:
        import yaml
        d = yaml.safe_load(fm_text)
        return d if isinstance(d, dict) else {}
    except Exception:
        return {}


def norm(s: str) -> str:
    """Match key: lowercase alphanumerics only, so 'Cobalt Strike' == 'CobaltStrike'."""
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


def _as_list(v) -> list[str]:
    if v is None:
        return []
    return [str(x).strip() for x in (v if isinstance(v, list) else [v]) if str(x).strip()]


def tgc_records(data: dict) -> list[dict]:
    """One record per importable tool/malware entry (Other category skipped)."""
    out = []
    for v in data.get("values", []):
        name = (v.get("value") or "").strip()
        if not name:
            continue
        meta = v.get("meta", {}) or {}
        cat = (meta.get("category") or "").strip().lower()
        typ = _CAT2TYPE.get(cat)
        if not typ:                       # "Other" / unknown -> skip
            continue
        syns = [s for s in _as_list(meta.get("synonyms")) if s.lower() != name.lower()]
        subtypes = _as_list(meta.get("type"))
        refs = _as_list(meta.get("refs"))
        card = next((r for r in refs if "etda.or.th" in r), refs[0] if refs else "")
        out.append({
            "name": name,
            "type": typ,
            "aliases": syns,
            "malware_type": subtypes,
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
    """{normalized name/alias -> page} over every malware/tool/software page, so a TGC
    tool can be matched to an existing page by any of its names. First writer wins on a
    collision (rare)."""
    idx: dict[str, Path] = {}
    ents = vault / "wiki" / "entities"
    if not ents.is_dir():
        return idx
    for p in ents.rglob("*.md"):
        if p.name.startswith(("_", ".")):
            continue
        fm = _read_fm(p)
        if str(fm.get("type", "")).strip() not in _MATCH_TYPES:
            continue
        keys = [fm.get("name") or p.stem] + _as_list(fm.get("aliases"))
        for k in keys:
            idx.setdefault(norm(k), p)
    return idx


def _owned_lines(rec: dict, aliases: list[str], malware_type: list[str],
                 today: str) -> list[str]:
    lines = []
    if aliases:
        lines.append(f"aliases: {_ylist(sorted(aliases))}")
    if malware_type:
        lines.append(f"malware_type: {_ylist(malware_type)}")
    if rec["card"]:
        lines.append(f"tgc_card: {rec['card']}")
    lines.append(f"last_updated: '{today}'")
    return lines


_NOTE = ("\n\n> Imported no_agent from ThaiCERT/ETDA Threat Group Cards (Tools). "
         "Sightings/relationships below are maintained by the ingest agent.")
# Pages still carrying the old bare placeholder body are un-enriched and safe to upgrade.
_STUB_MARK = "catalogued by ThaiCERT's Threat Group Cards"


def _summary_body(name: str, type_: str, aliases: list[str], malware_type: list[str],
                  card: str) -> str:
    """A readable one-line profile synthesized from the TGC metadata (token-free), plus a
    link to the full ThaiCERT card."""
    kind = "malware family" if type_ == "malware" else "tool"
    s = name
    aka = aliases[:6]
    if aka:
        s += " (aka " + ", ".join(aka) + ")"
    s += f" is a {kind}"
    if malware_type:
        s += " (" + ", ".join(malware_type[:4]) + ")"
    s += " tracked by ThaiCERT's Threat Group Cards."
    if card:
        s += f"\n\nFull profile: [ThaiCERT Threat Group Card]({card})."
    return s


def render_new(rec: dict, today: str) -> str:
    fm = [f"type: {rec['type']}", f"name: {_yaml_str(rec['name'])}", "tlp: clear"]
    fm += _owned_lines(rec, rec["aliases"], rec["malware_type"], today) + ["version: 1"]
    body = _summary_body(rec["name"], rec["type"], rec["aliases"], rec["malware_type"],
                         rec["card"])
    return "---\n" + "\n".join(fm) + "\n---\n" + body + _NOTE + "\n"


def merge_existing(text: str, rec: dict, today: str) -> str | None:
    """Enrich a matched malware/tool/software page: UNION aliases, FILL malware_type only
    when absent (never clobber curated values), set tgc_card. Preserve body + all other
    frontmatter (including the existing `type` — never retype). None if nothing changes."""
    m = _FM.match(text)
    fm_text, body = (m.group(1), m.group(2)) if m else ("", text)
    fm = _read_fm_from_text(fm_text)
    name = str(fm.get("name") or "")
    aliases = sorted({a for a in _as_list(fm.get("aliases")) + rec["aliases"]
                      if a.lower() != name.lower()})
    malware_type = _as_list(fm.get("malware_type")) or rec["malware_type"]   # fill-only
    new_owned = _owned_lines(rec, aliases, malware_type, today)
    kept = [ln for ln in fm_text.splitlines()
            if ln.strip() and ln.split(":", 1)[0].strip() not in _OWNED]
    old_owned = [ln for ln in fm_text.splitlines()
                 if ln.split(":", 1)[0].strip() in _OWNED]
    sig = lambda ls: [x for x in ls if not x.startswith("last_updated")]  # noqa: E731
    # Upgrade a bare placeholder body to the synthesized summary — never when the page
    # carries agent-added sections (a `## ` heading), so curated content is preserved.
    new_body = body
    if _STUB_MARK in body and "\n## " not in body:
        new_body = _summary_body(name or rec["name"], str(fm.get("type") or rec["type"]),
                                 aliases, malware_type, rec["card"]) + _NOTE + "\n"
    if sig(old_owned) == sig(new_owned) and new_body == body:
        return None
    return "---\n" + "\n".join(kept + new_owned) + "\n---\n" + new_body


def import_tgc_tools(data: dict, vault: Path, today: str, dry_run: bool = False) -> dict:
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
    req = urllib.request.Request(src, headers={"User-Agent": "okpack-sec-tgc-tools-import"})
    with urllib.request.urlopen(req, timeout=120) as r:   # noqa: S310 (trusted ETDA host)  # nosec B310
        return json.loads(r.read().decode("utf-8"))


# ── observation mode (multi-source MDM; okengine#38 / okpacks-library#6) ─────────────
SOURCE = "thaicert"   # source_registry key + observations/<SOURCE>/ subdir + `source:` stamp


def _registry_admiralty(vault: Path, default=("B", "3")) -> tuple[str, str]:
    """(reliability, credibility) for this source from schema.yaml `source_registry`."""
    rel, cred = default
    try:
        import yaml
        sch = yaml.safe_load((vault / "schema.yaml").read_text(encoding="utf-8")) or {}
        entry = (sch.get("source_registry") or {}).get(SOURCE) or {}
        rel = str(entry.get("reliability") or rel)
        cred = str(entry.get("credibility_default") or cred)
    except Exception:
        pass
    return rel, cred


def observation_path(vault: Path, slug: str) -> Path:
    return vault / "wiki" / "observations" / SOURCE / slug[0] / f"{slug}.md"


def render_observation(rec: dict, canonical_slug: str, reliability: str, credibility: str,
                       today: str) -> str:
    """ThaiCERT's per-source record for a malware/tool — never merged with others. `canonical`
    ties it to the golden record the assembler fuses into. `type` is the source's own view (a
    family may be malware to one source, tool to another)."""
    import yaml
    fm = {"type": rec["type"], "source": SOURCE, "reliability": reliability,
          "credibility": credibility, "canonical": canonical_slug, "name": rec["name"],
          "tlp": "clear"}
    if rec["aliases"]:
        fm["aliases"] = sorted(rec["aliases"])
    if rec["malware_type"]:
        fm["malware_type"] = rec["malware_type"]
    if rec["card"]:
        fm["refs"] = [{"std": "misp", "id": norm(rec["name"]), "url": rec["card"]}]
    fm["last_updated"] = today
    fm["version"] = 1
    body = _summary_body(rec["name"], rec["type"], rec["aliases"], rec["malware_type"], rec["card"])
    head = yaml.safe_dump(fm, sort_keys=False, allow_unicode=True,
                          default_flow_style=False).rstrip("\n")
    return "---\n" + head + "\n---\n" + body + _NOTE + "\n"


def import_observations(data: dict, vault: Path, today: str, dry_run: bool = False) -> dict:
    """Write one observations/thaicert/<slug>.md per tool/malware. Canonical resolved with the
    over-merge guard (okengine#39): a reused alias token across families mints a distinct canonical
    and flags it for review, rather than silently merging. Idempotent; no merge."""
    import mdm_resolve
    idx = mdm_resolve.build_canonical_index(vault, _MATCH_TYPES)
    trusted = mdm_resolve.load_trusted_coref(vault)
    reliability, credibility = _registry_admiralty(vault)
    counts = {"written": 0, "total": 0, "flagged": 0}
    for rec in tgc_records(data):
        counts["total"] += 1
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
                p.write_text(render_observation(rec, canonical, reliability, credibility, today),
                             encoding="utf-8")
        except OSError:
            if _STRICT:
                raise
            continue
        counts["written"] += 1
    return counts


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Import ThaiCERT Threat Group Cards Tools (no_agent).")
    ap.add_argument("--src", default=os.environ.get("OKPACK_SEC_TGC_TOOLS_SRC") or TGC_URL)
    ap.add_argument("--vault", default=os.environ.get("WIKI_PATH", "/opt/vault"))
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--observations", action="store_true",
                    help="write per-source observations/thaicert/ (MDM; okengine#38) instead of "
                         "legacy merge-in-place into entities/")
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
        print(f"tgc-tools-import: {'ERROR' if _STRICT else 'WARN'} could not load galaxy ({e})"
              f"{'' if _STRICT else ' — skipping this run'}", file=sys.stderr)
        record_run(args.vault, "tgc-tools", _started, "failed" if _STRICT else "degraded",
                   error=str(e), dry_run=getattr(args, "dry_run", False))
        return 1 if _STRICT else 0
    today = date.today().isoformat()
    if args.observations or os.environ.get("OKPACK_SEC_OBSERVATIONS"):
        c = import_observations(data, Path(args.vault), today, args.dry_run)
        print(f"tgc-tools-import[obs]: {c['total']} TGC tools -> {c['written']} observations/{SOURCE}/ "
              f"({c.get('flagged', 0)} over-merge-flagged){' [dry-run]' if args.dry_run else ''}")
        record_run(args.vault, "tgc-tools", _started, "success", counts=c, dry_run=args.dry_run)
        return 0
    c = import_tgc_tools(data, Path(args.vault), today, args.dry_run)
    print(f"tgc-tools-import: {c['total']} TGC tools — enriched {c['enriched']} existing, "
          f"created {c['created']} new, unchanged {c['unchanged']}"
          f"{' [dry-run]' if args.dry_run else ''}")
    record_run(args.vault, "tgc-tools", _started, "success", counts=c, dry_run=args.dry_run)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
