#!/usr/bin/env python3
"""okpack-sec — MITRE ATT&CK catalog importer (no_agent, ZERO LLM tokens).

Fetches the MITRE Enterprise ATT&CK STIX 2.1 bundle and writes the canonical
technique catalog as conformant `attack-pattern` pages. Deterministic STIX ->
markdown: no agent, no model calls. ATT&CK changes ~2-3x/year, so this runs weekly.

Idempotent + non-destructive: creates missing techniques, refreshes the
importer-owned frontmatter on existing ones, and NEVER clobbers agent-added body
sections (e.g. `## Used by` relationships) — only the frontmatter is rewritten.

Group bodies are additionally cleaned (no_agent; okpacks-library#9): MITRE's inline
attack.mitre.org markdown links become internal `[[wikilinks]]` and verbatim MITRE typos
are fixed — the deterministic half of actor-body synthesis (the sourced narrative half is #10).

Usage:
  okpack_sec_attack_import.py [--bundle URL|PATH] [--vault DIR] [--dry-run]
Env: WIKI_PATH (default /opt/vault), OKPACK_SEC_ATTACK_BUNDLE (override the URL).
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

ATTACK_URL = ("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
              "master/enterprise-attack/enterprise-attack.json")
_FM = re.compile(r"\A---[ \t]*\n(.*?\n)---[ \t]*\n?(.*)\Z", re.S)
_STRICT = False   # set in main() from --strict / OKPACK_STRICT_IMPORT; when on, a fetch/parse/write
                  # failure exits nonzero instead of best-effort skip (okpacks-library#16)


# ── pure transforms (unit-tested) ────────────────────────────────────────────
def kebab(s: str) -> str:
    s = re.sub(r"[^\w\s-]", "", (s or "").lower())
    return re.sub(r"[\s_]+", "-", s).strip("-") or "x"


def mitre_id_of(obj: dict) -> str | None:
    """The Txxxx external_id from the mitre-attack external reference."""
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return ref["external_id"]
    return None


def attack_url_of(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack" and ref.get("url"):
            return ref["url"]
    return None


def tactics_of(obj: dict) -> list[str]:
    return [p["phase_name"] for p in obj.get("kill_chain_phases", [])
            if p.get("kill_chain_name") in ("mitre-attack", "mitre-mobile-attack",
                                            "mitre-ics-attack") and p.get("phase_name")]


def is_deprecated(obj: dict) -> bool:
    return bool(obj.get("x_mitre_deprecated") or obj.get("revoked"))


def clean_description(text: str) -> str:
    """Strip MITRE's inline `(Citation: Name)` markers and tidy whitespace —
    they're reference bookkeeping, noise in the page prose."""
    text = re.sub(r"\(Citation:[^)]*\)", "", text or "")
    text = re.sub(r"[ \t]+\n", "\n", text)
    return re.sub(r"[ \t]{2,}", " ", text).strip()


# ── deterministic actor-body cleanup (no_agent; okpacks-library#9) ────────────
# MITRE descriptions link OUT to attack.mitre.org and carry a few verbatim typos. These are
# token-free text fixes (distinct from the sourced narrative synthesis, #10) applied to the
# group body the importer writes — so the canonical inherits internal links + clean prose.
_ATTACK_LINK = re.compile(r"\[([^\]]+)\]\((https?://attack\.mitre\.org/[^)]+)\)")
# link path categories the importers mint pages for -> resolvable as a [[wikilink]] (by slugified
# name against the vault graph). Anything else (tactics, data-sources, …) is de-linked to text.
_ENTITY_CATS = {"groups", "software", "techniques", "campaigns"}
# Known verbatim MITRE typos (conservative, unambiguous only — NOT a blanket spell-check):
# a missing article before "threat group/actor" (e.g. APT29: "is threat group").
_MITRE_TYPOS = [(re.compile(r"\bis threat (group|actor)\b"), r"is a threat \1")]


def internalize_attack_links(text: str, self_name: str = "") -> str:
    """Rewrite MITRE's inline `[Name](https://attack.mitre.org/<cat>/…)` markdown links to internal
    `[[Name]]` wikilinks (resolved by slugified name against the vault graph). A self-reference
    (link text == this page's name) is de-linked to plain text; a link to a non-entity category is
    de-linked too (kept readable, never a dangling link). No external attack.mitre.org link survives
    in the prose (the `attack_url:` frontmatter ref keeps the canonical source link)."""
    self_key = _norm(self_name)

    def repl(m: re.Match) -> str:
        label, url = m.group(1).strip(), m.group(2)
        cat = url.split("attack.mitre.org/", 1)[1].split("/", 1)[0]
        if self_key and _norm(label) == self_key:
            return label
        return f"[[{label}]]" if cat in _ENTITY_CATS else label

    return _ATTACK_LINK.sub(repl, text)


def fix_mitre_typos(text: str) -> str:
    for pat, rep in _MITRE_TYPOS:
        text = pat.sub(rep, text)
    return text


def polish_group_body(raw: str, name: str) -> str:
    """Citation-strip, internalize attack.mitre.org links, fix known MITRE typos — in that order
    (de-self-linking exposes the leading typo, e.g. '[APT29](…) is threat group' -> 'APT29 is a
    threat group')."""
    return fix_mitre_typos(internalize_attack_links(clean_description(raw), name))


def parse_attack_patterns(bundle: dict) -> list[dict]:
    """Extract technique records from a STIX bundle. Skips objects with no Txxxx id."""
    out = []
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        mid = mitre_id_of(obj)
        if not mid:
            continue
        out.append({
            "mitre_id": mid,
            "name": (obj.get("name") or mid).strip(),
            "description": clean_description(obj.get("description") or ""),
            "tactics": tactics_of(obj),
            "deprecated": is_deprecated(obj),
            "url": attack_url_of(obj) or f"https://attack.mitre.org/techniques/{mid.replace('.', '/')}",
            "is_subtechnique": bool(obj.get("x_mitre_is_subtechnique")),
        })
    return out


def page_slug(name: str, mitre_id: str) -> str:
    return f"{kebab(name)}-{mitre_id.lower().replace('.', '-')}"


def page_path(vault: str | os.PathLike, name: str, mitre_id: str) -> Path:
    slug = page_slug(name, mitre_id)
    return Path(vault) / "wiki" / "entities" / slug[0] / f"{slug}.md"


def _yaml_str(v: str) -> str:
    """Minimal scalar quoting for a frontmatter value."""
    if v == "" or re.search(r'[:#\[\]{}",&*!|>%@`]|^\s|\s$', v):
        return '"' + v.replace('\\', '\\\\').replace('"', '\\"') + '"'
    return v


def render_frontmatter(rec: dict, today: str) -> list[str]:
    """The importer-owned frontmatter lines (the canonical fields)."""
    lines = [
        "type: attack-pattern",
        f"mitre_id: {rec['mitre_id']}",
        f"name: {_yaml_str(rec['name'])}",
        "tlp: clear",
    ]
    if rec["tactics"]:
        lines.append("tactics: [" + ", ".join(rec["tactics"]) + "]")
    if rec["deprecated"]:
        lines.append("status: deprecated")
    lines.append(f"attack_url: {rec['url']}")
    lines.append(f"last_updated: '{today}'")
    return lines


def render_new_page(rec: dict, today: str) -> str:
    fm = render_frontmatter(rec, today) + ["version: 1"]
    body = rec["description"] or f"MITRE ATT&CK technique {rec['mitre_id']}."
    note = "\n\n> Canonical technique imported from MITRE ATT&CK Enterprise (STIX). " \
           "Relationship sections below are maintained by the ingest agent."
    return "---\n" + "\n".join(fm) + "\n---\n" + body + note + "\n"


# ── idempotent merge (frontmatter-only refresh; body preserved) ──────────────
def _split(text: str) -> tuple[str, str]:
    m = _FM.match(text)
    return (m.group(1), m.group(2)) if m else ("", text)


_TECH_OWNED = {"type", "mitre_id", "name", "tlp", "tactics", "status",
               "attack_url", "last_updated"}
_GROUP_OWNED = {"type", "mitre_id", "name", "aliases", "tlp", "status",
                "attack_url", "last_updated"}


def merge_owned(text: str, new_owned: list[str], owned_keys: set) -> str | None:
    """Replace the importer-owned frontmatter keys on an existing page; keep every
    other key and the whole body untouched (agent enrichment is preserved). Returns
    None when nothing but `last_updated` would change (so we skip the write)."""
    fm_text, body = _split(text)
    kept = [ln for ln in fm_text.splitlines()
            if ln.strip() and ln.split(":", 1)[0].strip() not in owned_keys]
    old_owned = [ln for ln in fm_text.splitlines()
                 if ln.split(":", 1)[0].strip() in owned_keys]
    sig = lambda ls: [x for x in ls if not x.startswith("last_updated")]  # noqa: E731
    if sig(old_owned) == sig(new_owned):
        return None
    return "---\n" + "\n".join(kept + new_owned) + "\n---\n" + body


def import_bundle(bundle: dict, vault: str | os.PathLike, today: str,
                  dry_run: bool = False, include_deprecated: bool = False) -> dict:
    counts = {"created": 0, "updated": 0, "unchanged": 0, "deprecated": 0,
              "skipped_deprecated": 0, "total": 0, "rels": 0}
    rels_by_slug = parse_relationships(bundle, _stix_index(bundle))   # subtechnique-of edges
    for rec in parse_attack_patterns(bundle):
        counts["total"] += 1
        if rec["deprecated"]:
            counts["deprecated"] += 1
        p = page_path(vault, rec["name"], rec["mitre_id"])
        rels = rels_by_slug.get(page_slug(rec["name"], rec["mitre_id"]), [])
        counts["rels"] += len(rels)
        # Skip seeding NEW pages for deprecated/revoked techniques (keep the
        # catalog current), but still flag an existing page if it's been
        # deprecated since — never silently drop content the agent enriched.
        if rec["deprecated"] and not include_deprecated and not p.exists():
            counts["skipped_deprecated"] += 1
            continue
        if p.exists():
            cur = p.read_text(encoding="utf-8", errors="replace")
            base = merge_owned(cur, render_frontmatter(rec, today), _TECH_OWNED) or cur
            final = _inject_assoc(base, rels)
            if final == cur:
                counts["unchanged"] += 1
                continue
            if not dry_run:
                p.write_text(final, encoding="utf-8")
            counts["updated"] += 1
        else:
            text = _inject_assoc(render_new_page(rec, today), rels)
            if not dry_run:
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(text, encoding="utf-8")
            counts["created"] += 1
    return counts


# ── groups (intrusion-set = named threat actors) ─────────────────────────────
def parse_groups(bundle: dict) -> list[dict]:
    out = []
    for obj in bundle.get("objects", []):
        if obj.get("type") != "intrusion-set":
            continue
        mid = mitre_id_of(obj)
        if not mid:
            continue
        name = (obj.get("name") or mid).strip()
        out.append({
            "mitre_id": mid,
            "name": name,
            # aliases minus the primary name — the high-value cross-reference set
            # (e.g. G0119 = Evil Corp = UNC2165 = DEV-0243) so feed mentions resolve.
            "aliases": [a.strip() for a in obj.get("aliases", [])
                        if a.strip() and a.strip() != name],
            # internalize attack.mitre.org links + fix verbatim typos (no_agent; #9)
            "description": polish_group_body(obj.get("description") or "", name),
            "deprecated": is_deprecated(obj),
            "url": attack_url_of(obj) or f"https://attack.mitre.org/groups/{mid}",
        })
    return out


def group_page_path(vault: str | os.PathLike, name: str) -> Path:
    slug = kebab(name)
    return Path(vault) / "wiki" / "entities" / slug[0] / f"{slug}.md"


def render_group_frontmatter(rec: dict, today: str) -> list[str]:
    lines = ["type: intrusion-set", f"mitre_id: {rec['mitre_id']}",
             f"name: {_yaml_str(rec['name'])}", "tlp: clear"]
    if rec["aliases"]:
        lines.append("aliases: [" + ", ".join(_yaml_str(a) for a in rec["aliases"]) + "]")
    if rec["deprecated"]:
        lines.append("status: deprecated")
    lines.append(f"attack_url: {rec['url']}")
    lines.append(f"last_updated: '{today}'")
    return lines


def render_new_group(rec: dict, today: str) -> str:
    fm = render_group_frontmatter(rec, today) + ["version: 1"]
    body = rec["description"] or f"MITRE ATT&CK group {rec['mitre_id']}."
    note = ("\n\n> Canonical adversary group imported from MITRE ATT&CK (STIX). "
            "Sightings/relationships below are maintained by the ingest agent.")
    return "---\n" + "\n".join(fm) + "\n---\n" + body + note + "\n"


def import_groups(bundle: dict, vault: str | os.PathLike, today: str,
                  dry_run: bool = False, include_deprecated: bool = False) -> dict:
    counts = {"created": 0, "updated": 0, "unchanged": 0, "skipped_deprecated": 0, "total": 0}
    for rec in parse_groups(bundle):
        counts["total"] += 1
        p = group_page_path(vault, rec["name"])
        if rec["deprecated"] and not include_deprecated and not p.exists():
            counts["skipped_deprecated"] += 1
            continue
        if p.exists():
            new = merge_owned(p.read_text(encoding="utf-8", errors="replace"),
                              render_group_frontmatter(rec, today), _GROUP_OWNED)
            if new is None:
                counts["unchanged"] += 1
                continue
            if not dry_run:
                p.write_text(new, encoding="utf-8")
            counts["updated"] += 1
        else:
            if not dry_run:
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(render_new_group(rec, today), encoding="utf-8")
            counts["created"] += 1
    return counts


# ── mitigations (course-of-action) ───────────────────────────────────────────
_MITI_OWNED = {"type", "mitre_id", "name", "tlp", "status", "attack_url", "last_updated"}


def parse_mitigations(bundle: dict) -> list[dict]:
    out = []
    for obj in bundle.get("objects", []):
        if obj.get("type") != "course-of-action":
            continue
        mid = mitre_id_of(obj)
        if not mid or not mid.startswith("M"):   # ATT&CK mitigations are M####
            continue
        out.append({
            "mitre_id": mid,
            "name": (obj.get("name") or mid).strip(),
            "description": clean_description(obj.get("description") or ""),
            "deprecated": is_deprecated(obj),
            "url": attack_url_of(obj) or f"https://attack.mitre.org/mitigations/{mid}",
        })
    return out


def mitigation_page_path(vault: str | os.PathLike, name: str, mitre_id: str) -> Path:
    slug = f"{kebab(name)}-{mitre_id.lower()}"
    return Path(vault) / "wiki" / "entities" / slug[0] / f"{slug}.md"


def render_mitigation_frontmatter(rec: dict, today: str) -> list[str]:
    lines = ["type: course-of-action", f"mitre_id: {rec['mitre_id']}",
             f"name: {_yaml_str(rec['name'])}", "tlp: clear"]
    if rec["deprecated"]:
        lines.append("status: deprecated")
    lines += [f"attack_url: {rec['url']}", f"last_updated: '{today}'"]
    return lines


def render_new_mitigation(rec: dict, today: str) -> str:
    fm = render_mitigation_frontmatter(rec, today) + ["version: 1"]
    body = rec["description"] or f"MITRE ATT&CK mitigation {rec['mitre_id']}."
    note = ("\n\n> Canonical mitigation imported from MITRE ATT&CK (STIX). "
            "Relationships below are maintained by the ingest agent.")
    return "---\n" + "\n".join(fm) + "\n---\n" + body + note + "\n"


def import_mitigations(bundle: dict, vault: str | os.PathLike, today: str,
                       dry_run: bool = False, include_deprecated: bool = False) -> dict:
    counts = {"created": 0, "updated": 0, "unchanged": 0, "skipped_deprecated": 0,
              "total": 0, "rels": 0}
    rels_by_slug = parse_relationships(bundle, _stix_index(bundle))   # mitigates -> technique
    for rec in parse_mitigations(bundle):
        counts["total"] += 1
        slug = f"{kebab(rec['name'])}-{rec['mitre_id'].lower()}"   # == mitigation_page_path slug
        rels = rels_by_slug.get(slug, [])
        counts["rels"] += len(rels)
        p = mitigation_page_path(vault, rec["name"], rec["mitre_id"])
        if rec["deprecated"] and not include_deprecated and not p.exists():
            counts["skipped_deprecated"] += 1
            continue
        if p.exists():
            cur = p.read_text(encoding="utf-8", errors="replace")
            base = merge_owned(cur, render_mitigation_frontmatter(rec, today), _MITI_OWNED) or cur
            final = _inject_assoc(base, rels)        # render/refresh the `mitigates` section
            if final == cur:
                counts["unchanged"] += 1
                continue
            if not dry_run:
                p.write_text(final, encoding="utf-8")
            counts["updated"] += 1
        else:
            text = _inject_assoc(render_new_mitigation(rec, today), rels)
            if not dry_run:
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(text, encoding="utf-8")
            counts["created"] += 1
    return counts


# ── software (malware + tool) — so group `uses` relationships resolve (#38 "A2") ──
# `type` is intentionally NOT owned: a page may already be typed by ThaiCERT (malware vs
# tool can differ between sources) and the importer must not retype it — only seed on create.
_SOFTWARE_OWNED = {"mitre_id", "name", "aliases", "tlp", "status", "attack_url", "last_updated"}


def parse_software(bundle: dict) -> list[dict]:
    """MITRE `malware` + `tool` objects -> records keyed by Sxxxx id (slug = kebab(name),
    matching the relationship target slugs the assembler links to)."""
    out = []
    for o in bundle.get("objects", []):
        t = o.get("type")
        if t not in ("malware", "tool"):
            continue
        mid, name = mitre_id_of(o), (o.get("name") or "").strip()
        if not mid or not name:
            continue
        aliases = [a.strip() for a in (o.get("x_mitre_aliases") or [])
                   if a.strip() and a.strip() != name]
        out.append({"mitre_id": mid, "name": name, "sw_type": t, "aliases": aliases,
                    "description": clean_description(o.get("description") or ""),
                    "deprecated": is_deprecated(o),
                    "url": attack_url_of(o) or f"https://attack.mitre.org/software/{mid}"})
    return out


def _software_owned_lines(rec: dict, today: str) -> list[str]:
    lines = [f"mitre_id: {rec['mitre_id']}", f"name: {_yaml_str(rec['name'])}", "tlp: clear"]
    if rec["aliases"]:
        lines.append("aliases: [" + ", ".join(_yaml_str(a) for a in rec["aliases"]) + "]")
    if rec["deprecated"]:
        lines.append("status: deprecated")
    lines.append(f"attack_url: {rec['url']}")
    lines.append(f"last_updated: '{today}'")
    return lines


def render_new_software(rec: dict, today: str) -> str:
    fm = [f"type: {rec['sw_type']}"] + _software_owned_lines(rec, today) + ["version: 1"]
    body = (rec["description"] or f"{rec['name']} is a {rec['sw_type']} tracked by MITRE ATT&CK.").strip()
    note = ("\n\n> Imported from MITRE ATT&CK (STIX). Sightings/relationships maintained "
            "by the ingest agent.")
    return "---\n" + "\n".join(fm) + "\n---\n" + body + note + "\n"


def import_software(bundle: dict, vault: str | os.PathLike, today: str,
                    dry_run: bool = False, include_deprecated: bool = False) -> dict:
    counts = {"created": 0, "updated": 0, "unchanged": 0, "skipped_deprecated": 0,
              "total": 0, "rels": 0}
    rels_by_slug = parse_relationships(bundle, _stix_index(bundle))   # malware/tool uses technique
    for rec in parse_software(bundle):
        counts["total"] += 1
        p = group_page_path(vault, rec["name"])   # generic kebab(name) -> entities/<l>/<slug>
        rels = rels_by_slug.get(kebab(rec["name"]), [])
        counts["rels"] += len(rels)
        if rec["deprecated"] and not include_deprecated and not p.exists():
            counts["skipped_deprecated"] += 1
            continue
        if p.exists():
            cur = p.read_text(encoding="utf-8", errors="replace")
            base = merge_owned(cur, _software_owned_lines(rec, today), _SOFTWARE_OWNED) or cur
            final = _inject_assoc(base, rels)
            if final == cur:
                counts["unchanged"] += 1
                continue
            if not dry_run:
                p.write_text(final, encoding="utf-8")
            counts["updated"] += 1
        else:
            text = _inject_assoc(render_new_software(rec, today), rels)
            if not dry_run:
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(text, encoding="utf-8")
            counts["created"] += 1
    return counts


# ── fetch + CLI ──────────────────────────────────────────────────────────────
def load_bundle(src: str) -> dict:
    if "://" not in src:
        return json.loads(Path(src).read_text(encoding="utf-8"))
    req = urllib.request.Request(src, headers={"User-Agent": "okpack-sec-attack-import"})
    with urllib.request.urlopen(req, timeout=120) as r:   # noqa: S310 (trusted MITRE host)  # nosec B310
        return json.loads(r.read().decode("utf-8"))


# ── observation mode: groups -> observations/mitre-attack/ (multi-source MDM; #38) ──
SOURCE = "mitre-attack"   # source_registry key + observations/<SOURCE>/ subdir + `source:` stamp


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


def _registry_reliability(vault: str | os.PathLike, default: str = "A") -> str:
    try:
        import yaml
        sch = yaml.safe_load((Path(vault) / "schema.yaml").read_text(encoding="utf-8")) or {}
        r = ((sch.get("source_registry") or {}).get(SOURCE) or {}).get("reliability")
        return str(r) if r else default
    except Exception:
        return default


# ── ATT&CK relationship graph (group --uses--> technique/malware/tool; #38 "A") ──
# (STIX relationship_type, source type, target type) -> okf predicate. Extend here to import
# more edges (okengine#44). Actor `uses` edges render on the canonical via the assembler;
# non-actor edges (e.g. `mitigates`) render on their own page in the importer (_inject_assoc).
_REL_PRED = {
    ("uses", "intrusion-set", "attack-pattern"): "uses-technique",
    ("uses", "intrusion-set", "malware"): "uses-malware",
    ("uses", "intrusion-set", "tool"): "uses-tool",
    ("uses", "malware", "attack-pattern"): "uses-technique",
    ("uses", "tool", "attack-pattern"): "uses-technique",
    ("mitigates", "course-of-action", "attack-pattern"): "mitigates",
    ("subtechnique-of", "attack-pattern", "attack-pattern"): "subtechnique-of",
}
_PRED_LABEL = {"uses-technique": "Uses techniques", "uses-malware": "Uses malware",
               "uses-tool": "Uses tools", "mitigates": "Mitigates",
               "subtechnique-of": "Sub-technique of"}


def _stix_index(bundle: dict) -> dict:
    """{stix_id -> {type, name, slug}} for the object types a relationship can reference, so an
    edge resolves to the SAME page slug the importers write."""
    idx: dict = {}
    for o in bundle.get("objects", []):
        sid, t, name = o.get("id"), o.get("type"), (o.get("name") or "").strip()
        if not sid or not name or is_deprecated(o):
            continue
        if t == "attack-pattern":
            mid = mitre_id_of(o)
            if mid:
                idx[sid] = {"type": t, "name": name, "slug": page_slug(name, mid)}
        elif t == "course-of-action":
            mid = mitre_id_of(o)
            if mid and mid.startswith("M"):
                idx[sid] = {"type": t, "name": name, "slug": f"{kebab(name)}-{mid.lower()}"}
        elif t in ("malware", "tool", "intrusion-set"):
            idx[sid] = {"type": t, "name": name, "slug": kebab(name)}
    return idx


def parse_relationships(bundle: dict, idx: dict) -> dict:
    """{source_slug -> [{p, t, n}]} — STIX edges (per _REL_PRED) carrying the okf predicate,
    target page slug, and target name. Keyed by SOURCE slug so each importer looks up the edges
    for the entities it writes (actors -> uses; mitigations -> mitigates; …)."""
    out: dict = {}
    for o in bundle.get("objects", []):
        if o.get("type") != "relationship":
            continue
        src, tgt = idx.get(o.get("source_ref")), idx.get(o.get("target_ref"))
        if not src or not tgt:
            continue
        pred = _REL_PRED.get((o.get("relationship_type"), src["type"], tgt["type"]))
        if not pred:
            continue
        out.setdefault(src["slug"], []).append({"p": pred, "t": tgt["slug"], "n": tgt["name"]})
    return out


_ASSOC_HEAD = "## Associated (MITRE ATT&CK)"


def _assoc_section(rels: list) -> str:
    """Maintained body section listing relationship edges as internal [[entities/<slug>|name]]
    wikilinks, grouped by predicate (sourced — not fabricated). Mirrors the assembler."""
    by: dict = {}
    for r in rels or []:
        if isinstance(r, dict) and r.get("t"):
            by.setdefault(_PRED_LABEL.get(r.get("p"), "Related"), set()).add((r["t"], r.get("n") or r["t"]))
    if not by:
        return ""
    out = [_ASSOC_HEAD, ""]
    for label in sorted(by):
        items = sorted(by[label])
        out.append(f"**{label}** ({len(items)}): "
                   + ", ".join(f"[[entities/{t}|{n}]]" for t, n in items))
        out.append("")
    return "\n".join(out).rstrip() + "\n"


def _set_managed_section(body: str, head: str, section: str) -> str:
    body = re.sub(r"\n*" + re.escape(head) + r".*?(?=\n## |\Z)", "", body, flags=re.S).rstrip()
    return (body + "\n\n" + section.rstrip() + "\n") if section.strip() else (body.rstrip() + "\n")


def _inject_assoc(text: str, rels: list) -> str:
    """Set/replace the Associated section in a page body, preserving frontmatter + agent prose."""
    fm_text, body = _split(text)
    if not fm_text:
        return text
    new_body = _set_managed_section(body, _ASSOC_HEAD, _assoc_section(rels))
    return "---\n" + fm_text.rstrip("\n") + "\n---\n" + new_body


def render_group_observation(rec: dict, canonical_slug: str, reliability: str, today: str,
                             rels: list | None = None) -> str:
    import yaml
    fm = {"type": "intrusion-set", "source": SOURCE, "reliability": reliability,
          "canonical": canonical_slug, "name": rec["name"], "tlp": "clear"}
    if rec.get("aliases"):
        fm["aliases"] = rec["aliases"]
    fm["refs"] = [{"std": "mitre-attack", "id": rec["mitre_id"], "url": rec["url"]}]
    if rels:
        fm["mitre_rels"] = rels   # the assembler renders these as [[wikilinks]] on the canonical
    fm["last_updated"] = today
    fm["version"] = 1
    body = (rec.get("description") or f"{rec['name']} is a tracked adversary group.").strip()
    note = ("\n\n> MITRE ATT&CK per-source record. Fused into the canonical by "
            "canonical_assemble; synthesis is maintained on the canonical page.")
    head = yaml.safe_dump(fm, sort_keys=False, allow_unicode=True,
                          default_flow_style=False).rstrip("\n")
    return "---\n" + head + "\n---\n" + body + note + "\n"


def import_group_observations(bundle: dict, vault: str | os.PathLike, today: str,
                              dry_run: bool = False, include_deprecated: bool = False) -> dict:
    import mdm_resolve
    idx = mdm_resolve.build_canonical_index(vault, {"intrusion-set"})
    trusted = mdm_resolve.load_trusted_coref(vault)   # Microsoft mapping vouches cross-vendor aliases
    reliability = _registry_reliability(vault)
    rels_by_group = parse_relationships(bundle, _stix_index(bundle))   # group_slug -> uses-edges
    counts = {"written": 0, "total": 0, "skipped_deprecated": 0, "rels": 0, "flagged": 0}
    for rec in parse_groups(bundle):
        if rec.get("deprecated") and not include_deprecated:
            counts["skipped_deprecated"] += 1
            continue
        counts["total"] += 1
        # canonical slug = over-merge-guarded match against existing canonicals (okengine#39):
        # merge only on a primary-name match or >=2 shared keys; a lone shared alias mints a new
        # canonical and is flagged for review. File under the source's own slug so distinct source
        # records never collide (the assembler groups by `canonical:`).
        src_slug = kebab(rec["name"]).lower()
        res = mdm_resolve.resolve(idx, rec["name"], rec.get("aliases") or [], trusted)
        canonical = res.slug if res.merged else src_slug
        if not res.merged and res.evidence == "single-alias" and res.ambiguous:
            mdm_resolve.flag_over_merge(vault, src_slug, rec["name"], res.ambiguous, SOURCE, today)
            counts["flagged"] += 1
        grels = rels_by_group.get(src_slug, [])
        counts["rels"] += len(grels)
        p = Path(vault) / "wiki" / "observations" / SOURCE / src_slug[0] / f"{src_slug}.md"
        try:
            if not dry_run:
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(render_group_observation(rec, canonical, reliability, today, grels),
                             encoding="utf-8")
        except OSError:
            if _STRICT:
                raise
            continue
        counts["written"] += 1
    return counts


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Import the MITRE ATT&CK catalog (no_agent).")
    ap.add_argument("--bundle", default=os.environ.get("OKPACK_SEC_ATTACK_BUNDLE") or ATTACK_URL)
    ap.add_argument("--vault", default=os.environ.get("WIKI_PATH", "/opt/vault"))
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--include-deprecated", action="store_true",
                    help="also seed pages for deprecated/revoked techniques")
    ap.add_argument("--observations", action="store_true",
                    help="write groups as per-source observations/mitre-attack/ (MDM; #38) "
                         "instead of legacy merge-in-place; techniques/mitigations unaffected")
    ap.add_argument("--strict", action="store_true",
                    help="exit nonzero on fetch/parse/write failure instead of best-effort skip "
                         "(also OKPACK_STRICT_IMPORT=1); default is best-effort for scheduled crons")
    args = ap.parse_args(argv)
    global _STRICT
    _STRICT = bool(args.strict or os.environ.get("OKPACK_STRICT_IMPORT"))
    _started = datetime.now(timezone.utc)
    try:
        bundle = load_bundle(args.bundle)
    except Exception as e:  # noqa: BLE001 — best-effort by default; strict -> nonzero
        print(f"attack-import: {'ERROR' if _STRICT else 'WARN'} could not load bundle ({e})"
              f"{'' if _STRICT else ' — skipping this run'}", file=sys.stderr)
        record_run(args.vault, "attack", _started, "failed" if _STRICT else "degraded",
                   error=str(e), dry_run=getattr(args, "dry_run", False))
        return 1 if _STRICT else 0
    today = date.today().isoformat()
    if args.observations or os.environ.get("OKPACK_SEC_OBSERVATIONS"):
        # groups -> per-source observations (MDM overlay); techniques + mitigations are
        # single-source MITRE data and still seed entities/ directly (no overlay needed).
        gc = import_group_observations(bundle, args.vault, today, args.dry_run,
                                       args.include_deprecated)
        tech = import_bundle(bundle, args.vault, today, args.dry_run, args.include_deprecated)
        miti = import_mitigations(bundle, args.vault, today, args.dry_run, args.include_deprecated)
        sw = import_software(bundle, args.vault, today, args.dry_run, args.include_deprecated)
        tag = " [dry-run]" if args.dry_run else ""
        print(f"attack-import[obs]: {gc['total']} groups -> {gc['written']} observations/{SOURCE}/ "
              f"({gc.get('flagged', 0)} over-merge-flagged); "
              f"techniques created {tech['created']} ({tech.get('rels', 0)} subtechnique-edges), "
              f"mitigations created {miti['created']} ({miti.get('rels', 0)} mitigates-edges), "
              f"software created {sw['created']}/updated {sw['updated']} "
              f"({sw.get('rels', 0)} uses-edges){tag}")
        record_run(args.vault, "attack", _started, "success",
                   counts={"groups_obs": gc.get("written", 0),
                           "techniques": tech.get("total", 0),
                           "mitigations": miti.get("total", 0),
                           "software": sw.get("total", 0)},
                   dry_run=args.dry_run)
        return 0
    tech = import_bundle(bundle, args.vault, today, args.dry_run, args.include_deprecated)
    grp = import_groups(bundle, args.vault, today, args.dry_run, args.include_deprecated)
    miti = import_mitigations(bundle, args.vault, today, args.dry_run, args.include_deprecated)
    sw = import_software(bundle, args.vault, today, args.dry_run, args.include_deprecated)
    tag = " [dry-run]" if args.dry_run else ""
    for label, c in (("techniques", tech), ("groups (threat actors)", grp),
                     ("mitigations", miti), ("software (malware/tool)", sw)):
        edges = f", {c['rels']} edges" if c.get("rels") else ""
        print(f"attack-import: {c['total']} {label} — created {c['created']}, "
              f"updated {c['updated']}, unchanged {c['unchanged']}, "
              f"skipped {c['skipped_deprecated']} deprecated{edges}{tag}")
    record_run(args.vault, "attack", _started, "success",
               counts={"techniques": tech.get("total", 0), "groups": grp.get("total", 0),
                       "mitigations": miti.get("total", 0), "software": sw.get("total", 0)},
               dry_run=args.dry_run)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
