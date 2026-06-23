#!/usr/bin/env python3
"""Validate the okpack-sec domain pack — parse + cross-consistency checks.

Runs with no engine checkout and no Docker: it only reads this pack. Catches the class of bug
that ships silently in a config/data pack — a YAML/JSON/OPML parse error, or drift between what
the crons write and what schema.yaml declares (e.g. a cron writing to a namespace that has no
partitioning/tier rule).

The common checks (parse, OPML/feeds, cron-jitter, namespace consistency, schema cross-drift,
human-only gates, namespace dirs) live in the shared validator lib, vendored beside this file as
`_pack_validate_lib.py` (canonical: scripts/pack_validate_lib.py; okpacks-library#17). okpack-sec
is the worked example of a RICH pack: it keeps its own stricter variants (type-alias-aware
type/enum/pack.yaml checks) plus page-tree checks (page enum values, refs shape, rels predicates,
IOC defang) and OKF-SEC-SPEC.md sync, then drives them from its own main().

Usage:
    python3 validate.py            # parse + consistency checks (offline, fast)
    python3 validate.py --fix      # regenerate drift-checked blocks (feed count + spec machine reference)
    python3 validate.py --probe    # HTTP-probe the suggested feeds in feeds.opml.example (network)

Exit 0 = all checks pass. Exit 1 = at least one FAIL (warnings never fail the run).
Dependency: PyYAML (schema.yaml). Everything else is stdlib.
"""
import argparse
import re
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))  # find the vendored lib next to us
import _pack_validate_lib as lib  # noqa: E402
from _pack_validate_lib import (  # noqa: E402  (shared common checks)
    ROOT, ROOT_WIKI_FILES, check_crons_jittered, check_feeds, check_human_only_gates,
    check_namespace_consistency, check_namespace_dirs_exist, check_parse,
    check_schema_consistency, cron_prompt_strings, fail, fails, fix_feed_count,
    probe_feeds, warn, warns,
)

# okpack-sec requires the findings namespace to stay human-only (regression guard) — the shared
# check_human_only_gates reads this module global from the lib.
lib.REQUIRED_HUMAN_ONLY = ["findings"]

# The spec carries a generated, drift-checked mirror of schema.yaml's machine contract
# (types, aliases, enums, field bindings) so the spelled-out values can never lie. CI fails
# if the block is stale; `python3 validate.py --fix` regenerates it. schema.yaml is the SoT.
SPEC_FILE = "OKF-SEC-SPEC.md"
GEN_BEGIN = "<!-- BEGIN GENERATED okf-sec machine reference (do not edit — `python3 validate.py --fix`) -->"
GEN_END = "<!-- END GENERATED okf-sec machine reference -->"
GEN_RE = re.compile(re.escape(GEN_BEGIN) + r".*?" + re.escape(GEN_END), re.S)


def render_machine_reference(schema: dict) -> str:
    """Render the authoritative types/aliases/enums/bindings block from schema.yaml.
    Deterministic (schema insertion order) so it diffs cleanly against the committed copy."""
    types = list((schema.get("types") or {}))
    aliases = schema.get("type_aliases") or {}
    enums = schema.get("enums") or {}
    field_enums = schema.get("field_enums") or {}
    out = [GEN_BEGIN, ""]
    if schema.get("okf_sec_version"):
        out.append(f"**okf-sec version** — `{schema['okf_sec_version']}`")
        out.append("")
    out.append("**Canonical types** — " + " · ".join(f"`{t}`" for t in types))
    out.append("")
    out.append("**Type aliases** — " + " · ".join(f"`{a}`→`{c}`" for a, c in aliases.items()))
    out.append("")
    out.append("**Enumerations** (*extensible* marked at the binding below)")
    for name, vals in enums.items():
        out.append(f"- `{name}`: " + " · ".join(f"`{v}`" for v in vals))
    out.append("")
    out.append("**Field → enum bindings**")
    for field, spec in field_enums.items():
        if not isinstance(spec, dict):
            continue
        if "by_type" in spec:
            binding = ", ".join(f"`{t}`→`{en}`" for t, en in (spec.get("by_type") or {}).items())
        else:
            binding = f"`{spec.get('enum')}`"
        ext = " *(extensible)*" if spec.get("extensible") else ""
        out.append(f"- `{field}` → {binding}{ext}")
    lfe = schema.get("list_field_enums") or {}
    if lfe:
        out.append("")
        out.append("**List-of-object enum bindings**")
        for field, subspec in lfe.items():
            parts = []
            for sub, spec in subspec.items():
                en = spec.get("enum") if isinstance(spec, dict) else spec
                e = " *(ext)*" if isinstance(spec, dict) and spec.get("extensible") else ""
                parts.append(f"`{sub}`→`{en}`{e}")
            out.append(f"- `{field}[]`: " + ", ".join(parts))
    rv = schema.get("rels_vocabulary") or {}
    if rv:
        out.append("")
        out.append("**Relationship predicates** (`rels`)")
        for group, label in (("canonical", "canonical"), ("reverse", "reverse"), ("okf_native", "okf-native")):
            vals = rv.get(group) or []
            if vals:
                out.append(f"- {label}: " + " · ".join(f"`{v}`" for v in vals))
    out.append("")
    out.append(GEN_END)
    return "\n".join(out)


def fix_spec_reference(schema: dict) -> bool:
    """Regenerate the spec's machine-reference block from schema.yaml. Returns True if changed."""
    path = ROOT / SPEC_FILE
    if not path.exists():
        return False
    text = path.read_text()
    if GEN_BEGIN not in text or GEN_END not in text:
        return False  # markers must be placed by hand once
    new = GEN_RE.sub(lambda _m: render_machine_reference(schema), text, count=1)
    if new != text:
        path.write_text(new)
        print(f"FIXED  {SPEC_FILE} machine-reference block regenerated from schema.yaml")
        return True
    return False


def check_spec_sync(schema: dict) -> None:
    """Fail if the spec's generated machine-reference block has drifted from schema.yaml."""
    path = ROOT / SPEC_FILE
    if not path.exists():
        return
    text = path.read_text()
    if GEN_BEGIN not in text or GEN_END not in text:
        warn(f"{SPEC_FILE}: no generated machine-reference block (add the markers, then --fix)")
        return
    m = GEN_RE.search(text)
    current = (m.group(0) if m else "").strip()
    expected = render_machine_reference(schema).strip()
    if current != expected:
        fail(f"{SPEC_FILE} machine-reference block is stale vs schema.yaml "
             f"(run `python3 validate.py --fix`)")


def check_pack_yaml(schema: dict) -> None:
    """Shape-check pack.yaml (identity + composition) and keep `owns` in sync with schema.yaml.
    Full cross-pack composition validation happens at deploy across all installed packs."""
    path = ROOT / "pack.yaml"
    if not path.exists():
        warn("pack.yaml absent — recommended for composition (name/version/trust/owns)")
        return
    try:
        meta = yaml.safe_load(path.read_text())
    except Exception as e:  # noqa: BLE001
        fail(f"pack.yaml: invalid YAML — {e}")
        return
    if not isinstance(meta, dict):
        fail("pack.yaml: not a mapping")
        return
    for k in ("name", "version"):
        if not meta.get(k):
            fail(f"pack.yaml: missing '{k}'")
    if meta.get("trust") not in ("public", "private"):
        warn(f"pack.yaml: trust '{meta.get('trust')}' — should be public or private")
    owns = meta.get("owns") or {}
    if not (owns.get("types") or owns.get("namespaces")):
        warn("pack.yaml: owns declares no types/namespaces")
    # drift guard: owns must agree with schema.yaml
    schema_types = set(schema.get("types") or {})
    schema_ns = set((schema.get("partitioning") or {}).get("namespaces") or {})
    for t in sorted(set(owns.get("types") or []) - schema_types):
        fail(f"pack.yaml owns type '{t}' not in schema.yaml types")
    for n in sorted(set(owns.get("namespaces") or []) - schema_ns):
        fail(f"pack.yaml owns namespace '{n}' not in schema.yaml partitioning")
    for t in sorted(schema_types - set(owns.get("types") or [])):
        warn(f"schema type '{t}' is not declared in pack.yaml owns.types")


def check_type_consistency(schema: dict) -> None:
    """Every literal `type: X` a cron tells the agent to write must be a schema type
    (canonical or a declared alias). okpack-sec variant: aliases are accepted."""
    types = set(schema.get("types") or {})
    known = types | set(schema.get("type_aliases") or {})
    for prompt in cron_prompt_strings():
        for t in re.findall(r"type:\s+([a-z][a-z-]+)", prompt):
            if t not in known:
                fail(f"cron writes frontmatter `type: {t}` but it is not a schema type "
                     f"or alias (declared: {sorted(types)})")


def check_type_aliases(schema: dict) -> None:
    """Every type alias must normalize to a real canonical type, and must not shadow one."""
    types = set(schema.get("types") or {})
    for alias, canonical in (schema.get("type_aliases") or {}).items():
        if canonical not in types:
            fail(f"type_aliases['{alias}'] -> '{canonical}' is not a canonical schema type "
                 f"(declared: {sorted(types)})")
        if alias in types:
            warn(f"type_aliases['{alias}'] shadows a canonical type of the same name")


FRONTMATTER_RE = re.compile(r"^---\s*\n(.*?)\n---\s*\n", re.S)


def _frontmatter(path: Path) -> dict:
    """Parse a page's YAML frontmatter; {} if absent or invalid."""
    m = FRONTMATTER_RE.match(path.read_text())
    if not m:
        return {}
    try:
        d = yaml.safe_load(m.group(1))
    except Exception:  # noqa: BLE001  (a malformed page shouldn't crash the validator)
        return {}
    return d if isinstance(d, dict) else {}


def _iter_wiki_pages(schema: dict):
    """Every authored knowledge page (skips excluded namespaces + engine root files)."""
    excluded = {Path(p.rstrip("/")).name for p in (schema.get("exclude") or [])}
    base = ROOT / "wiki"
    if not base.is_dir():
        return
    for p in base.rglob("*.md"):
        rel = p.relative_to(base)
        if rel.parts and rel.parts[0] in excluded:
            continue
        if len(rel.parts) == 1 and p.stem in ROOT_WIKI_FILES:
            continue
        yield p


def _dotted(fm: dict, key: str):
    """Resolve a possibly-dotted frontmatter key to its value (None if absent)."""
    cur = fm
    for part in key.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def check_enums_wellformed(schema: dict) -> None:
    """Every field_enums entry must target a declared enum and a real type (by_type).
    okpack-sec variant: also validates list_field_enums."""
    enums = schema.get("enums") or {}
    types = set(schema.get("types") or {})
    for field, spec in (schema.get("field_enums") or {}).items():
        if not isinstance(spec, dict):
            fail(f"field_enums['{field}'] must be a mapping")
            continue
        targets = [spec["enum"]] if "enum" in spec else []
        for t, en in (spec.get("by_type") or {}).items():
            targets.append(en)
            if t not in types:
                fail(f"field_enums['{field}'].by_type references unknown type '{t}'")
        if not targets:
            fail(f"field_enums['{field}'] has neither `enum:` nor `by_type:`")
        for en in targets:
            if en not in enums:
                fail(f"field_enums['{field}'] -> enum '{en}' is not declared in enums:")
    for field, subspec in (schema.get("list_field_enums") or {}).items():
        if not isinstance(subspec, dict):
            fail(f"list_field_enums['{field}'] must be a mapping")
            continue
        for sub, spec in subspec.items():
            en = spec.get("enum") if isinstance(spec, dict) else spec
            if en not in enums:
                fail(f"list_field_enums['{field}'].{sub} -> enum '{en}' is not declared in enums:")


def check_page_enum_values(schema: dict) -> None:
    """Check every authored page's frontmatter values against the declared enums.
    Wrong value FAILS (unless the field is extensible -> WARN); absence is fine."""
    enums = schema.get("enums") or {}
    field_enums = schema.get("field_enums") or {}
    aliases = schema.get("type_aliases") or {}
    if not field_enums:
        return
    for page in _iter_wiki_pages(schema):
        fm = _frontmatter(page)
        if not fm:
            continue
        ptype = aliases.get(fm.get("type"), fm.get("type"))
        rel = page.relative_to(ROOT)
        for field, spec in field_enums.items():
            val = _dotted(fm, field)
            if val is None:
                continue
            enum_name = (spec.get("by_type") or {}).get(ptype) if "by_type" in spec else spec.get("enum")
            if not enum_name:  # by_type field on a type with no rule — skip
                continue
            allowed = {str(x) for x in enums.get(enum_name, [])}
            extensible = bool(spec.get("extensible"))
            for v in (val if isinstance(val, list) else [val]):
                if str(v) not in allowed:
                    msg = (f"{rel}: {field}={v!r} not in enum '{enum_name}' "
                           f"({sorted(allowed)})")
                    warn(msg) if extensible else fail(msg)


def check_page_required_fields(schema: dict) -> None:
    """Warn when an authored page is missing a required (tier R) field for its type.
    Flag-not-gate (spec §1.4): a missing required field warns, never fails."""
    types = schema.get("types") or {}
    aliases = schema.get("type_aliases") or {}
    for page in _iter_wiki_pages(schema):
        fm = _frontmatter(page)
        if not fm:
            continue
        ptype = aliases.get(fm.get("type"), fm.get("type"))
        spec = types.get(ptype)
        if not spec:
            continue
        for field in spec.get("required", []):
            if field != "type" and _dotted(fm, field) is None:
                warn(f"{page.relative_to(ROOT)}: missing required '{field}' for type '{ptype}'")


def _rels_predicates(schema: dict) -> set:
    rv = schema.get("rels_vocabulary") or {}
    return set().union(*(set(rv.get(g) or []) for g in ("canonical", "reverse", "okf_native"))) \
        if rv else set()


def check_page_rels_predicates(schema: dict) -> None:
    """Warn on a page `rels` predicate outside the §6 vocabulary (flag-not-gate, §6.4)."""
    vocab = _rels_predicates(schema)
    if not vocab:
        return
    for page in _iter_wiki_pages(schema):
        rels = _frontmatter(page).get("rels")
        if not isinstance(rels, dict):
            continue
        for pred in rels:
            if pred not in vocab:
                warn(f"{page.relative_to(ROOT)}: rels predicate '{pred}' not in the §6 vocabulary")


def check_page_list_enum_values(schema: dict) -> None:
    """Check enum values inside list-of-object fields (refs[].std, cvss[].version/severity)."""
    enums = schema.get("enums") or {}
    lfe = schema.get("list_field_enums") or {}
    if not lfe:
        return
    for page in _iter_wiki_pages(schema):
        fm = _frontmatter(page)
        for field, subspec in lfe.items():
            items = fm.get(field)
            if not isinstance(items, list):
                continue
            for i, item in enumerate(items):
                if not isinstance(item, dict):
                    continue
                for sub, spec in subspec.items():
                    val = item.get(sub)
                    if val is None:
                        continue
                    enum_name = spec.get("enum") if isinstance(spec, dict) else spec
                    allowed = {str(x) for x in enums.get(enum_name, [])}
                    extensible = isinstance(spec, dict) and bool(spec.get("extensible"))
                    if str(val) not in allowed:
                        msg = f"{page.relative_to(ROOT)}: {field}[{i}].{sub}={val!r} not in enum '{enum_name}'"
                        warn(msg) if extensible else fail(msg)


def check_page_refs_shape(schema: dict) -> None:
    """Each `refs[]` entry needs `std` and at least one of `id`/`url` (spec §9.4)."""
    for page in _iter_wiki_pages(schema):
        refs = _frontmatter(page).get("refs")
        if not isinstance(refs, list):
            continue
        rel = page.relative_to(ROOT)
        for i, r in enumerate(refs):
            if not isinstance(r, dict):
                fail(f"{rel}: refs[{i}] is not a mapping")
                continue
            if not r.get("std"):
                fail(f"{rel}: refs[{i}] missing 'std'")
            if not (r.get("id") or r.get("url")):
                fail(f"{rel}: refs[{i}] needs at least one of id/url")


def check_cross_refs() -> None:
    """Every §N / §N.M reference in the spec must resolve to a section heading. Tolerant of
    item-refs (§7.3 = item 3 of §7): a §N.M passes if §N exists even when N.M is not a heading."""
    path = ROOT / SPEC_FILE
    if not path.exists():
        return
    text = path.read_text()
    headings = set(re.findall(r"^#{2,3}\s+([0-9][0-9a-z]*(?:\.[0-9a-z]+)*)", text, re.M))
    tops = {h.split(".")[0] for h in headings}
    for ref in sorted(set(re.findall(r"§([0-9][0-9a-z.]*)", text))):
        r = ref.rstrip(".")
        if r in headings or r.split(".")[0] in tops:
            continue
        fail(f"{SPEC_FILE}: cross-ref §{ref} resolves to no section")


DEFANG_MARKERS = ("[.]", "[:]", "(.)", "[d]", "hxxp", "[at]", "[@]", "{.}")


def check_page_defang(schema: dict) -> None:
    """IOC values must be defanged (CLAUDE.md). Checks `indicator.value` for a live ip/domain/url/
    email — the deterministic, low-false-positive case (body-text/`cidr`/`refs` URLs are legit and
    not scanned). Flag-not-gate: warns."""
    aliases = schema.get("type_aliases") or {}
    for page in _iter_wiki_pages(schema):
        fm = _frontmatter(page)
        if aliases.get(fm.get("type"), fm.get("type")) != "indicator":
            continue
        value = fm.get("value")
        if value is None:
            continue
        v = str(value)
        if any(m in v for m in DEFANG_MARKERS):
            continue  # already defanged
        ioc_type = fm.get("ioc_type")
        live = (
            (ioc_type == "ip" and re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", v))
            or (ioc_type in ("domain", "url") and (v.startswith(("http://", "https://")) or "." in v))
            or (ioc_type == "email" and "@" in v and "." in v)
        )
        if live:
            warn(f"{page.relative_to(ROOT)}: indicator value {v!r} looks un-defanged "
                 f"(use [.] / [:] / hxxp — CLAUDE.md)")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--probe", action="store_true", help="HTTP-probe every feed (network)")
    ap.add_argument("--fix", action="store_true", help="rewrite the feeds.opml count comment to match")
    args = ap.parse_args()

    schema = check_parse()
    if args.fix:
        fix_feed_count()
        if schema:
            fix_spec_reference(schema)

    suggested = check_feeds()
    if schema:
        check_namespace_consistency(schema)
        check_type_consistency(schema)
        check_type_aliases(schema)
        check_pack_yaml(schema)
        check_enums_wellformed(schema)
        check_page_enum_values(schema)
        check_page_list_enum_values(schema)
        check_page_refs_shape(schema)
        check_page_required_fields(schema)
        check_page_rels_predicates(schema)
        check_page_defang(schema)
        check_cross_refs()
        check_spec_sync(schema)
        check_human_only_gates(schema)
        check_schema_consistency(schema)
        check_namespace_dirs_exist(schema)
    check_crons_jittered()
    if args.probe:
        probe_feeds(suggested)

    for w in warns:
        print(f"WARN  {w}")
    for f in fails:
        print(f"FAIL  {f}")
    if fails:
        print(f"\n{len(fails)} failure(s), {len(warns)} warning(s).")
        return 1
    print(f"OK — pack valid ({len(suggested)} suggested feeds), {len(warns)} warning(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
