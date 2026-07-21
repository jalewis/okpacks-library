#!/usr/bin/env python3
"""Conformance: every shipped golden page conforms to schema.yaml (okpacks-library#4).

Proves the domain contract is self-consistent and usable: each `conformance/golden/*.md`
page has a known `type`, all its type's required fields, and only valid values for the
enum-constrained fields (`field_enums`). This is the page-VALUE check that complements
validate.py's offline schema-WELLFORMEDNESS check (which never touches the page tree).

Runs standalone (conformance-all.sh: `python3 conformance/test_pages.py`, nonzero exit on
failure) and is pytest-discoverable. No network; pure frontmatter parsing.
"""
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
GOLDEN = Path(__file__).resolve().parent / "golden"
_FM = re.compile(r"\A---\s*\n(.*?\n)---\s*\n", re.S)

# Engine base-schema (L1) core types — merged UNDER the pack at deploy (okengine#90 P2), so the
# conformance contract is the MERGED type set, not schema.yaml alone. Required fields mirror
# okengine config/base-schema.yaml at the release pinned in engine.version. (The okf-level `id`
# MUST is excluded: the write path mints it at creation; authored goldens ship without it.)
BASE_TYPES = {
    "source":     {"required": ["type", "published"]},
    "concept":    {"required": ["type"]},
    "prediction": {"required": ["type", "status", "confidence", "subject", "resolves_by"]},
    "finding":    {"required": ["type", "status"]},
    "dashboard":  {"required": ["type", "title"]},
    "briefing":   {"required": ["type", "title", "published"]},
    "trend":      {"required": ["type", "title", "period", "direction"]},
}


def _schema() -> dict:
    return yaml.safe_load((ROOT / "schema.yaml").read_text())


def _frontmatter(text: str):
    m = _FM.match(text)
    if not m:
        return None
    d = yaml.safe_load(m.group(1))
    return d if isinstance(d, dict) else None


def check_page(fm: dict, schema: dict) -> list[str]:
    """Conformance errors for one page's frontmatter: unknown type, a missing required field, or
    an enum-constrained field carrying a value outside its vocabulary (unless `extensible`)."""
    types = schema.get("types") or {}
    t = fm.get("type")
    spec = types.get(t) if t in types else BASE_TYPES.get(t)
    if spec is None:
        return [f"unknown type {t!r}"]
    errs = []
    for req in spec.get("required", []):
        if fm.get(req) in (None, "", []):
            errs.append(f"missing required field '{req}' for type '{t}'")
    enums = schema.get("enums") or {}
    for field, spec in (schema.get("field_enums") or {}).items():
        if field not in fm:
            continue
        enum_name = (spec.get("by_type") or {}).get(t) if "by_type" in spec else spec.get("enum")
        if not enum_name:
            continue
        vocab = enums.get(enum_name) or []
        for v in (fm[field] if isinstance(fm[field], list) else [fm[field]]):
            if v not in vocab and not spec.get("extensible"):
                errs.append(f"field '{field}'={v!r} not in enum '{enum_name}' {vocab}")
    return errs


def test_golden_pages_conform():
    schema = _schema()
    files = sorted(GOLDEN.rglob("*.md"))
    assert files, "no golden pages found under conformance/golden/"
    for p in files:
        fm = _frontmatter(p.read_text(encoding="utf-8"))
        assert fm, f"{p.name}: no parseable frontmatter"
        errs = check_page(fm, schema)
        assert not errs, f"{p.name}: " + "; ".join(errs)


def test_every_type_has_a_golden_page():
    schema = _schema()
    seen = {(_frontmatter(p.read_text(encoding="utf-8")) or {}).get("type")
            for p in GOLDEN.rglob("*.md")}
    missing = set(schema.get("types") or {}) - seen
    assert not missing, f"types with no golden page: {sorted(missing)}"


def test_checker_catches_bad_pages():
    schema = _schema()
    assert check_page({"type": "source", "source_kind": "bogus", "published": "2026-01-01"}, schema)  # bad enum
    assert check_page({"type": "prediction"}, schema)                      # missing base required fields
    assert check_page({"type": "source"}, schema)                          # source missing `published`
    # base (engine-owned) types are part of the merged contract; a valid source passes:
    assert not check_page({"type": "source", "source_kind": "threat-report",
                           "published": "2026-01-01"}, schema)
    assert check_page({"type": "technique", "tactic": ["not-a-tactic"]}, schema)   # bad tactic enum (closed)
    assert check_page({"type": "actor", "attribution_confidence": "bogus"}, schema)  # bad attribution enum (closed)
    # extensible enum: an unknown target_sector is allowed (warn-not-fail) -> no error
    assert not check_page({"type": "actor", "target_sector": ["metaverse"]}, schema)


def test_current_enterprise_tactic_vocabulary():
    schema = yaml.safe_load((Path(__file__).resolve().parent.parent / "schema.yaml").read_text())
    tactics = set(schema["enums"]["tactic"])
    assert {"stealth", "defense-impairment"} <= tactics
    assert "defense-evasion" not in tactics


def _run() -> int:
    fails = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"  ok   {name}")
            except AssertionError as e:
                fails += 1
                print(f"  FAIL {name}: {e}")
    return fails


if __name__ == "__main__":
    print("== okpack-threat-actors page conformance ==")
    n = _run()
    print("all golden pages conform" if not n else f"{n} conformance test(s) failed")
    sys.exit(1 if n else 0)
