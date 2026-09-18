#!/usr/bin/env python3
"""Golden-fixture conformance for this pack (okpacks-library#27).

Proves the pack's declared types are SATISFIABLE and ENFORCED: every golden page in
conformance/golden/ must parse and satisfy the schema's required fields for its type,
and the inline NEGATIVE fixture (a page missing a required field) must be rejected —
a checker born without a red path has never been observed working.

Usage: python3 conformance/run_conformance.py     # exit 1 on any failure
"""
import re
import sys
from pathlib import Path

import yaml

PACK = Path(__file__).resolve().parent.parent
FM_RE = re.compile(r"\A---\s*\n(.*?)\n---", re.S)

# Engine base-schema (L1) core types — merged UNDER the pack at deploy (okengine#90 P2), so a
# base-typed golden (source/concept/…) belongs to the merged contract, not "not declared".
# Required fields mirror okengine config/base-schema.yaml at the pinned release.
BASE_REQUIRED = {
    "source":     ["type", "published"],
    "concept":    ["type"],
    "prediction": ["type", "status", "confidence", "subject", "resolves_by"],
    "finding":    ["type", "status"],
    "dashboard":  ["type", "title"],
    "briefing":   ["type", "title", "published"],
    "trend":      ["type", "title", "period", "direction"],
}


def required_for(schema: dict, t: str) -> list:
    types = schema.get("types") or {}
    t = (schema.get("type_aliases") or {}).get(t, t)
    if t in types:                    # a pack declaration overrides the core copy (merge semantics)
        return list((types[t] or {}).get("required") or [])
    if t in BASE_REQUIRED:
        return list(BASE_REQUIRED[t])
    return None


def check_page(schema: dict, text: str) -> str | None:
    m = FM_RE.match(text)
    if not m:
        return "no frontmatter"
    fm = yaml.safe_load(m.group(1)) or {}
    req = required_for(schema, fm.get("type"))
    if req is None:
        return f"type '{fm.get('type')}' not declared by this pack"
    missing = [f for f in req if f not in fm or fm.get(f) in (None, "")]
    return f"missing required {missing}" if missing else None


def main() -> int:
    schema = yaml.safe_load((PACK / "schema.yaml").read_text())
    fails = 0
    golden = sorted((PACK / "conformance" / "golden").glob("*.md"))
    declared = set(schema.get("types") or {})
    covered = set()
    for g in golden:
        err = check_page(schema, g.read_text())
        fm = yaml.safe_load(FM_RE.match(g.read_text()).group(1))
        covered.add(fm.get("type"))
        status = "ok" if not err else f"FAIL ({err})"
        print(f"  {g.name}: {status}")
        fails += bool(err)
    missing = declared - covered
    if missing:
        print(f"  FAIL: declared type(s) without a golden fixture: {sorted(missing)}")
        fails += 1
    # negative fixture: enforcement must actually reject (red path, inline)
    first = sorted(declared)[0]
    req = required_for(schema, first)
    broken = f"---\ntype: {first}\n---\nbody\n"
    if req and len(req) > 1 and check_page(schema, broken) is None:
        print(f"  FAIL: negative fixture (type {first} missing {req}) was ACCEPTED")
        fails += 1
    else:
        print(f"  negative fixture rejected as expected (type {first})")
    print("conformance:", "FAIL" if fails else "OK", f"({len(golden)} golden, {len(declared)} types)")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
