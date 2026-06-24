#!/usr/bin/env python3
"""Pack quality / readiness scoring (okpacks-library#23 + #27).

Scores each pack against a checklist and gates it on a bar that scales with its catalog `status`
(example < community < flagship). Dimensions: README, schema, pack.yaml, validate.py, LICENSE,
engine pin, safe feed defaults, conformance suite, **golden-fixture coverage of every type (#27)**,
and CHANGELOG. Human-readable table; exits nonzero if a pack misses a dimension REQUIRED for its
status. `example` packs are a skeleton exception. Run via `okpacks quality` (or in CI).
"""
import json
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
FM_RE = re.compile(r"\A---\s*\n(.*?)\n---", re.S)

# Dimensions REQUIRED to pass, by catalog status. Higher tiers inherit lower ones.
REQUIRED = {
    "example":   ["readme", "schema", "pack_yaml", "validator", "license"],
    "community": ["readme", "schema", "pack_yaml", "validator", "license",
                  "engine_pin", "safe_feeds", "conformance", "fixtures"],
    "flagship":  ["readme", "schema", "pack_yaml", "validator", "license",
                  "engine_pin", "safe_feeds", "conformance", "fixtures", "changelog"],
}
ALL_DIMS = ["readme", "schema", "pack_yaml", "validator", "license", "engine_pin",
            "safe_feeds", "conformance", "fixtures", "changelog"]


def _has(p: Path) -> bool:
    return p.exists()


def _conformance_entrypoints(pd: Path) -> bool:
    c = pd / "conformance"
    return c.is_dir() and (any(c.glob("run_*.py")) or any(c.glob("test_*.py")))


def _safe_feeds(pd: Path) -> bool:
    """No ACTIVE feeds shipped (safe default) and a curated suggestion list present."""
    active = pd / "feeds" / "feeds.opml"
    has_active = active.exists() and "xmlUrl=" in active.read_text(errors="replace")
    return (not has_active) and (pd / "feeds" / "feeds.opml.example").exists()


def _fixture_coverage(pd: Path, schema: dict) -> tuple[str, str]:
    """(#27) Every schema type has a golden page, OR a documented exemption (a pack that proves
    type coverage through a conformance suite + spec rather than per-type page files)."""
    types = set(schema.get("types") or {})
    aliases = schema.get("type_aliases") or {}
    gdir = pd / "conformance" / "golden"
    golden = list(gdir.glob("*.md")) if gdir.is_dir() else []
    if not golden:
        if _conformance_entrypoints(pd):
            return "exempt", "no golden pages; conformance suite + spec cover the types"
        return "missing", "no golden fixtures and no conformance suite"
    covered = set()
    for g in golden:
        m = FM_RE.match(g.read_text(errors="replace"))
        if m:
            fm = yaml.safe_load(m.group(1)) or {}
            t = fm.get("type")
            covered.add(aliases.get(t, t))
    missing = types - covered
    if missing:
        return "partial", f"{len(covered)}/{len(types)} types; missing golden: {sorted(missing)}"
    return "ok", f"{len(covered)}/{len(types)} types covered"


def score_pack(pd: Path, status: str) -> dict:
    meta = yaml.safe_load((pd / "pack.yaml").read_text()) or {}
    try:
        schema = yaml.safe_load((pd / "schema.yaml").read_text()) or {}
    except (OSError, yaml.YAMLError):
        schema = {}
    fixtures_state, fixtures_note = _fixture_coverage(pd, schema)
    dims = {
        "readme":     _has(pd / "README.md"),
        "schema":     bool(schema),
        "pack_yaml":  all(meta.get(k) for k in ("name", "version", "trust", "owns")),
        "validator":  _has(pd / "validate.py"),
        "license":    _has(pd / "LICENSE"),
        "engine_pin": _has(pd / "engine.version"),
        "safe_feeds": _safe_feeds(pd),
        "conformance": _conformance_entrypoints(pd),
        "fixtures":   fixtures_state in ("ok", "exempt"),
        "changelog":  _has(pd / "CHANGELOG.md"),
    }
    required = REQUIRED.get(status, REQUIRED["community"])
    missing_required = [d for d in required if not dims[d]]
    return {"name": meta.get("name", pd.name), "status": status, "dims": dims,
            "fixtures_note": fixtures_note, "required": required,
            "missing_required": missing_required}


def main() -> int:
    catalog = json.loads((ROOT / "catalog.json").read_text())
    status_by_sub = {p.get("subdir", "").rsplit("/", 1)[-1]: p.get("status", "community")
                     for p in catalog.get("packs", [])}
    rows = []
    for pd in sorted((ROOT / "packs").iterdir()):
        if pd.is_dir() and (pd / "pack.yaml").exists():
            rows.append(score_pack(pd, status_by_sub.get(pd.name, "community")))

    def cell(r, d):
        if d not in r["dims"]:
            return " - "
        ok = r["dims"][d]
        req = d in r["required"]
        return (" ✓ " if ok else (" ✗ " if req else " · "))  # ✗ = required-and-missing

    hdr = f"{'pack':22} {'status':10} " + " ".join(f"{d[:5]:^5}" for d in ALL_DIMS)
    print(hdr)
    print("-" * len(hdr))
    for r in rows:
        line = f"{r['name']:22} {r['status']:10} " + " ".join(cell(r, d) for d in ALL_DIMS)
        print(line)
        if r["dims"].get("fixtures") and "fixtures" in r["required"]:
            pass
    print()
    print("  legend: ✓ present · required-and-missing=✗ · ·=optional-absent · -=n/a    "
          "(#27 fixture coverage in the `fixtures` column)")
    for r in rows:
        note = r["fixtures_note"]
        print(f"  {r['name']}: fixtures — {note}")

    failed = [r for r in rows if r["missing_required"]]
    if failed:
        print()
        for r in failed:
            print(f"FAIL  {r['name']} ({r['status']}) missing required: {', '.join(r['missing_required'])}")
        print(f"\n{len(failed)} pack(s) below their readiness bar.")
        return 1
    print(f"\nall {len(rows)} packs meet their readiness bar.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
