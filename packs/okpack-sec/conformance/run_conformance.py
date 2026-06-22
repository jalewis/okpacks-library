#!/usr/bin/env python3
"""STIX 2.1 projection conformance suite for okf-sec (freeze item D).

Proves — not claims — that `projectors/stix.py` emits valid STIX 2.1. The spec-backed fixtures are
**extracted from the worked examples in OKF-SEC-SPEC.md** (not hand-copied), so they cannot drift
from the published spec; the few types the spec doesn't exemplify get inline COVERAGE fixtures.

For each fixture page:
  1. project → a STIX bundle (deterministic, so golden-stable);
  2. structural check — id/timestamp/spec_version shapes + per-SDO required properties;
  3. official check — if `stix2` is installed, parse every object through it (real STIX 2.1
     validation). Skipped with a notice if not installed;
  4. documented-loss invariant — recorded loss == exactly the `x_okfsec_*` props (no silent/phantom);
  5. golden — compare to conformance/golden/<name>.json (or write it with --update).

Usage:
    python3 conformance/run_conformance.py            # validate + golden compare (exit 1 on fail)
    python3 conformance/run_conformance.py --update    # (re)write golden fixtures
"""
import datetime
import json
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from projectors.stix import project_page  # noqa: E402

GOLDEN = Path(__file__).resolve().parent / "golden"
SPEC = ROOT / "OKF-SEC-SPEC.md"
ID_RE = re.compile(r"^[a-z0-9-]+--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3})?Z$")

# Per-SDO required properties (STIX 2.1, the subset our projector emits).
REQUIRED = {
    "vulnerability": ["name"], "attack-pattern": ["name"], "threat-actor": ["name"],
    "intrusion-set": ["name"], "malware": ["is_family"], "tool": ["name"], "campaign": ["name"],
    "infrastructure": ["name"], "identity": ["name"], "course-of-action": ["name"],
    "indicator": ["pattern", "pattern_type", "valid_from"],
    "report": ["name", "published", "object_refs"],
    "relationship": ["relationship_type", "source_ref", "target_ref"],
}

# Spec worked examples → (golden label, slug). Frontmatter is pulled from OKF-SEC-SPEC.md by name;
# the slug is the canonical wikilink slug other examples use to point at this entity (so the graph
# is id-coherent). Adding a worked example to the spec without an entry here → a WARN (untested).
SPEC_EXAMPLES = {
    "xz-utils backdoor (CVE-2024-3094)":                 ("vulnerability-xz",          "xz-utils-backdoor"),
    "PowerShell":                                        ("attack-pattern-powershell", "t1059-001-powershell"),
    "APT29":                                             ("intrusion-set-apt29",       "apt29"),
    "APT29 C2 — telemetry-fronting domain":              ("indicator-c2-domain",       "apt29-c2-telemetry-domain"),
    "Mandiant — APT29 supply-chain update (2026-06-10)": ("source-mandiant",           "2026-06-10-mandiant-apt29"),
    "Bulletproof host — AS65535":                        ("infrastructure-asn",        "as65535-bulletproof"),
    "WellMess":                                          ("malware-wellmess",          "wellmess"),
    "SolarWinds":                                        ("identity-solarwinds",       "solarwinds"),
    "SUNBURST / SolarWinds supply-chain":                ("campaign-sunburst",         "sunburst-solarwinds"),
    "Sigma — encoded PowerShell with anomalous parent":  ("detection-sigma",           "sigma-encoded-powershell"),
}

# Types the spec does not exemplify → inline coverage fixtures (so all 18 types are proven).
COVERAGE = [
    ("tool-mimikatz", "mimikatz", {
        "type": "tool", "name": "Mimikatz", "category": "credential-exploitation",
        "description": "Post-exploitation credential-dumping tool.", "created": "2026-06-16",
        "updated": "2026-06-16",
        "refs": [{"std": "mitre-attack", "id": "S0002", "url": "https://attack.mitre.org/software/S0002/"}],
        "rels": {"used-by": ["[[entities/threat-actor/apt29]]"]}, "tags": ["credential-access"]}),
    ("threat-actor-ecrime", "acme-ransom-crew", {
        "type": "threat-actor", "name": "Acme Ransom Crew (example)", "actor_class": "criminal",
        "description": "Illustrative financially-motivated ecrime actor.",
        "motivation": {"primary": "personal-gain"}, "sophistication": "intermediate",
        "resource_level": "team", "first_seen": "2024-01-01", "created": "2026-06-16",
        "updated": "2026-06-16", "rels": {"uses-malware": ["[[entities/malware/wellmess]]"]},
        "tags": ["ecrime", "ransomware"]}),
    ("course-of-action-m1040", "m1040-behavior-prevention", {
        "type": "course-of-action", "name": "Behavior Prevention on Endpoint",
        "description": "Block process behaviors associated with technique abuse.",
        "created": "2026-06-16", "updated": "2026-06-16",
        "refs": [{"std": "mitre-attack", "id": "M1040", "url": "https://attack.mitre.org/mitigations/M1040/"}],
        "rels": {"mitigates": ["[[entities/attack-pattern/t1059-001-powershell]]"]},
        "tags": ["mitigation", "endpoint"]}),
    ("software-orion", "solarwinds-orion", {
        "type": "software", "name": "SolarWinds Orion", "cpe": "cpe:2.3:a:solarwinds:orion:*:*:*:*:*:*:*:*",
        "vendor": "SolarWinds", "created": "2026-06-16", "updated": "2026-06-16",
        "rels": {"affected-by": ["[[entities/vulnerability/cve-2020-10148]]"]}, "tags": ["it-management"]}),
    ("concept-lotl", "living-off-the-land", {
        "type": "concept", "name": "living-off-the-land",
        "description": "Adversary use of built-in, signed system tooling to evade detection.",
        "created": "2026-06-16", "updated": "2026-06-16",
        "rels": {"related-to": ["[[entities/attack-pattern/t1059-001-powershell]]"]},
        "tags": ["lolbin", "evasion"]}),
    ("finding-unpatched-xz", "unpatched-xz-prod", {
        "type": "finding", "name": "Unpatched xz on production hosts", "severity": "high",
        "status": "open", "created": "2026-06-16", "updated": "2026-06-16",
        "rels": {"related-to": ["[[entities/vulnerability/xz-utils-backdoor]]"]}, "tags": ["exposure"]}),
    ("prediction-supplychain", "xz-style-supplychain-180d", {
        "type": "prediction", "name": "Another xz-style supply-chain RCE within 180 days",
        "status": "open", "confidence": 0.6, "subject": "[[entities/concept/living-off-the-land]]",
        "resolves_by": "2026-12-31", "made_on": "2026-06-17", "horizon": "medium",
        "created": "2026-06-16", "updated": "2026-06-16", "tags": ["forecast"]}),
    ("dashboard-ransomware", "ransomware-watch", {
        "type": "dashboard", "title": "Ransomware watch", "created": "2026-06-16",
        "updated": "2026-06-16", "tags": ["dashboard"]}),
]


def _norm_dates(obj):
    """YAML parses dates as date objects; normalize to ISO strings (JSON-safe + matches authoring)."""
    if isinstance(obj, (datetime.date, datetime.datetime)):
        return obj.isoformat()
    if isinstance(obj, dict):
        return {k: _norm_dates(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_norm_dates(v) for v in obj]
    return obj


def _spec_examples():
    """Extract worked-example frontmatter from the spec. Returns (matched fixtures, untracked names)."""
    text = SPEC.read_text()
    matched, untracked, seen = [], [], set()
    for _lang, body in re.findall(r"```(\w*)\n(.*?)\n```", text, re.S):
        m = re.match(r"---\n(.*?)\n---", body, re.S)
        if not m:
            continue
        try:
            fm = yaml.safe_load(m.group(1))
        except Exception:  # noqa: BLE001
            continue
        if not isinstance(fm, dict):
            continue
        name = fm.get("name")
        if not fm.get("type") or not name or str(name).startswith("<") or name in seen:
            continue
        seen.add(name)
        if name in SPEC_EXAMPLES:
            label, slug = SPEC_EXAMPLES[name]
            matched.append((label, slug, _norm_dates(fm)))
        else:
            untracked.append(name)
    return matched, untracked


def _build_fixtures():
    matched, untracked = _spec_examples()
    found = {lbl for lbl, _, _ in matched}
    missing = {lbl for lbl, _ in SPEC_EXAMPLES.values()} - found
    if missing:
        raise SystemExit(f"FATAL: SPEC_EXAMPLES not found in {SPEC.name}: {sorted(missing)}")
    if untracked:
        print(f"WARN  untested worked example(s) in {SPEC.name} — add to SPEC_EXAMPLES: {untracked}")
    return matched + COVERAGE


FIXTURES = _build_fixtures()


def structural_errors(bundle: dict) -> list:
    errs = []
    if bundle.get("type") != "bundle" or not ID_RE.match(bundle.get("id", "")):
        errs.append("bundle: bad type/id")
    for o in bundle.get("objects", []):
        t = o.get("type", "?")
        if not ID_RE.match(o.get("id", "")):
            errs.append(f"{t}: bad id {o.get('id')!r}")
        for ts in ("created", "modified", "valid_from", "published", "first_seen", "last_seen"):
            if ts in o and not TS_RE.match(o[ts]):
                errs.append(f"{t}.{ts}: bad timestamp {o[ts]!r}")
        for req in REQUIRED.get(t, []):
            if req not in o:
                errs.append(f"{t}: missing required '{req}'")
        if t == "report" and not o.get("object_refs"):
            errs.append("report: empty object_refs")
    return errs


def loss_invariant_errors(result: dict) -> list:
    """The recorded loss set must equal exactly the x_okfsec_* props on the primary object."""
    primary = result["bundle"]["objects"][0]
    on_obj = {k[len("x_okfsec_"):] for k in primary if k.startswith("x_okfsec_")}
    recorded = set(result["loss"])
    if on_obj != recorded:
        return [f"loss mismatch: recorded={sorted(recorded)} but x_okfsec props={sorted(on_obj)}"]
    return []


def stix2_errors(bundle: dict):
    """Validate each object via the official stix2 library, if installed. Returns (errors, ran)."""
    try:
        from stix2 import parse
    except Exception:  # noqa: BLE001
        return [], False
    errs = []
    for o in bundle["objects"]:
        try:
            parse(o, allow_custom=True)
        except Exception as e:  # noqa: BLE001
            errs.append(f"stix2 rejected {o.get('type')}: {e}")
    return errs, True


def main() -> int:
    update = "--update" in sys.argv
    GOLDEN.mkdir(exist_ok=True)
    total_fail = 0
    stix2_ran = False
    for name, slug, page in FIXTURES:
        result = project_page(page, slug)
        bundle = result["bundle"]
        errs = structural_errors(bundle) + loss_invariant_errors(result)
        s2_errs, ran = stix2_errors(bundle)
        stix2_ran = stix2_ran or ran
        errs += s2_errs

        gpath = GOLDEN / f"{name}.json"
        payload = {"bundle": bundle, "loss": result["loss"]}
        if update:
            gpath.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
        elif gpath.exists():
            if json.loads(gpath.read_text()) != payload:
                errs.append("golden mismatch (run --update if intended)")
        else:
            errs.append("golden missing (run --update)")

        n = len(bundle["objects"])
        if errs:
            total_fail += 1
            print(f"FAIL  {name}  ({n} objects, loss={result['loss']})")
            for e in errs:
                print(f"        - {e}")
        else:
            print(f"ok    {name}  ({n} objects, loss={result['loss']})")

    note = "validated via stix2" if stix2_ran else \
        "stix2 not installed — structural+golden only (pip install stix2 for full validation)"
    print(f"\n{len(FIXTURES) - total_fail}/{len(FIXTURES)} fixtures pass · {note}")
    if update:
        print("golden fixtures written.")
    return 1 if total_fail else 0


if __name__ == "__main__":
    raise SystemExit(main())
