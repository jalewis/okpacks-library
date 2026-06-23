#!/usr/bin/env python3
"""Whole-vault link resolution test (spec §7 / issue #13.2).

Proves the STIX projector resolves `rels`/wikilink targets against the REAL page graph (a target
page's true type + identity field), not the link-path shape. Builds a tiny temp vault where:
  - an attack-pattern lives under a by-letter shard (`entities/a/...`) and is identified by its
    `mitre_id` (T1059.001) — so its real STIX id is derived from the mitre id, not the slug;
  - a malware page links to it by SLUG ONLY (`[[t1059-001-powershell]]`, no type in the path).

Neither the by-letter path nor the slug-only link is resolvable by the path-shape heuristic. With
the vault index, the malware's `uses` SRO must target the attack-pattern's mitre-derived id.
"""
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from projectors.stix import (  # noqa: E402
    build_vault_index, project_page, page_stix_id, _target_id,
)

VAULT = {
    "wiki/entities/a/t1059-001-powershell.md":
        "---\ntype: attack-pattern\nname: PowerShell\nmitre_id: T1059.001\n---\nbody\n",
    "wiki/entities/m/maliscript.md":
        "---\ntype: malware\nname: MaliScript\nrels:\n  uses:\n    - '[[t1059-001-powershell]]'\n---\nbody\n",
}


def main() -> int:
    errs = []
    with tempfile.TemporaryDirectory() as d:
        for rel, text in VAULT.items():
            p = Path(d) / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text)
        resolver = build_vault_index(d)

        attack_pattern = {"type": "attack-pattern", "name": "PowerShell", "mitre_id": "T1059.001"}
        malware = {"type": "malware", "name": "MaliScript",
                   "rels": {"uses": ["[[t1059-001-powershell]]"]}}
        real_ap_id = page_stix_id(attack_pattern, "t1059-001-powershell")  # mitre-derived

        # 1. the slug is indexed
        if "t1059-001-powershell" not in resolver:
            errs.append("vault index missing the slug key")
        # 2. the id is mitre-derived, NOT slug-derived (proves identity-based resolution)
        if real_ap_id == _target_id("[[entities/attack-pattern/t1059-001-powershell]]"):
            errs.append("real id equals the slug-derived heuristic id (identity not used)")
        # 3. WITHOUT a resolver, a slug-only link does NOT resolve (heuristic needs type-in-path)
        if _target_id("[[t1059-001-powershell]]") is not None:
            errs.append("heuristic unexpectedly resolved a slug-only link")
        # 4. WITH the resolver, it resolves to the attack-pattern's real id
        got = _target_id("[[t1059-001-powershell]]", resolver)
        if got != real_ap_id:
            errs.append(f"resolver returned {got}, expected real id {real_ap_id}")
        # 5. end-to-end: the malware's `uses` SRO targets the attack-pattern's real id
        bundle = project_page(malware, "maliscript", resolver=resolver)["bundle"]
        sros = [o for o in bundle["objects"] if o["type"] == "relationship"]
        if not any(s["relationship_type"] == "uses" and s["target_ref"] == real_ap_id for s in sros):
            errs.append(f"no `uses` SRO targeting {real_ap_id}; "
                        f"got {[(s['relationship_type'], s['target_ref']) for s in sros]}")

    if errs:
        print("FAIL  vault-resolution")
        for e in errs:
            print(f"        - {e}")
        return 1
    print("ok    vault-resolution — slug-only + by-letter links resolve to real page ids")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
