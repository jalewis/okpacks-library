#!/usr/bin/env python3
"""Conformance for cve_actor_edge.py — the actor↔CVE pivot the cockpit renders both ways.

Invariants:
  1. compute_edges unions DIRECT actor fields (exploits_cve/cves_exploited/np_cves_exploited)
     with the TECHNIQUE-mediated seam (actor.techniques -> technique.exploits_cve), forward + reverse.
  2. main stamps `exploited_cve_ids` on actor pages and `exploiting_actors` on EXISTING cve pages only
     (a CVE with no page is skipped, never created).
  3. SET semantics, not merge: an actor that stops exploiting a CVE is DROPPED next run; other
     frontmatter + body preserved; a page already at the computed value is left untouched (idempotent);
     --dry-run writes nothing.

Drives the REAL lane. Runs standalone (conformance-all.sh) and is pytest-discoverable.
"""
import importlib.util
import sys
import tempfile
from pathlib import Path

import yaml

SCRIPTS = Path(__file__).resolve().parent.parent / "crons" / "scripts"


def _load(name: str):
    for m in ("_okf_write", "okf_migrate", name):
        sys.modules.pop(m, None)
    sys.path.insert(0, str(SCRIPTS))
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _write(p: Path, fm: dict, body: str = "body") -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("---\n" + yaml.safe_dump(fm, sort_keys=False) + "---\n\n" + body + "\n", encoding="utf-8")


def _fm(p: Path) -> dict:
    t = p.read_text(encoding="utf-8")
    return yaml.safe_load(t[3:t.find("\n---", 3)]) or {}


def test_compute_edges_unions_direct_and_technique():
    m = _load("cve_actor_edge")
    actors = {
        # ATT&CK-imported: id (G0999) differs from the slug -> reverse edge must use the id so the
        # Vulnerabilities bar's link_page {by: id} resolves it.
        "dragonforce": {"type": "actor", "id": "G0999",
                        "np_cves_exploited": ["CVE-2025-5777", "cve-2023-32315"],
                        "techniques": ["T1190"]},
        "turla": {"type": "actor", "exploits_cve": ["CVE-2021-30860"]},   # no id -> falls back to slug
        "quiet": {"type": "actor"},                                        # no CVEs -> absent from fwd
    }
    techs = {"exploit-public-app": {"type": "technique", "attack_id": "T1190",
                                    "exploits_cve": ["CVE-2024-3400"]}}
    fwd, rev = m.compute_edges(actors, techs, m._DEFAULT_SOURCE_FIELDS)
    # forward stays keyed by SLUG (to find the page), direct + technique-mediated, upper-cased, sorted
    assert fwd["dragonforce"] == ["CVE-2023-32315", "CVE-2024-3400", "CVE-2025-5777"]
    assert fwd["turla"] == ["CVE-2021-30860"]
    assert "quiet" not in fwd
    # reverse is valued by the actor ID (G0999), or the slug when there is no id (turla)
    assert rev["CVE-2024-3400"] == ["G0999"]
    assert rev["CVE-2025-5777"] == ["G0999"]
    assert rev["CVE-2021-30860"] == ["turla"]


def test_main_stamps_both_directions_and_skips_unmapped():
    m = _load("cve_actor_edge")
    with tempfile.TemporaryDirectory() as t:
        vault = Path(t); wiki = vault / "wiki"
        _write(wiki / "entities" / "dragonforce.md",
               {"type": "actor", "id": "G0999", "title": "DragonForce",
                "np_cves_exploited": ["CVE-2025-5777"]})
        # an EXISTING cve page (sharded) that maps; and NO page for CVE-2099-9999
        _write(wiki / "cves" / "2025" / "07" / "CVE-2025-5777.md",
               {"type": "cve", "cve_id": "CVE-2025-5777", "kev": True})
        _write(wiki / "entities" / "ghost.md",
               {"type": "actor", "title": "Ghost", "exploits_cve": ["CVE-2099-9999"]})

        assert m.main(["--vault", str(vault)]) == 0
        # forward stamped on both actors (keyed by slug — the page it found)
        assert _fm(wiki / "entities" / "dragonforce.md")["exploited_cve_ids"] == ["CVE-2025-5777"]
        assert _fm(wiki / "entities" / "ghost.md")["exploited_cve_ids"] == ["CVE-2099-9999"]
        # reverse stamped on the mapped cve page only, valued by the actor ID (G0999); curated preserved
        cve = _fm(wiki / "cves" / "2025" / "07" / "CVE-2025-5777.md")
        assert cve["exploiting_actors"] == ["G0999"] and cve["kev"] is True
        # no cve page was created for the unmapped CVE
        assert not (wiki / "cves" / "2099").exists()


def test_set_semantics_drops_stale_and_is_idempotent():
    m = _load("cve_actor_edge")
    with tempfile.TemporaryDirectory() as t:
        vault = Path(t); wiki = vault / "wiki"
        cve = wiki / "cves" / "CVE-2025-5777.md"
        # a stale exploiting_actors listing an actor that no longer exploits it
        _write(cve, {"type": "cve", "cve_id": "CVE-2025-5777", "exploiting_actors": ["oldactor"]})
        _write(wiki / "entities" / "dragonforce.md",
               {"type": "actor", "title": "DragonForce", "exploits_cve": ["CVE-2025-5777"]})

        assert m.main(["--vault", str(vault)]) == 0
        assert _fm(cve)["exploiting_actors"] == ["dragonforce"]        # stale 'oldactor' dropped (SET)

        # second run changes nothing (idempotent) — mtime unchanged
        before = cve.stat().st_mtime_ns
        assert m.main(["--vault", str(vault)]) == 0
        assert cve.stat().st_mtime_ns == before

        # dry-run never writes even when there IS a change
        _write(wiki / "entities" / "newactor.md",
               {"type": "actor", "title": "New", "exploits_cve": ["CVE-2025-5777"]})
        before = cve.stat().st_mtime_ns
        assert m.main(["--vault", str(vault), "--dry-run"]) == 0
        assert cve.stat().st_mtime_ns == before


if __name__ == "__main__":
    test_compute_edges_unions_direct_and_technique()
    test_main_stamps_both_directions_and_skips_unmapped()
    test_set_semantics_drops_stale_and_is_idempotent()
    print("OK")
