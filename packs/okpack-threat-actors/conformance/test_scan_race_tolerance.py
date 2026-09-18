#!/usr/bin/env python3
"""Regression: vault scans must tolerate pages vanishing mid-scan.

misp_galaxy_import.index_actors() and cti_dashboards._load() glob whole vault
subtrees and read each page while mover lanes (reshelve, url-reconcile,
schema-type-drain) relocate pages concurrently. Both crashed with
FileNotFoundError during the 2026-07-13 okcti catch-up stampede.

A dangling symlink reproduces the race deterministically: rglob/glob lists it,
the read raises FileNotFoundError — exactly a page deleted between glob and read.

Runs standalone (conformance-all.sh) and is pytest-discoverable.
"""
import importlib.util
import sys
import tempfile
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent.parent / "crons" / "scripts"


def _load(name: str):
    for m in ("_okf_write", "okf_migrate", name):
        sys.modules.pop(m, None)
    sys.path.insert(0, str(SCRIPTS))
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _vault_with_ghost(root: Path) -> Path:
    ent = root / "entities" / "a"
    ent.mkdir(parents=True)
    (ent / "apt-x.md").write_text(
        "---\ntype: actor\ntitle: APT X\naliases: [ghostwriter]\n---\n# APT X\n",
        encoding="utf-8")
    # dangling symlink: listed by the glob, read raises FileNotFoundError
    (ent / "ghost.md").symlink_to(ent / "gone.md")
    return root


def test_misp_index_actors_tolerates_vanished_pages():
    mod = _load("misp_galaxy_import")
    with tempfile.TemporaryDirectory() as td:
        vault = _vault_with_ghost(Path(td))
        idx = mod.index_actors(vault)   # must not raise
    assert any("apt-x" in rel for rel in idx.values())


def test_cti_dashboards_load_tolerates_vanished_pages():
    mod = _load("cti_dashboards")
    with tempfile.TemporaryDirectory() as td:
        wiki = _vault_with_ghost(Path(td))
        actors, software, techs, cves = mod._load(wiki)   # must not raise
    assert "apt-x" in actors


if __name__ == "__main__":
    test_misp_index_actors_tolerates_vanished_pages()
    test_cti_dashboards_load_tolerates_vanished_pages()
    print("OK")
