#!/usr/bin/env python3
"""Regression: vault scans must tolerate pages vanishing mid-scan.

landscape_reports_import._index_actors() rglobs entities/ and reads each page
while mover lanes relocate pages concurrently; it crashed with FileNotFoundError
during the 2026-07-13 okcti catch-up stampede. A dangling symlink reproduces the
race deterministically: rglob lists it, read_text raises FileNotFoundError.

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


def test_index_actors_tolerates_vanished_pages():
    mod = _load("landscape_reports_import")
    with tempfile.TemporaryDirectory() as td:
        ent = Path(td) / "entities" / "a"
        ent.mkdir(parents=True)
        (ent / "ghostwriter.md").write_text(
            "---\ntype: actor\ntitle: Ghostwriter\n---\n# Ghostwriter\n", encoding="utf-8")
        (ent / "ghost.md").symlink_to(ent / "gone.md")
        rx, stems = mod._index_actors(Path(td))   # must not raise
    assert "ghostwriter" in stems


if __name__ == "__main__":
    test_index_actors_tolerates_vanished_pages()
    print("OK")
