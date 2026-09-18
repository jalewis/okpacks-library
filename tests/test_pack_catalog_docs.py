"""Pack catalog documentation is generated from catalog.json without drift."""

import json
import sys
from pathlib import Path

import pytest

from scripts.pack_catalog_docs import BEGIN, END, render_table, synchronize
from scripts import generate_pack_catalog


CATALOG = {
    "packs": [
        {
            "name": "okpack-one",
            "domain": "First domain",
            "status": "community",
            "subdir": "packs/okpack-one",
        },
        {
            "name": "okpack-two",
            "domain": "Second | domain",
            "status": "example",
            "subdir": "packs/okpack-two",
        },
    ]
}


def _repository(tmp_path: Path) -> Path:
    (tmp_path / "packs").mkdir()
    (tmp_path / "catalog.json").write_text(json.dumps(CATALOG), encoding="utf-8")
    template = f"before\n{BEGIN}\nstale\n{END}\nafter\n"
    (tmp_path / "README.md").write_text(template, encoding="utf-8")
    (tmp_path / "packs" / "README.md").write_text(template, encoding="utf-8")
    return tmp_path


def test_synchronize_generates_both_link_contexts(tmp_path: Path) -> None:
    root = _repository(tmp_path)

    assert synchronize(root, check=False) == [root / "README.md", root / "packs" / "README.md"]
    assert synchronize(root, check=True) == []
    assert "(packs/okpack-one)" in (root / "README.md").read_text(encoding="utf-8")
    nested = (root / "packs" / "README.md").read_text(encoding="utf-8")
    assert "(okpack-one)" in nested
    assert "Second \\| domain" in nested


def test_check_reports_drift_without_writing(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    before = (root / "README.md").read_text(encoding="utf-8")

    assert synchronize(root, check=True) == [root / "README.md", root / "packs" / "README.md"]
    assert (root / "README.md").read_text(encoding="utf-8") == before


def test_render_rejects_missing_canonical_metadata() -> None:
    with pytest.raises(ValueError, match="missing documentation fields: status"):
        render_table(
            {"packs": [{"name": "okpack-one", "domain": "One", "subdir": "packs/okpack-one"}]},
            from_packs_dir=False,
        )


def test_synchronize_rejects_missing_markers(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    (root / "README.md").write_text("no generated section\n", encoding="utf-8")

    with pytest.raises(ValueError, match="exactly one"):
        synchronize(root, check=True)


def test_cli_updates_drift_and_then_passes_check(tmp_path: Path, monkeypatch, capsys) -> None:
    root = _repository(tmp_path)
    monkeypatch.setattr(generate_pack_catalog, "ROOT", root)
    monkeypatch.setattr(sys, "argv", ["generate_pack_catalog.py"])

    assert generate_pack_catalog.main() == 0
    assert "updated pack catalog documentation" in capsys.readouterr().out

    monkeypatch.setattr(sys, "argv", ["generate_pack_catalog.py", "--check"])
    assert generate_pack_catalog.main() == 0
    assert "pack catalog documentation is current" in capsys.readouterr().out


def test_cli_check_rejects_drift_without_writing(tmp_path: Path, monkeypatch, capsys) -> None:
    root = _repository(tmp_path)
    before = (root / "README.md").read_text(encoding="utf-8")
    monkeypatch.setattr(generate_pack_catalog, "ROOT", root)
    monkeypatch.setattr(sys, "argv", ["generate_pack_catalog.py", "--check"])

    assert generate_pack_catalog.main() == 1
    output = capsys.readouterr().out
    assert "pack catalog documentation is stale" in output
    assert "run: python3 scripts/generate_pack_catalog.py" in output
    assert (root / "README.md").read_text(encoding="utf-8") == before
