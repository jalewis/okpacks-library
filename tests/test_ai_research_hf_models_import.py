"""okpack-ai-research HF notable-models importer: presence is decided by identity (okpacks-library#104).

On a live vault the importer checked only its hand-built seat `entities/<letter>/<slug>.md`. The
reshelve drain had moved every page to `entities/<l>/<l2>/<slug>.md`, so each weekly run re-created
~100 id-less pages; the engine's slug-identity guard quarantined them and failed the run, four
weeks running. Six of the models also already had curated pages under their plain names.

These tests use the REAL engine identity libs (id_lib, okf_migrate, id_index) from ENGINE_DIR.
"""
from __future__ import annotations

import importlib.util
import os
import shutil
import sys
from pathlib import Path

import pytest
import yaml

PACK = Path(__file__).resolve().parents[1] / "packs" / "okpack-ai-research"
SCRIPTS = PACK / "crons" / "scripts"
ENGINE = os.environ.get("ENGINE_DIR") or os.environ.get("OKENGINE_DIR")
CRON = Path(ENGINE) / "scripts" / "cron" if ENGINE else None

pytestmark = pytest.mark.skipif(
    not (CRON and (CRON / "okf_migrate.py").is_file()),
    reason="no ENGINE_DIR checkout with the engine identity libs — identity contract UNDETECTABLE")

MODELS = [
    {"id": "deepseek-ai/DeepSeek-R1", "author": "deepseek-ai", "pipeline_tag": "text-generation",
     "likes": 13000, "createdAt": "2025-01-20T00:00:00.000Z", "library_name": "transformers"},
    {"id": "facebook/sam3", "author": "facebook", "pipeline_tag": "mask-generation",
     "likes": 2808, "createdAt": "2025-11-07T00:00:00.000Z"},
    {"id": "openai/whisper-large-v3", "author": "openai",
     "pipeline_tag": "automatic-speech-recognition", "likes": 5000},
]
_ENGINE_MODS = ("id_lib", "okf_migrate", "id_index", "schema_lib", "importer_guard",
                "authority_lib", "_okf_write")


@pytest.fixture
def importer(monkeypatch, tmp_path):
    for m in _ENGINE_MODS:
        monkeypatch.delitem(sys.modules, m, raising=False)
    monkeypatch.setattr(sys, "path", [str(SCRIPTS), str(CRON), *sys.path])
    monkeypatch.setenv("WIKI_PATH", str(tmp_path))
    monkeypatch.setenv("HERMES_DATA", str(tmp_path / "data"))   # no persisted id-index: build it
    monkeypatch.delenv("OKPACK_STRICT_IMPORT", raising=False)
    shutil.copy(PACK / "schema.yaml", tmp_path / "schema.yaml")
    name = "hf_models_import_under_test"
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / "okpack_ai_research_hf_import.py")
    mod = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, name, mod)
    spec.loader.exec_module(mod)
    yield mod
    for m in _ENGINE_MODS:
        sys.modules.pop(m, None)


def _pages(vault: Path) -> dict[str, dict]:
    out = {}
    for p in sorted((vault / "wiki" / "entities").rglob("*.md")):
        out[p.relative_to(vault / "wiki").as_posix()] = yaml.safe_load(p.read_text().split("---")[1])
    return out


def _page(vault: Path, rel: str, fm: dict) -> None:
    p = vault / "wiki" / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("---\n" + yaml.safe_dump(fm, sort_keys=False) + "---\nCurated body.\n")


def test_new_models_get_an_id_and_the_engine_seat(importer, tmp_path):
    c = importer.import_models(MODELS, tmp_path, "2026-09-26")
    assert c["created"] == 3 and c["exists"] == 0 and c["unverifiable"] == 0
    pages = _pages(tmp_path)
    sam = pages["entities/f/a/facebook-sam3.md"]
    assert sam["id"] == "entities:sam3", "the id backfill_ids would derive from the title"
    assert all(fm.get("id") for fm in pages.values()), "no id-less page is ever minted"
    assert "entities/f/facebook-sam3.md" not in pages, "never the old hand-built one-letter seat"


def test_a_rerun_creates_nothing(importer, tmp_path):
    importer.import_models(MODELS, tmp_path, "2026-09-26")
    before = _pages(tmp_path)
    c = importer.import_models(MODELS, tmp_path, "2026-09-27")
    assert c["created"] == 0 and c["exists"] == 3
    assert _pages(tmp_path) == before


def test_a_page_the_drain_moved_is_found_where_it_sits(importer, tmp_path):
    """REGRESSION: the live pages sat at entities/f/a/ while the importer looked at entities/f/."""
    _page(tmp_path, "entities/f/a/facebook-sam3.md", {"type": "model", "title": "sam3"})
    c = importer.import_models(MODELS[1:2], tmp_path, "2026-09-26")
    assert c == {"created": 0, "exists": 1, "total": 1, "unverifiable": 0, "collision": 0}
    assert list(_pages(tmp_path)) == ["entities/f/a/facebook-sam3.md"]


def test_a_model_with_a_curated_page_is_not_seeded_again(importer, tmp_path):
    """A curated `DeepSeek-R1` page holds the id the importer would mint: that IS the model."""
    _page(tmp_path, "entities/d/e/deepseek-r1.md",
          {"id": "entities:deepseek-r1", "type": "model", "title": "DeepSeek-R1"})
    c = importer.import_models(MODELS[:1], tmp_path, "2026-09-26")
    assert c["created"] == 0 and c["exists"] == 1
    assert list(_pages(tmp_path)) == ["entities/d/e/deepseek-r1.md"]


def test_without_the_identity_libs_nothing_is_created(importer, tmp_path, monkeypatch, capsys):
    """NEGATIVE: an unverified create is how the duplicates began — refuse, and say so."""
    monkeypatch.setattr(importer, "okf_migrate", None)
    c = importer.import_models(MODELS, tmp_path, "2026-09-26")
    assert c["created"] == 0 and c["unverifiable"] == 3
    assert not (tmp_path / "wiki").exists()
    assert "okf_migrate" in capsys.readouterr().err


def test_dry_run_writes_nothing(importer, tmp_path):
    c = importer.import_models(MODELS, tmp_path, "2026-09-26", dry_run=True)
    assert c["created"] == 3
    assert not list(tmp_path.rglob("*.md"))
