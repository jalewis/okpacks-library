"""okpack-ai-research HF daily-papers importer: raw captures, never wiki pages.

The importer used to hand-build a seat and write `sources/**` pages directly, with no `id` and a
pseudo backlink. On a live vault that minted ~600 pages the engine's write path could neither
update nor find by identity, so the same paper later compiled from the arXiv feed became a
duplicate (okengine#886). It now writes a feed-item-shaped RAW capture that the engine's
raw-compile lane compiles through the write path.
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest
import yaml

PACK = Path(__file__).resolve().parents[1] / "packs" / "okpack-ai-research"
SCRIPT = PACK / "crons" / "scripts" / "okpack_ai_research_hf_papers_import.py"

ITEMS = [
    {"paper": {"id": "2609.00001", "title": "Sparse Attention at Scale",
               "publishedAt": "2026-09-20T10:00:00.000Z", "upvotes": 42,
               "summary": "We study sparse attention for long-context models and report a 3x "
                          "throughput gain at equal perplexity across four model sizes.",
               "authors": [{"name": "A. Author"}, {"name": "B. Author"}],
               "ai_keywords": ["Sparse Attention", "long context"]}},
    {"paper": {"id": "", "title": "no arXiv id — skipped"}},
    "not a dict",
]


@pytest.fixture
def importer(monkeypatch):
    sys.path.insert(0, str(SCRIPT.parent))
    name = "hf_papers_import_under_test"
    spec = importlib.util.spec_from_file_location(name, SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    monkeypatch.delenv("OKPACK_STRICT_IMPORT", raising=False)
    yield mod
    sys.modules.pop(name, None)
    sys.path.remove(str(SCRIPT.parent))


def _run(mod, vault: Path, *extra: str) -> int:
    src = vault / "items.json"
    src.write_text(json.dumps(ITEMS))
    return mod.main(["--vault", str(vault), "--src", str(src), *extra])


def _captures(vault: Path) -> list[Path]:
    return sorted((vault / "raw" / "hf").glob("*.md"))


def test_papers_become_raw_captures_not_wiki_pages(importer, tmp_path):
    assert _run(importer, tmp_path) == 0
    (capture,) = _captures(tmp_path)
    assert capture.name == "2026-09-20-sparse-attention-at-scale-2609-00001.md"
    assert not (tmp_path / "wiki" / "sources").exists(), "the importer must never write pages"
    text = capture.read_text()
    fm = yaml.safe_load(text.split("---")[1])
    assert fm["url"] == "https://arxiv.org/abs/2609.00001"
    assert fm["publisher"] == "arXiv", "raw-compile needs a declared publisher"
    assert fm["published"] == "2026-09-20" and fm["title"] == "Sparse Attention at Scale"
    assert fm["arxiv_id"] == "2609.00001" and fm["hf_upvotes"] == 42
    assert fm["source_tags"] == ["long-context", "sparse-attention"]
    assert "id" not in fm and "raw" not in fm, "identity and backlinks are the engine's to stamp"
    assert "hf-daily-papers" not in text, "a feed-wide tag is noise to the trends signal"
    assert "3x throughput" in text


def test_a_capture_is_written_once(importer, tmp_path):
    _run(importer, tmp_path)
    (capture,) = _captures(tmp_path)
    capture.write_text(capture.read_text() + "\nlocal edit\n")
    assert _run(importer, tmp_path) == 0
    assert capture.read_text().endswith("local edit\n"), "an existing capture is never rewritten"


def test_dry_run_writes_nothing(importer, tmp_path):
    assert _run(importer, tmp_path, "--dry-run") == 0
    assert _captures(tmp_path) == []


def test_a_failed_write_is_strict_only_when_asked(importer, tmp_path):
    (tmp_path / "raw").mkdir()
    (tmp_path / "raw" / "hf").write_text("a file where the capture directory belongs")
    assert _run(importer, tmp_path) == 0, "best-effort by default: the cron never crashes"
    assert _run(importer, tmp_path, "--strict") == 1


def test_the_capture_is_compilable_by_the_engine(importer, tmp_path):
    """The contract that matters: the engine's raw-compile accepts this capture as a complete
    identity (url, title, published, declared publisher, body). Needs an engine checkout."""
    engine = os.environ.get("ENGINE_DIR") or os.environ.get("OKENGINE_DIR")
    if not engine or not (Path(engine) / "scripts" / "cron" / "raw_compile.py").is_file():
        pytest.skip("no ENGINE_DIR checkout with raw_compile.py — "
                    "capture contract UNDETECTABLE here")
    _run(importer, tmp_path)
    (capture,) = _captures(tmp_path)
    cron = str(Path(engine) / "scripts" / "cron")
    saved_path, saved_env = list(sys.path), os.environ.get("WIKI_PATH")
    sys.path.insert(0, cron)
    os.environ["WIKI_PATH"] = str(tmp_path)
    try:
        for mod in ("raw_compile", "select_raw_batch"):
            sys.modules.pop(mod, None)
        import raw_compile
        rel = capture.relative_to(tmp_path).as_posix()
        parsed = raw_compile.structured(rel, capture.read_text(), {})
        assert not isinstance(parsed, str), f"raw-compile leaves it for the model: {parsed}"
        fm, _body = parsed
        assert fm["arxiv_id"] == "2609.00001", "importer provenance survives compilation"
    finally:
        sys.path[:] = saved_path
        for mod in ("raw_compile", "select_raw_batch"):
            sys.modules.pop(mod, None)
        if saved_env is None:
            os.environ.pop("WIKI_PATH", None)
        else:
            os.environ["WIKI_PATH"] = saved_env
