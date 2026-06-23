#!/usr/bin/env python3
"""Conformance for okpack-ai-research's no_agent importers (okpacks-library#12).

Drives the Hugging Face importer's pure transforms with inline fixtures (no network) and proves
every minted `model` page conforms to schema.yaml — required fields + enum vocabularies — by
running it through the SAME checker the golden-page suite uses (`test_pages.check_page`).

Runs standalone (conformance-all.sh: `python3 conformance/test_importers.py`, nonzero exit on
failure) and is pytest-discoverable.
"""
import importlib.util
import sys
import tempfile
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent.parent / "crons" / "scripts"
sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_pages import _frontmatter, _schema, check_page  # noqa: E402 — reuse the page checker


def _load(name):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


# A trimmed slice of the real Hugging Face /api/models response shape.
_HF = [
    {"id": "deepseek-ai/DeepSeek-R1", "author": "deepseek-ai", "pipeline_tag": "text-generation",
     "likes": 13404, "library_name": "transformers", "createdAt": "2025-01-20T03:46:07.000Z"},
    {"id": "black-forest-labs/FLUX.1-dev", "author": "black-forest-labs",
     "pipeline_tag": "text-to-image", "likes": 13281, "createdAt": "2024-08-01T00:00:00.000Z"},
    {"id": "some-org/Unknown-Task", "author": "some-org", "pipeline_tag": "brand-new-task",
     "likes": 5},                                                  # unknown task -> modality omitted
    {"id": "no-task/model", "author": "no-task", "likes": 1},      # no pipeline_tag at all
    {"id": "", "author": "x", "likes": 99},                        # nameless -> skipped
    {"id": "priv/secret", "private": True, "likes": 50},           # private -> skipped
]


def test_hf_model_records_and_modality_mapping():
    m = _load("okpack_ai_research_hf_import")
    recs = {r["id"]: r for r in m.model_records(_HF)}
    assert set(recs) == {"deepseek-ai/DeepSeek-R1", "black-forest-labs/FLUX.1-dev",
                         "some-org/Unknown-Task", "no-task/model"}   # nameless + private dropped
    r = recs["deepseek-ai/DeepSeek-R1"]
    assert r["title"] == "DeepSeek-R1" and r["org_slug"] == "deepseek-ai"
    assert r["modality"] == "text" and r["released"] == "2025-01-20"
    assert recs["black-forest-labs/FLUX.1-dev"]["modality"] == "image"
    assert recs["some-org/Unknown-Task"]["modality"] is None        # unmapped task -> not guessed
    assert recs["no-task/model"]["modality"] is None


def test_hf_slug_keeps_org_prefix():
    m = _load("okpack_ai_research_hf_import")
    assert m.hf_slug("deepseek-ai/DeepSeek-R1") == "deepseek-ai-deepseek-r1"
    assert m.hf_slug("meta-llama/Llama-3.1-8B-Instruct") == "meta-llama-llama-31-8b-instruct"


def test_hf_import_creates_conformant_pages_idempotent():
    m = _load("okpack_ai_research_hf_import")
    schema = _schema()
    with tempfile.TemporaryDirectory() as t:
        v = Path(t)
        c = m.import_models(_HF, v, "2026-06-20")
        assert c == {"created": 4, "exists": 0, "total": 4}
        pages = list((v / "wiki" / "entities").rglob("*.md"))
        assert len(pages) == 4
        for p in pages:                                             # every minted page is conformant
            fm = _frontmatter(p.read_text(encoding="utf-8"))
            assert fm, f"{p.name}: unparseable frontmatter"
            errs = check_page(fm, schema)
            assert not errs, f"{p.name}: {errs}"
        ds = (v / "wiki" / "entities" / "d" / "deepseek-ai-deepseek-r1.md").read_text()
        assert "lab: '[[deepseek-ai]]'" in ds and "release_status: released" in ds
        assert m.import_models(_HF, v, "2026-06-20") == {"created": 0, "exists": 4, "total": 4}


# A trimmed slice of the real HF /api/daily_papers response shape.
_HF_PAPERS = [
    {"paper": {"id": "2606.20529", "title": "LedgerAgent: Structured State for Tool-Calling",
               "publishedAt": "2026-06-17T20:00:00.000Z", "upvotes": 6,
               "authors": [{"name": "Md Nayem Uddin"}, {"name": "Amir Saeidi"}],
               "summary": "Policy-adherent tool-calling agents must maintain task state.",
               "ai_keywords": ["tool-calling", "agents", "structured state"]}},
    {"paper": {"id": "", "title": "no arxiv id", "publishedAt": "2026-06-01T00:00:00.000Z"}},  # skipped
    {"paper": {"id": "2606.00001", "title": "", "upvotes": 1}},                                # skipped
]


def test_hf_papers_records():
    m = _load("okpack_ai_research_hf_papers_import")
    recs = {r["arxiv"]: r for r in m.paper_records(_HF_PAPERS)}
    assert set(recs) == {"2606.20529"}                              # no-id + no-title dropped
    r = recs["2606.20529"]
    assert r["published"] == "2026-06-17" and r["upvotes"] == 6
    assert r["authors"] == ["Md Nayem Uddin", "Amir Saeidi"]
    assert r["url"] == "https://arxiv.org/abs/2606.20529"
    assert "tool-calling" in r["keywords"]
    assert m.source_slug(r) == "ledgeragent-structured-state-for-tool-calling-2606-20529"


def test_hf_papers_import_creates_conformant_pages_idempotent():
    m = _load("okpack_ai_research_hf_papers_import")
    schema = _schema()
    with tempfile.TemporaryDirectory() as t:
        v = Path(t)
        c = m.import_sources(_HF_PAPERS, v, "2026-06-20")
        assert c == {"created": 1, "exists": 0, "total": 1}
        pages = list((v / "wiki" / "sources").rglob("*.md"))
        assert len(pages) == 1
        p = pages[0]
        assert "/sources/2026/06/" in str(p)                         # by-date partition
        fm = _frontmatter(p.read_text(encoding="utf-8"))
        assert fm and not check_page(fm, schema)                     # conformant: required + enums
        txt = p.read_text(encoding="utf-8")
        assert "source_kind: paper" in txt and "hf-daily-papers" in txt
        assert m.import_sources(_HF_PAPERS, v, "2026-06-20") == {"created": 0, "exists": 1, "total": 1}


def test_hf_papers_strict_mode_fetch_and_write():
    m = _load("okpack_ai_research_hf_papers_import")
    # fetch/parse failure: best-effort returns 0; --strict returns nonzero (okpacks-library#16)
    assert m.main(["--src", "/nonexistent-papers.json"]) == 0
    assert m.main(["--src", "/nonexistent-papers.json", "--strict"]) == 1
    with tempfile.TemporaryDirectory() as t:
        src = Path(t) / "papers.json"
        src.write_text('[{"paper":{"id":"2606.1","title":"X","upvotes":1}}]')
        bad = Path(t) / "afile"
        bad.write_text("not a dir")        # vault is a file -> write OSError
        assert m.main(["--src", str(src), "--vault", str(bad)]) == 0          # best-effort skip
        assert m.main(["--src", str(src), "--vault", str(bad), "--strict"]) == 1  # strict -> nonzero


def _run() -> int:
    fails = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"  ok   {name}")
            except AssertionError as e:
                fails += 1
                print(f"  FAIL {name}: {e}")
    return fails


if __name__ == "__main__":
    print("== okpack-ai-research importer conformance ==")
    n = _run()
    print("all importer tests pass" if not n else f"{n} importer test(s) failed")
    sys.exit(1 if n else 0)
