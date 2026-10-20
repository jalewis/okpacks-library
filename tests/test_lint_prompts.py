"""`scripts/lint_prompts.py` — the receipt-requirement check (library#108).

The defect this guards: every pack's concept-backfill prompt (and five packs'
page-quality-enrich) never mentioned the fenced okengine-receipt its selector prints and the
runner verifies, so the lane could not finish with the receipt its completion gate requires.
The prompt-text lint could not see it, because a prompt that never mentions a receipt carries
no marker to check. The requirement is therefore derived from the ENGINE: the lane's
output_contract and its selector's source.

These tests build a miniature engine checkout rather than reading the real one, so they assert
the RULE and stay green when the engine's lane list changes.
"""
from __future__ import annotations

import importlib.util
import json
import pathlib

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
SCRIPT = REPO / "scripts" / "lint_prompts.py"


def load_module():
    spec = importlib.util.spec_from_file_location("lint_prompts", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


mod = load_module()

PER_ITEM = {"api": 1, "completion": "per-selected-item"}
GOOD_PREFIX = ("Concept backfill. FIRST response MUST be a tool call: converge_concept. "
               "Do not gather more information; take the action that records it now. ")


@pytest.fixture
def engine(tmp_path):
    """Three lanes: a receipt lane, a per-item lane whose selector prints none, a run lane."""
    root = tmp_path / "engine"
    (root / "config").mkdir(parents=True)
    (root / "scripts" / "cron").mkdir(parents=True)
    (root / "config" / "engine-crons.json").write_text(json.dumps([
        {"name": "concept-backfill", "script": "select_concept.py", "output_contract": PER_ITEM},
        {"name": "classify-drain", "script": "select_classify.py", "output_contract": PER_ITEM},
        {"name": "daily-brief", "script": "select_brief.py",
         "output_contract": {"api": 1, "completion": "run"}},
    ]), encoding="utf-8")
    cron = root / "scripts" / "cron"
    (cron / "select_concept.py").write_text('print("```okengine-receipt")\n', encoding="utf-8")
    (cron / "select_classify.py").write_text('print("=== batch ===")\n', encoding="utf-8")
    (cron / "select_brief.py").write_text('print("digest")\n', encoding="utf-8")
    return root


def write_pack(tmp_path, prompts: dict) -> pathlib.Path:
    packs = tmp_path / "packs"
    crons = packs / "okpack-t" / "crons"
    crons.mkdir(parents=True)
    (crons / "engine-template-prompts.json").write_text(json.dumps(prompts), encoding="utf-8")
    return packs


def run(monkeypatch, capsys, packs, engine_dir=None, ci=False):
    monkeypatch.delenv("OKENGINE_DIR", raising=False)
    if engine_dir is None:
        monkeypatch.delenv("ENGINE_DIR", raising=False)
    else:
        monkeypatch.setenv("ENGINE_DIR", str(engine_dir))
    if ci:
        monkeypatch.setenv("CI", "true")
    else:
        monkeypatch.delenv("CI", raising=False)
    rc = mod.main([str(packs)])
    return rc, capsys.readouterr().out


def test_prompt_missing_the_receipt_its_selector_prints_fails(tmp_path, engine, monkeypatch,
                                                               capsys):
    # Arrange: the pre-#108 concept-backfill shape -- action directives present, no receipt.
    packs = write_pack(tmp_path, {"concept-backfill": GOOD_PREFIX + "LOCAL-ONLY."})
    # Act
    rc, out = run(monkeypatch, capsys, packs, engine)
    # Assert
    assert rc == 1, out
    assert "okpack-t/concept-backfill" in out and "never tells the model to return it" in out


def test_prompt_with_the_receipt_instruction_passes(tmp_path, engine, monkeypatch, capsys):
    packs = write_pack(tmp_path, {"concept-backfill": GOOD_PREFIX +
                                  "End with only the exact fenced okengine-receipt. LOCAL-ONLY."})
    rc, out = run(monkeypatch, capsys, packs, engine)
    assert rc == 0, out


def test_pack_supplied_contract_overrides_engine_contract(tmp_path, engine, monkeypatch, capsys):
    # A pack prompt carrying its own per-item contract owes a receipt even on a "run" lane.
    packs = write_pack(tmp_path, {"daily-brief": {"prompt": "Write the brief.",
                                                  "output_contract": PER_ITEM}})
    (engine / "scripts" / "cron" / "select_brief.py").write_text(
        'print("```okengine-receipt")\n', encoding="utf-8")
    rc, out = run(monkeypatch, capsys, packs, engine)
    assert rc == 1, out
    assert "okpack-t/daily-brief" in out


def test_run_completion_lane_owes_no_receipt(tmp_path, engine, monkeypatch, capsys):
    packs = write_pack(tmp_path, {"daily-brief": "Write the brief."})
    rc, out = run(monkeypatch, capsys, packs, engine)
    assert rc == 0, out


def test_selector_that_prints_no_receipt_is_reported_not_failed(tmp_path, engine, monkeypatch,
                                                                capsys):
    # The prompt has nothing to copy; the gap is engine-side (okengine#799). Visible, not red.
    packs = write_pack(tmp_path, {"classify-drain": "Classify the batch."})
    rc, out = run(monkeypatch, capsys, packs, engine)
    assert rc == 0, out
    assert "okpack-t/classify-drain: runner verifies a receipt its selector" in out


def test_unreadable_selector_is_undetectable_not_a_pass(tmp_path, engine, monkeypatch, capsys):
    (engine / "scripts" / "cron" / "select_concept.py").unlink()
    packs = write_pack(tmp_path, {"concept-backfill": GOOD_PREFIX + "LOCAL-ONLY."})
    rc, out = run(monkeypatch, capsys, packs, engine)
    assert rc == 1, out
    assert "UNDETECTABLE" in out


def test_shared_receipt_helper_counts_as_printing_a_receipt(tmp_path, engine, monkeypatch,
                                                            capsys):
    (engine / "scripts" / "cron" / "select_concept.py").write_text(
        "print_receipt_template(manifest)\n", encoding="utf-8")
    packs = write_pack(tmp_path, {"concept-backfill": GOOD_PREFIX + "LOCAL-ONLY."})
    rc, out = run(monkeypatch, capsys, packs, engine)
    assert rc == 1, out


def test_missing_engine_dir_fails_under_ci(tmp_path, monkeypatch, capsys):
    packs = write_pack(tmp_path, {"daily-brief": "Write the brief."})
    rc, out = run(monkeypatch, capsys, packs, engine_dir=None, ci=True)
    assert rc == 1, out
    assert "UNDETECTABLE" in out


def test_missing_engine_dir_is_announced_locally(tmp_path, monkeypatch, capsys):
    packs = write_pack(tmp_path, {"daily-brief": "Write the brief."})
    rc, out = run(monkeypatch, capsys, packs, engine_dir=None, ci=False)
    assert rc == 0, out
    assert "SKIPPED" in out and "UNDETECTABLE" in out
