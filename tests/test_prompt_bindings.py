"""`scripts/check_prompt_bindings.py` — the gate that catches a prompt key nothing resolves.

The defect this guards (okengine#562): 21 `prediction-*` prompt keys across 7 packs kept
pointing at engine lanes that had migrated into the `okengine.predictions` extension. On the
single-pack path those keys are silently dropped, so the deployment ran the extension's default
prompt while pack source said otherwise; on the N-way compose path the same keys are hard
errors, so the packs were uncomposable. Nothing in this repo could see either, because the job
names the keys refer to live in the engine.

These tests build a miniature engine checkout rather than reading the real one, so they assert
the RULE and stay green when the engine's own lane list changes.
"""
from __future__ import annotations

import importlib.util
import json
import pathlib

import pytest
import yaml

REPO = pathlib.Path(__file__).resolve().parent.parent
SCRIPT = REPO / "scripts" / "check_prompt_bindings.py"


def load_module():
    spec = importlib.util.spec_from_file_location("check_prompt_bindings", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


mod = load_module()


@pytest.fixture
def engine(tmp_path):
    """A two-lane engine: one plain engine-template lane, one CONTRACTED one."""
    cfg = tmp_path / "engine" / "config"
    cfg.mkdir(parents=True)
    (cfg / "engine-crons.json").write_text(json.dumps([
        {"name": "raw-backfill", "no_agent": False},
        {"name": "page-quality-enrich", "no_agent": False,
         "output_contract": {"api": 1, "completion": "run"}},
        {"name": "index-rebuild", "no_agent": True},
    ]), encoding="utf-8")
    (cfg / "cron-tiers.yaml").write_text(yaml.safe_dump({
        "engine": ["index-rebuild"],
        "engine-template": ["raw-backfill", "page-quality-enrich"],
        "domain": [],
    }), encoding="utf-8")
    return tmp_path / "engine"


def write_pack(root: pathlib.Path, name: str, prompts: dict, domain=None):
    crons = root / name / "crons"
    crons.mkdir(parents=True)
    (crons / "engine-template-prompts.json").write_text(json.dumps(prompts), encoding="utf-8")
    if domain is not None:
        (crons / "domain-crons.json").write_text(json.dumps(domain), encoding="utf-8")
    return root


# --- the derivation itself ----------------------------------------------------------------

def test_a_contracted_model_lane_binds_its_own_writer():
    """`bind_contract_writers` routes a contracted lane away from the generic/admin writer."""
    job = {"name": "page-quality-enrich", "output_contract": {"api": 1}}
    assert mod.expected_writer(job) == "okengine-write-page-quality-enrich"


def test_an_uncontracted_lane_and_a_script_lane_both_keep_the_generic_writer():
    """Two different reasons to stay generic: no contract at all, and no_agent."""
    assert mod.expected_writer({"name": "raw-backfill"}) == "okengine-write"
    assert mod.expected_writer(
        {"name": "x", "no_agent": True, "output_contract": {"api": 1}}) == "okengine-write"


def test_the_hermes_tool_name_maps_every_non_word_character():
    """Hermes publishes mcp__<server>__<tool>; `-` and `.` are not word characters there, and a
    prompt written against the un-sanitized spelling names a tool that cannot resolve."""
    assert mod.sanitize("okengine-write-page-quality-enrich") == "okengine_write_page_quality_enrich"
    assert mod.sanitize("okengine.predictions:grade") == "okengine_predictions_grade"


# --- what the gate catches ----------------------------------------------------------------

def test_a_prompt_key_that_resolves_to_no_lane_fails(tmp_path, engine):
    """The okengine#562 defect exactly: a key left behind when its lane moved to an extension."""
    packs = write_pack(tmp_path / "packs", "okpack-demo", {"prediction-grade": "grade things"})
    failures, seen_packs, seen_prompts = mod.check(packs, engine)
    assert seen_packs == 1 and seen_prompts == 1
    assert len(failures) == 1
    assert "prediction-grade" in failures[0] and "engine-template" in failures[0]


def test_a_prompt_key_for_a_pure_engine_lane_fails_too(tmp_path, engine):
    """`index-rebuild` EXISTS in the engine but is not engine-template, so a pack cannot drive
    it. Checking existence alone would pass this and the prompt would still go nowhere."""
    packs = write_pack(tmp_path / "packs", "okpack-demo", {"index-rebuild": "rebuild"})
    failures, _, _ = mod.check(packs, engine)
    assert len(failures) == 1 and "index-rebuild" in failures[0]


def test_a_prompt_naming_the_generic_writer_on_a_contracted_lane_fails(tmp_path, engine):
    """The prompt still WORKS — the model resolves tools from the tool list — so no runtime
    signal exists. That is the whole reason this is checked statically."""
    packs = write_pack(tmp_path / "packs", "okpack-demo",
                       {"page-quality-enrich": "call mcp__okengine_write__append_to_section"})
    failures, _, _ = mod.check(packs, engine)
    assert len(failures) == 1
    assert "mcp__okengine_write__append_to_section" in failures[0]
    assert "mcp__okengine_write_page_quality_enrich__append_to_section" in failures[0]


def test_a_prompt_naming_the_per_lane_writer_on_a_generic_lane_fails(tmp_path, engine):
    """The mirror image — over-specific is as wrong as under-specific, and a rule that only
    checked one direction would pass a prompt naming a server the lane never binds."""
    packs = write_pack(tmp_path / "packs", "okpack-demo",
                       {"raw-backfill": "call mcp__okengine_write_raw_backfill__create_entity"})
    failures, _, _ = mod.check(packs, engine)
    assert len(failures) == 1 and "mcp__okengine_write__create_entity" in failures[0]


def test_domain_job_prompts_are_checked_against_their_own_contract(tmp_path, engine):
    """A domain job carries its own definition, so its expected writer comes from the job, not
    from the engine. A gate that only read engine-template prompts would miss every one."""
    packs = write_pack(
        tmp_path / "packs", "okpack-demo", {},
        domain=[{"name": "demo-digest", "output_contract": {"api": 1},
                 "prompt": "write via mcp__okengine_write__create_entity"}])
    failures, _, _ = mod.check(packs, engine)
    assert len(failures) == 1
    assert "mcp__okengine_write_demo_digest__create_entity" in failures[0]


def test_a_dict_shaped_prompt_is_read_not_skipped(tmp_path, engine):
    """Prompts come as a bare string OR {"prompt": ..., "output_contract": ...}. Handling only
    the first is how a pack gets silently skipped — it hid okpack-example from an earlier scan."""
    packs = write_pack(tmp_path / "packs", "okpack-demo",
                       {"page-quality-enrich": {"prompt": "mcp__okengine_write__update_entity",
                                                "output_contract": {"api": 1}}})
    failures, _, _ = mod.check(packs, engine)
    assert len(failures) == 1


# --- what the gate refuses to call a pass -------------------------------------------------

def test_correct_prompts_pass(tmp_path, engine):
    """The gate has to be capable of passing, or the failing tests above prove nothing."""
    packs = write_pack(
        tmp_path / "packs", "okpack-demo",
        {"raw-backfill": "call mcp__okengine_write__create_entity",
         "page-quality-enrich": "call mcp__okengine_write_page_quality_enrich__append_to_section"})
    failures, seen_packs, seen_prompts = mod.check(packs, engine)
    assert failures == [] and seen_packs == 1 and seen_prompts == 2


def test_an_engine_checkout_with_no_lanes_is_undetectable_not_a_pass(tmp_path):
    """An engine clone that yielded nothing is the state where this gate knows least — and it
    is also the state that looks identical to "everything is fine" if you only count failures."""
    cfg = tmp_path / "engine" / "config"
    cfg.mkdir(parents=True)
    (cfg / "engine-crons.json").write_text("[]", encoding="utf-8")
    (cfg / "cron-tiers.yaml").write_text(yaml.safe_dump({"engine-template": []}), encoding="utf-8")
    packs = write_pack(tmp_path / "packs", "okpack-demo", {"raw-backfill": "x"})
    failures, _, _ = mod.check(packs, tmp_path / "engine")
    assert len(failures) == 1 and "UNDETECTABLE" in failures[0]


def test_examining_no_packs_fails_rather_than_reporting_success(tmp_path, engine, capsys,
                                                                monkeypatch):
    """A moved layout makes the glob match nothing. Zero failures over zero prompts is not a
    green gate — it is a gate that was not run."""
    monkeypatch.setenv("ENGINE_DIR", str(engine))
    empty = tmp_path / "packs"
    empty.mkdir()
    assert mod.main([str(empty)]) == 1
    assert "examined nothing" in capsys.readouterr().out


def test_without_an_engine_it_reports_skipped_locally_and_fails_in_ci(tmp_path, capsys,
                                                                     monkeypatch):
    """Two different right answers for the same missing input: a developer without an engine
    checkout gets told what was skipped; the required CI lane fails closed."""
    monkeypatch.delenv("ENGINE_DIR", raising=False)
    monkeypatch.delenv("OKENGINE_DIR", raising=False)
    monkeypatch.delenv("CI", raising=False)
    assert mod.main([str(tmp_path)]) == 0
    assert "UNDETECTABLE" in capsys.readouterr().out

    monkeypatch.setenv("CI", "true")
    assert mod.main([str(tmp_path)]) == 1
    assert "required check in CI" in capsys.readouterr().out


def test_the_real_packs_pass_against_the_real_engine_when_one_is_available(monkeypatch):
    """The live assertion. Skipped without an engine checkout — and that skip is visible,
    which is the point: it does not masquerade as a pass."""
    import os
    engine = os.environ.get("ENGINE_DIR") or os.environ.get("OKENGINE_DIR")
    if not engine or not (pathlib.Path(engine) / "config" / "engine-crons.json").is_file():
        pytest.skip("no ENGINE_DIR checkout — binding check UNDETECTABLE here")
    failures, packs, prompts = mod.check(REPO / "packs", pathlib.Path(engine))
    assert packs > 0 and prompts > 0
    assert failures == [], "\n".join(failures)
