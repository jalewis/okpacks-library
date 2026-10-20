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
    write_engine_rule(tmp_path / "engine", ENGINE_RULE)
    return tmp_path / "engine"


# The engine's writer-name rule, as a stand-in checkout provides it. The checker loads this from
# ENGINE_DIR rather than carrying its own copy, so a test engine has to supply one, exactly as it
# supplies engine-crons.json. Short names are identical under the bounded rule (okengine#840).
ENGINE_RULE = """
import re
def contract_writer_name(job_name):
    return "okengine-write-" + re.sub(r"[^a-z0-9]+", "-", job_name.lower()).strip("-")
"""


def write_engine_rule(engine_dir: pathlib.Path, source: str) -> None:
    scripts = engine_dir / "scripts"
    scripts.mkdir(parents=True, exist_ok=True)
    (scripts / "cron_pack_split.py").write_text(source, encoding="utf-8")


def write_pack(root: pathlib.Path, name: str, prompts: dict, domain=None):
    crons = root / name / "crons"
    crons.mkdir(parents=True)
    (crons / "engine-template-prompts.json").write_text(json.dumps(prompts), encoding="utf-8")
    if domain is not None:
        (crons / "domain-crons.json").write_text(json.dumps(domain), encoding="utf-8")
    return root


# --- the derivation itself ----------------------------------------------------------------

def test_a_contracted_model_lane_binds_its_own_writer(engine):
    """`bind_contract_writers` routes a contracted lane away from the generic/admin writer."""
    job = {"name": "page-quality-enrich", "output_contract": {"api": 1}}
    rule = mod.engine_writer_name(engine)
    assert mod.expected_writer(job, rule) == "okengine-write-page-quality-enrich"


def test_an_uncontracted_lane_and_a_script_lane_both_keep_the_generic_writer(engine):
    """Two different reasons to stay generic: no contract at all, and no_agent."""
    rule = mod.engine_writer_name(engine)
    assert mod.expected_writer({"name": "raw-backfill"}, rule) == "okengine-write"
    assert mod.expected_writer(
        {"name": "x", "no_agent": True, "output_contract": {"api": 1}}, rule) == "okengine-write"


def test_the_checker_follows_the_engines_rule_not_a_copy_of_its_own(tmp_path, engine):
    """The okengine#840 failure: a mirrored rule kept certifying names the engine had stopped
    producing. Give the stand-in engine a rule no copy could have guessed, and the checker must
    expect exactly what it says."""
    write_engine_rule(engine, 'def contract_writer_name(n):\n    return "okengine-write-x" + str(len(n))\n')
    packs = write_pack(tmp_path / "packs", "okpack-demo",
                       {"page-quality-enrich": "call mcp__okengine_write_x19__append_to_section"})
    failures, _, _ = mod.check(packs, engine)
    assert failures == [], failures
    packs2 = write_pack(tmp_path / "packs2", "okpack-demo",
                        {"page-quality-enrich":
                         "call mcp__okengine_write_page_quality_enrich__append_to_section"})
    failures, _, _ = mod.check(packs2, engine)
    assert len(failures) == 1 and "okengine_write_x19" in failures[0], failures


def test_an_unloadable_engine_rule_is_undetectable_not_a_pass(tmp_path, engine):
    """No rule means no expected writer: that is not knowledge that every prompt is right."""
    write_engine_rule(engine, "raise ImportError('broken engine checkout')\n")
    packs = write_pack(tmp_path / "packs", "okpack-demo",
                       {"raw-backfill": "call mcp__okengine_write__create_entity"})
    failures, _, _ = mod.check(packs, engine)
    assert len(failures) == 1 and "UNDETECTABLE" in failures[0], failures
    assert "cron_pack_split.py" in failures[0]


def test_an_early_failure_prints_its_reason(tmp_path, engine, capsys, monkeypatch):
    """A failure that stops the check before it examines anything must still say why."""
    monkeypatch.setenv("ENGINE_DIR", str(engine))
    write_engine_rule(engine, "raise ImportError('broken engine checkout')\n")
    packs = write_pack(tmp_path / "packs", "okpack-demo", {"raw-backfill": "x"})
    assert mod.main([str(packs)]) == 1
    assert "broken engine checkout" in capsys.readouterr().out


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


# --- selector scripts are prompt text too -------------------------------------------------

def write_selector(root: pathlib.Path, pack: str, name: str, body: str) -> None:
    scripts = root / pack / "crons" / "scripts"
    scripts.mkdir(parents=True, exist_ok=True)
    (scripts / name).write_text(body, encoding="utf-8")


def test_a_selector_naming_a_stale_writer_fails(tmp_path, engine):
    """The digest a selector prints is what the model reads; a writer it names is a prompt."""
    packs = write_pack(tmp_path / "packs", "okpack-demo", {},
                       domain=[{"name": "demo-digest", "script": "select_demo.py",
                                "output_contract": {"api": 1}, "prompt": "go"}])
    write_selector(packs, "okpack-demo", "select_demo.py",
                   'print("write via mcp__okengine_write__create_entity")\n')
    failures, _, _ = mod.check(packs, engine)
    assert len(failures) == 1 and "select_demo.py" in failures[0], failures
    assert "mcp__okengine_write_demo_digest__create_entity" in failures[0]


def test_a_selector_naming_its_jobs_writer_passes(tmp_path, engine):
    packs = write_pack(tmp_path / "packs", "okpack-demo", {},
                       domain=[{"name": "demo-digest", "script": "select_demo.py",
                                "output_contract": {"api": 1}, "prompt": "go"}])
    write_selector(packs, "okpack-demo", "select_demo.py",
                   'print("write via mcp__okengine_write_demo_digest__create_entity")\n')
    assert mod.check(packs, engine)[0] == []


def test_a_selector_shared_by_two_jobs_may_name_either_writer(tmp_path, engine):
    """One script, two lanes: naming either lane's writer is right, a third is not."""
    domain = [{"name": "digest-a", "script": "select_shared.py",
               "output_contract": {"api": 1}, "prompt": "go"},
              {"name": "digest-b", "script": "select_shared.py",
               "output_contract": {"api": 1}, "prompt": "go"}]
    packs = write_pack(tmp_path / "packs", "okpack-demo", {}, domain=domain)
    write_selector(packs, "okpack-demo", "select_shared.py",
                   'A = "mcp__okengine_write_digest_a__create_entity"\n'
                   'B = "mcp__okengine_write_digest_b__update_entity"\n')
    assert mod.check(packs, engine)[0] == []
    write_selector(packs, "okpack-demo", "select_shared.py",
                   'C = "mcp__okengine_write_digest_c__create_entity"\n')
    failures, _, _ = mod.check(packs, engine)
    assert len(failures) == 1 and "digest_c" in failures[0], failures


def test_a_job_whose_selector_is_absent_is_left_to_the_existence_check(tmp_path, engine):
    packs = write_pack(tmp_path / "packs", "okpack-demo", {},
                       domain=[{"name": "demo-digest", "script": "select_missing.py",
                                "output_contract": {"api": 1}, "prompt": "go"}])
    assert mod.check(packs, engine)[0] == []
