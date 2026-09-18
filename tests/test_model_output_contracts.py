import json
from pathlib import Path


ROOT = Path(__file__).parents[1]


def _job(pack, name):
    jobs = json.loads((ROOT / "packs" / pack / "crons" / "domain-crons.json").read_text())
    return next(job for job in jobs if job["name"] == name)


def test_cti_weekly_briefs_are_grounded_briefing_only_lanes():
    lanes = [
        _job("okpack-threat-actors", "okpack-threat-actors-weekly-brief"),
        _job("okpack-threat-landscape", "okpack-threat-landscape-weekly-brief"),
    ]
    for lane in lanes:
        contract = lane["output_contract"]
        assert contract["allowed_namespaces"] == ["briefings"]
        assert contract["allowed_types"] == ["briefing"]
        assert set(contract["operations"]) <= {"create", "update"}
        assert contract["body"]["required"] and contract["body"]["min_non_whitespace"] >= 200
        assert contract["unresolved_links"] == "reject"
        assert contract["placeholder_links"] == "reject"
        assert "tests/test_model_output_contracts.py" in lane["adversarial_fixtures"]


def test_brief_prompts_require_resolving_source_grounding():
    actors = _job("okpack-threat-actors", "okpack-threat-actors-weekly-brief")["prompt"]
    landscape = _job("okpack-threat-landscape", "okpack-threat-landscape-weekly-brief")["prompt"]
    assert "EVERY item" in actors and "[[sources/...]]" in actors
    assert "LOCAL-ONLY" in landscape and "[[trends/theme-...]]" in landscape


def test_cti_ingest_prompts_separate_source_compilation_from_entity_extraction():
    prompts = json.loads(
        (ROOT / "packs" / "okpack-threat-actors" / "crons" / "engine-template-prompts.json").read_text()
    )
    raw = prompts["raw-backfill"]
    entity = prompts["entity-backfill"]

    assert "SOURCE-ONLY" in raw
    assert "MUST NOT create or update entities" in raw
    assert "okengine-receipt" in raw
    assert "lane_id, contract_digest, and input_digest" in raw
    assert "accepted, duplicate, skipped, rejected, failed, or deferred" in raw
    assert "downstream entity lane" in entity
    assert "must cite at least one source page that exists" in entity
    assert "Never create source, concept, prediction, finding, or briefing" in entity


def test_cti_persona_documents_staged_ingest_boundaries():
    persona = (ROOT / "packs" / "okpack-threat-actors" / "CLAUDE.md").read_text()
    assert "Staged ingest workflow (sources, then entities)" in persona
    assert "lane stops after writing a complete accepted source" in persona
    assert "must not create or update entities, concepts" in persona
    assert "enriched entity must cite a resolving source page" in persona


def test_example_pack_scaffolds_contracted_staged_ingest():
    pack = ROOT / "packs" / "okpack-example"
    prompts = json.loads((pack / "crons" / "engine-template-prompts.json").read_text())
    raw = prompts["raw-backfill"]
    contract = raw["output_contract"]

    assert "SOURCE-ONLY" in raw["prompt"]
    assert "okengine-receipt" in raw["prompt"]
    assert "lane_id, contract_digest, and input_digest" in raw["prompt"]
    assert contract["allowed_namespaces"] == ["sources"]
    assert contract["allowed_types"] == ["source"]
    assert contract["completion"] == "per-selected-item"
    assert contract["body"]["required"] and contract["body"]["min_non_whitespace"] >= 80
    assert contract["unresolved_links"] == "reject"
    assert contract["placeholder_links"] == "reject"

    entity = prompts["entity-backfill"]
    assert "downstream entity lane" in entity
    assert "must cite at least one source page that exists" in entity
    assert "Never create source, concept, prediction, finding, or briefing" in entity


def test_example_pack_copy_retains_staged_model_write_rules(tmp_path):
    import shutil

    source = ROOT / "packs" / "okpack-example"
    generated = tmp_path / "okpack-new-domain"
    shutil.copytree(source, generated)

    prompts = json.loads((generated / "crons" / "engine-template-prompts.json").read_text())
    persona = (generated / "CLAUDE.md").read_text()
    readme = (generated / "README.md").read_text()
    assert prompts["raw-backfill"]["output_contract"]["completion"] == "per-selected-item"
    assert "Staged ingest workflow (sources, then entities)" in persona
    assert "source lane must not create or update entities" in persona
    assert "Safe staged model-write lanes" in readme


def test_every_library_raw_and_entity_prompt_uses_staged_boundaries():
    exempt = set()
    for pack in sorted((ROOT / "packs").glob("okpack-*")):
        path = pack / "crons" / "engine-template-prompts.json"
        if not path.is_file():
            continue
        prompts = json.loads(path.read_text())
        raw_value = prompts.get("raw-backfill")
        raw = raw_value.get("prompt", "") if isinstance(raw_value, dict) else raw_value or ""
        entity = prompts.get("entity-backfill") or ""
        if isinstance(entity, dict):
            entity = entity.get("prompt", "")
        assert "SOURCE-ONLY" in raw, f"{pack.name} raw lane is not source-only"
        assert "okengine-receipt" in raw, f"{pack.name} raw lane lacks exact receipts"
        assert "lane_id" in raw and "contract_digest" in raw and "input_digest" in raw
        assert "accepted" in entity.lower(), f"{pack.name} entity lane does not consume accepted sources"
        assert "resolving source" in entity.lower() or "source page that exists" in entity.lower()


def test_ai_research_weekly_brief_is_contracted_and_grounded():
    lane = _job("okpack-ai-research", "okpack-ai-research-weekly-brief")
    contract = lane["output_contract"]
    assert contract["allowed_namespaces"] == ["briefings"]
    assert contract["allowed_types"] == ["briefing"]
    assert contract["body"]["required"] and contract["body"]["min_non_whitespace"] >= 200
    assert contract["unresolved_links"] == "reject"
    assert "EVERY item" in lane["prompt"] and "Source: [[sources/...]]" in lane["prompt"]
