"""Original-source identity checks and mention counts at the real installed engine boundary."""
import json
import importlib
import sys
from pathlib import Path

import pytest

from test_actor_context_mentions import fm, lane, shared_writer, write
import actor_mentions

VICTIM = "Waterford Hotel Group suffered a data breach. The Interlock ransomware group claimed responsibility for the incident."
FABRICATED = "Waterford Hotel Group is a cybercriminal intrusion set that claimed responsibility for a ransomware attack."


@pytest.fixture(autouse=True)
def engine_identity_libraries(monkeypatch):
    """Creation uses real engine identity libraries, not ambient stand-ins from other suites."""
    import okengine.actor_identity
    scripts = Path(okengine.actor_identity.__file__).resolve().parents[2] / "scripts/cron"
    assert scripts.is_dir(), "required real engine checkout has no identity scripts"
    monkeypatch.syspath_prepend(str(scripts))
    modules = {}
    for name in ("id_lib", "schema_lib", "id_index"):
        monkeypatch.delitem(sys.modules, name, raising=False)
        module = importlib.import_module(name)
        assert Path(module.__file__).resolve().is_relative_to(scripts), name
        modules[name] = module
    import _okf_write
    for name, module in modules.items():
        monkeypatch.setattr(_okf_write, name, module)
    from importer_guard import guard
    modules["_importer_guard"] = guard
    monkeypatch.setattr(_okf_write, "_importer_guard", guard)
    return modules


@pytest.fixture
def identity_writer(shared_writer, engine_identity_libraries):
    for name, module in engine_identity_libraries.items():
        setattr(shared_writer, name, module)
    return shared_writer


def candidate(**extra):
    return {"type": "actor", "title": "Waterford Hotel Group", "actor_type": "cybercriminal",
            "sources": ["sources/incident"], "actor_identity_validated": True, "recent_news": 9, **extra}


def victim_source(wiki, prose=VICTIM):
    write(wiki / "sources/incident.md", {"type": "source", "title": "Incident"}, "# Incident\n" + prose)


@pytest.mark.parametrize("existing", [False, True])
def test_six_writers_reject_fabricated_victim_actor_before_publication(tmp_path, existing, identity_writer):
    wiki = tmp_path / "wiki"
    victim_source(wiki)
    target = wiki / "entities/waterford-hotel-group.md"
    if existing:
        write(target, candidate(), FABRICATED)
    before = target.read_bytes() if existing else None

    with pytest.raises(ValueError, match="actor write refused"):
        identity_writer.write_page(wiki, "entities/waterford-hotel-group", candidate(), FABRICATED)

    if existing:
        assert target.read_bytes() == before
    else:
        assert not target.exists()


def test_six_writers_nonactor_victim_is_compatible_and_real_attacker_survives(tmp_path, identity_writer):
    wiki = tmp_path / "wiki"
    victim_source(wiki)
    identity_writer.write_page(wiki, "entities/waterford-hotel-group",
                            candidate(type="identity"), "Waterford Hotel Group is a hotel company.")
    assert fm(wiki / "entities/waterford-hotel-group.md")["type"] == "identity"
    identity_writer.write_page(wiki, "entities/interlock-ransomware",
                            {"type": "actor", "title": "Interlock Ransomware", "sources": ["sources/incident"]},
                            "Interlock Ransomware is a ransomware operation.")
    assert fm(wiki / "entities/interlock-ransomware.md")["type"] == "actor"


@pytest.mark.parametrize("prose", [
    VICTIM,
    "Interlock attacked Waterford Hotel Group.",
    "Waterford Hotel Group was attacked by Interlock.",
    "Waterford Hotel Group disclosed a breach affecting its customers.",
    "Waterford Hotel Group was the victim of a ransomware attack.",
    VICTIM + " Waterford Hotel Group targets hospitality customers.",
    VICTIM + " Waterford Hotel Group deploys recovery tooling.",
    VICTIM + " Waterford Hotel Group attacks breach rumors.",
    VICTIM + " Waterford Hotel Group denied launching a ransomware attack.",
    VICTIM + "\n\n## Actors named in this report\n- [[waterford-hotel-group|Waterford Hotel Group is a cybercriminal group]]\n",
])
def test_roster_original_role_overrides_fabricated_body_and_metadata(tmp_path, prose):
    wiki = tmp_path / "wiki"
    victim_source(wiki, prose)
    assert not actor_mentions.eligible(candidate(attack_id="G9999", authority_ids=["forged"]), FABRICATED, wiki)
    assert actor_mentions.eligible({"type": "actor", "title": "Interlock Ransomware"},
                                   "Interlock Ransomware is a ransomware operation.", wiki)


@pytest.mark.parametrize("extra_source", [None, "missing", "unreadable", "positive"])
def test_roster_mixed_cited_sources_preserve_known_contradiction_and_dual_role(tmp_path, extra_source):
    wiki = tmp_path / "wiki"
    victim_source(wiki)
    sources = ["sources/incident"]
    if extra_source:
        sources.append("sources/" + extra_source)
    if extra_source == "unreadable":
        (wiki / "sources/unreadable.md").write_bytes(b"\xff")
    if extra_source == "positive":
        write(wiki / "sources/positive.md", {"type": "source"},
              "Waterford Hotel Group is a ransomware actor launching unauthorized malware attacks.")
    assert actor_mentions.eligible(candidate(sources=sources), FABRICATED, wiki) is (extra_source == "positive")


def test_roster_missing_unreadable_and_unknown_sources_keep_existing_unknown_behavior(tmp_path):
    wiki = tmp_path / "wiki"
    (wiki / "sources").mkdir(parents=True)
    (wiki / "sources/unreadable.md").write_bytes(b"\xff")
    for sources in ([], ["sources/missing"], ["sources/unreadable"]):
        assert actor_mentions.eligible(candidate(sources=sources), FABRICATED, wiki)
    victim_source(wiki, "Waterford Hotel Group appeared in reporting about security.")
    assert actor_mentions.eligible(candidate(), FABRICATED, wiki)


def test_news_and_report_rosters_exclude_false_victim_and_retain_attacker(tmp_path):
    from datetime import datetime, timezone
    wiki = tmp_path / "wiki"
    victim_source(wiki)
    source = wiki / "sources/incident.md"
    write(source, {"type": "source", "title": "Incident", "source_kind": "news",
                   "published": datetime.now(timezone.utc).date().isoformat(),
                   "mentions_actors": ["waterford-hotel-group", "interlock-ransomware"]}, VICTIM)
    false_actor = wiki / "entities/waterford-hotel-group.md"
    write(false_actor, candidate(), FABRICATED)
    true_actor = wiki / "entities/interlock-ransomware.md"
    write(true_actor, {"type": "actor", "title": "Interlock Ransomware", "sources": ["sources/incident"]},
          "Interlock Ransomware is a ransomware operation.")
    before = false_actor.read_bytes()

    for _ in range(2):
        assert lane("actor_news_activity").main(["--vault", str(tmp_path)]) == 0
        assert lane("actor_activity").main(["--vault", str(tmp_path)]) == 0
        assert false_actor.read_bytes() == before
        assert fm(true_actor)["recent_news"] == fm(true_actor)["news_total"] == 1
        assert fm(true_actor)["recent_reports"] == fm(true_actor)["total_mentions"] == 1
    assert "waterford-hotel-group" not in (wiki / "dashboards/top-actors-by-activity.md").read_text()


@pytest.mark.parametrize("mention", ["Silence was attacked by another actor.", "Silence denied responsibility for this incident."])
def test_independent_real_actor_victimization_and_incident_denial_are_mentions(tmp_path, mention):
    wiki = tmp_path / "wiki"
    write(wiki / "sources/identity.md", {"type": "source"},
          "Silence is a cybercriminal group launching ransomware attacks.")
    actor_fm = {"type": "actor", "title": "Silence", "sources": ["sources/identity"]}
    assert actor_mentions.eligible(actor_fm, "Silence is a group.", wiki)
    assert actor_mentions.mentions(mention, {"silence": "silence"}) == {"silence"}
    assert actor_mentions.explicit_mention_supported(mention, {"silence"})


def test_dual_role_actor_canonical_source_survives_contrary_alias(tmp_path):
    wiki = tmp_path / "wiki"
    write(wiki / "sources/identity.md", {"type": "source"},
          "Crimson Holdings is a ransomware actor launching unauthorized malware attacks. "
          "Crimson Holdings was attacked by a rival group. Alibaba suffered a data breach.")
    assert actor_mentions.eligible({"type": "actor", "title": "Crimson Holdings", "aliases": ["Alibaba"],
                                   "sources": ["sources/identity"]}, "Crimson Holdings is a threat actor.", wiki)


def test_audit_checks_original_role_before_forged_authority_and_preserves_dry_run(tmp_path):
    wiki = tmp_path / "wiki"
    victim_source(wiki)
    path = wiki / "entities/waterford-hotel-group.md"
    forged = candidate(attack_id="G9999", authority_ids=["forged"], review_status="auto-verified", consensus=5)
    write(path, forged, FABRICATED)
    before = path.read_bytes()
    audit = lane("actor_identity_audit")

    assert audit.classify(forged, FABRICATED, path, wiki=wiki)[0] == "tombstone"
    assert audit.main(["--vault", str(tmp_path)]) == 0
    assert path.read_bytes() == before


def test_import_indexes_and_annual_report_do_not_reinforce_false_victim(tmp_path, monkeypatch):
    wiki = tmp_path / "wiki"
    victim_source(wiki)
    write(wiki / "entities/waterford-hotel-group.md", candidate(), FABRICATED)
    write(wiki / "entities/interlock.md", {"type": "actor", "title": "Interlock", "sources": ["sources/incident"]},
          "Interlock is a ransomware group.")
    importer = lane("misp_galaxy_import")
    assert "waterford hotel group" not in importer.index_actors(wiki)
    assert "waterford hotel group" not in importer.primary_actor_index(wiki)
    report = tmp_path / "reports/Markdown Conversions/2024/vendor-ransomware.md"
    report.parent.mkdir(parents=True)
    report.write_text("# Ransomware Report\n" + VICTIM)
    monkeypatch.setenv("ANNUAL_REPORTS_INCLUDE", "ransomware")

    assert lane("annual_reports_import").main(["--vault", str(tmp_path), "--dir", str(tmp_path / "reports"), "--years", "2024"]) == 0

    target = wiki / "sources/2024-01-01-ransomware-report.md"
    assert fm(target)["mentions_actors"] == ["interlock"]
    assert "Waterford Hotel Group suffered a data breach" in target.read_text()


def test_pack_entity_prompt_grounding_distinguishes_victim_from_attacker():
    path = Path(__file__).resolve().parents[1] / "crons/engine-template-prompts.json"
    prompt = json.loads(path.read_text())["entity-backfill"]
    assert "Do not transfer another subject's attack" in prompt
    assert "original source support" in prompt
    assert "otherwise skip or defer" in prompt


def test_unicode_named_victim_and_wrong_subject_boundaries(tmp_path):
    wiki = tmp_path / "wiki"
    write(wiki / "sources/incident.md", {"type": "source", "title": "Incident"},
          "# Incident\n**Hôtel Étoile** suffered a data breach. Interlock claimed responsibility.")
    assert not actor_mentions.eligible({"type": "actor", "title": "Hôtel Étoile",
                                       "sources": ["sources/incident"]},
                                      "Hôtel Étoile is a cybercriminal group.", wiki)
    assert actor_mentions.eligible({"type": "actor", "title": "Étoile Delta",
                                   "sources": ["sources/incident"]}, "Étoile Delta is a group.", wiki)


def test_original_heading_is_not_adversarial_role_support(tmp_path):
    wiki = tmp_path / "wiki"
    write(wiki / "sources/incident.md", {"type": "source",
                                       "title": "Waterford Hotel Group is a ransomware actor"},
          "# Waterford Hotel Group is a ransomware actor\n" + VICTIM)
    assert not actor_mentions.eligible(candidate(), FABRICATED, wiki)


def test_named_victim_possessive_object_does_not_contradict_company_identity(tmp_path):
    wiki = tmp_path / "wiki"
    for possessive in ("'s", "’s"):
        write(wiki / "sources/incident.md", {"type": "source"},
              f"Nightlock attacked Harbor Hotel Group{possessive} supplier.")
        assert actor_mentions.eligible({"type": "actor", "title": "Harbor Hotel Group",
                                       "sources": ["sources/incident"]}, "Observed intrusion set.", wiki)


@pytest.mark.parametrize("actor_type", ["threat-actor", "threat_actor", "intrusion-set", "Actor"])
@pytest.mark.parametrize("existing", [False, True])
def test_six_writers_resolve_supported_actor_type_before_source_guard(
        tmp_path, actor_type, existing, identity_writer):
    wiki = tmp_path / "wiki"
    definition = Path(__file__).resolve().parents[1] / "schema.yaml"
    (tmp_path / "schema.yaml").write_bytes(definition.read_bytes())
    victim_source(wiki)
    target = wiki / "entities/waterford-hotel-group.md"
    if existing:
        write(target, candidate(type=actor_type), FABRICATED)
    before = target.read_bytes() if existing else None

    with pytest.raises(ValueError, match="actor write refused"):
        identity_writer.write_page(wiki, "entities/waterford-hotel-group",
                                   candidate(type=actor_type), FABRICATED)

    if existing:
        assert target.read_bytes() == before
    else:
        assert not target.exists()


@pytest.mark.parametrize("name", ["actor_news_activity", "actor_activity"])
def test_invalid_utf8_maintenance_source_is_unreadable_and_retains_activity(tmp_path, name):
    wiki = tmp_path / "wiki"
    target = wiki / "entities/silence.md"
    write(target, {"type": "actor", "title": "Silence", "recent_news": 3, "news_total": 4,
                   "recent_reports": 2, "total_mentions": 2}, "Silence is a threat group.")
    source = wiki / "sources/unreadable.md"
    source.parent.mkdir(parents=True)
    source.write_bytes(b"---\ntype: source\nsource_kind: news\nmentions_actors: [silence]\n---\ninvalid \xff source")
    before = target.read_bytes()

    assert lane(name).main(["--vault", str(tmp_path)]) == 1

    assert target.read_bytes() == before
