"""Real sourced severity prose, roster decisions, and complete activity recomputation."""
import importlib.util
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml

SCRIPTS = Path(__file__).resolve().parents[1] / "crons/scripts"
sys.path.insert(0, str(SCRIPTS))
import actor_mentions


def lane(name):
    spec = importlib.util.spec_from_file_location("context_" + name, SCRIPTS / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(params=["threat-actors", "ai-research", "detections", "incidents", "indicators", "threat-landscape"])
def shared_writer(request):
    path = SCRIPTS.parents[2] / ("okpack-" + request.param) / "crons/scripts/_okf_write.py"
    spec = importlib.util.spec_from_file_location("shared_writer_" + request.param.replace("-", "_"), path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write(path, fm, body=""):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("---\n" + yaml.safe_dump(fm, sort_keys=False) + "---\n\n" + body + "\n")


def fm(path):
    text = path.read_text()
    return yaml.safe_load(text[3:text.find("\n---", 3)])


@pytest.mark.parametrize("text", [
    "More than 65% of exploited edge vulnerabilities met GTIG’s High or Critical threat-risk ratings.",
    "Enterprise leaders recognize ransomware as a critical threat.",
    "| Very critical threat score SAIDs (71-99) | 21 |",
])
def test_severity_class_prose_is_not_a_named_actor_mention(text):
    assert actor_mentions.mentions(text, {"critical threat": "critical-threat"}) == set()
    assert not actor_mentions.explicit_mention_supported(text + "\n\n## Actors named in this report\n\n- [[critical-threat]]\n", {"critical threat"})


@pytest.mark.parametrize("name,text", [
    ("Silence", "Silence is a threat group targeting mailboxes."),
    ("IT", "The intrusion set known as IT attacked several banks."),
    ("XQ", "XQ exfiltrated private mailboxes."),
    ("Unfamiliar Delta", "Unfamiliar Delta appeared in new reporting."),
    ("Critical Threat", "The group named Critical Threat attacked bank networks."),
])
def test_legitimate_common_short_and_unfamiliar_names_survive_context(name, text):
    terms = actor_mentions.terms_for({"title": name})
    assert actor_mentions.mentions(text, {term: "actor" for term in terms}) == {"actor"}


def test_contrary_alias_does_not_silence_independent_primary_name():
    text = "Alibaba patches its library. Operation Cleaver campaign resurfaces."
    assert actor_mentions.mentions(text, {"alibaba": "cleaver", "operation cleaver": "cleaver"}) == {"cleaver"}
    assert not actor_mentions.mentions("Alibaba patches its library.", {"alibaba": "cleaver"})
    assert not actor_mentions.mentions("Silence is not a threat actor.", {"silence": "silence"})


def test_roster_guard_rejects_vulnerability_subject_but_retains_unfamiliar_actor():
    assert not actor_mentions.eligible({"type": "actor", "title": "Critical Threat"},
        "A critical Windows driver vulnerability (CVE-2026-68820) allows escalation to SYSTEM.")
    assert actor_mentions.eligible({"type": "actor", "title": "Novel Cluster"}, "Observed targeting mailboxes.")
    assert not actor_mentions.eligible({"type": "actor", "title": "Novel Cluster", "status": "tombstoned"}, "Observed targeting mailboxes.")
    assert not actor_mentions.eligible({"type": "malware", "title": "Novel Cluster"}, "Software.")


def test_news_zero_hit_and_empty_source_repeat_clear_owned_fields_only(tmp_path):
    news = lane("actor_news_activity")
    path = tmp_path / "wiki/entities/c/critical-threat.md"
    write(path, {"type": "actor", "title": "Critical Threat", "news_total": 8, "recent_news": 5,
                 "news_last_seen": "2026-01-01", "recent_news_refs": ["sources/stale"], "recent_reports": 7},
          "Critical Threat is a threat group.")
    source = tmp_path / "wiki/sources/one.md"
    write(source, {"type": "source", "source_kind": "news", "published": datetime.now(timezone.utc).date().isoformat()},
          "More than 65% met High or Critical threat-risk ratings.")
    assert news.main(["--vault", str(tmp_path)]) == 0
    after = fm(path)
    assert after["recent_news"] == after["news_total"] == 0
    assert not after.get("news_last_seen") and not after.get("recent_news_refs")
    assert after["recent_reports"] == 7
    source.unlink()
    assert news.main(["--vault", str(tmp_path)]) == 0
    assert fm(path)["recent_news"] == fm(path)["news_total"] == 0


def test_unreadable_source_retains_news_and_reports(tmp_path):
    actor = tmp_path / "wiki/entities/s/silence.md"
    write(actor, {"type": "actor", "title": "Silence", "recent_news": 3, "news_total": 4,
                  "recent_reports": 2, "total_mentions": 2}, "Silence is a threat group.")
    source = tmp_path / "wiki/sources/broken.md"
    source.parent.mkdir(parents=True)
    source.write_text("not a complete source record")
    before = actor.read_bytes()
    assert lane("actor_news_activity").main(["--vault", str(tmp_path)]) == 1
    assert actor.read_bytes() == before
    assert lane("actor_activity").main(["--vault", str(tmp_path)]) == 1
    assert actor.read_bytes() == before


def test_report_recomputation_rejects_severity_and_resets_to_zero(tmp_path):
    actor = tmp_path / "wiki/entities/c/critical-threat.md"
    write(actor, {"type": "actor", "title": "Critical Threat", "total_mentions": 2, "recent_reports": 2,
                  "recent_news": 8}, "Critical Threat is a threat group.")
    source = tmp_path / "wiki/sources/report.md"
    write(source, {"type": "source", "published": "2025-01-01", "mentions_actors": ["critical-threat"]},
          "Ransomware is a critical threat.\n\n## Actors named in this report\n\n- [[critical-threat]]")
    activity = lane("actor_activity")
    assert activity.main(["--vault", str(tmp_path)]) == 0
    after = fm(actor)
    assert after["total_mentions"] == after["recent_reports"] == 0
    assert after["activity_tier"] == "cold" and after["recent_news"] == 8
    source.unlink()
    assert activity.main(["--vault", str(tmp_path)]) == 0
    assert fm(actor)["total_mentions"] == 0


@pytest.mark.parametrize("text", [
    "The critical threat posed by ransomware is growing",
    "Critical threat from ransomware remains high",
])
def test_severity_phrase_without_named_actor_context_is_not_a_mention(text):
    assert not actor_mentions.mentions(text, {"critical threat": "critical-threat"})


def test_generated_appendix_is_not_an_independent_structured_claim():
    assert not actor_mentions.explicit_mention_supported(
        "Report text.\n\n## Actors named in this report\n- [[critical-threat]]\n",
        {"critical threat"})
    assert actor_mentions.explicit_mention_supported("Report text with external structured attribution.", {"unfamiliar delta"})


@pytest.mark.parametrize("current", [{"type": "malware"}, {"type": "actor", "status": "tombstoned"}])
def test_activity_writer_refuses_current_ineligible_record(tmp_path, current, shared_writer):
    writer = shared_writer
    wiki = tmp_path / "wiki"
    path = wiki / "entities/silence.md"
    write(path, {"title": "Silence", **current}, "Current preserved body.")
    before = path.read_bytes()
    assert writer.write_page(wiki, "entities/silence", {"recent_news": 9},
                             "Stale actor body.", require_actor=True) == "ineligible"
    assert path.read_bytes() == before



def test_annual_import_replaces_false_links_and_retains_common_actor_context(tmp_path, monkeypatch):
    importer = lane("annual_reports_import")
    wiki = tmp_path / "wiki"
    write(wiki / "entities/critical-threat.md", {"type": "actor", "title": "Critical Threat"},
          "Critical Threat is a threat group.")
    write(wiki / "entities/silence.md", {"type": "actor", "title": "Silence"},
          "Silence is a threat group.")
    report = tmp_path / "reports/Markdown Conversions/2024/Semperis-ransomware.md"
    report.parent.mkdir(parents=True)
    text = "# Ransomware Risk Report\nEnterprise leaders recognize ransomware as a critical threat.\nSilence targeted banks.\n"
    report.write_text(text)
    target = wiki / "sources/2024-01-01-ransomware-risk-report.md"
    write(target, {"type": "source", "title": "Ransomware Risk Report", "mentions_actors": ["critical-threat"]},
          text + "\n## Actors named in this report\n- [[critical-threat]]\n")
    monkeypatch.setenv("ANNUAL_REPORTS_INCLUDE", "ransomware")
    assert importer.main(["--vault", str(tmp_path), "--dir", str(tmp_path / "reports"), "--years", "2024"]) == 0
    assert fm(target)["mentions_actors"] == ["silence"]
    assert "ransomware as a critical threat" in target.read_text()
    assert "[[critical-threat]]" not in target.read_text()
    report.write_text(text.replace("Silence targeted banks.\n", ""))
    assert importer.main(["--vault", str(tmp_path), "--dir", str(tmp_path / "reports"), "--years", "2024"]) == 0
    assert "mentions_actors" not in fm(target)


def test_importer_effective_actor_body_rejection_preserves_existing_bytes(tmp_path, shared_writer):
    writer = shared_writer
    wiki = tmp_path / "wiki"
    target = wiki / "entities/critical-threat.md"
    write(target, {"type": "actor", "title": "Critical Threat"}, "Critical Threat is a threat group.")
    before = target.read_bytes()
    with pytest.raises(ValueError, match="actor write refused"):
        writer.write_page(wiki, "entities/critical-threat", {},
                          "A critical Windows driver vulnerability allows privilege escalation to SYSTEM.")
    assert target.read_bytes() == before


@pytest.mark.parametrize("prose", [
    "A critical Windows driver vulnerability allows privilege escalation to SYSTEM.",
    "Exploited vulnerabilities met High or Critical threat-risk ratings.",
])
def test_raw_writer_rejects_fabricated_actor_profile_against_original_sources(tmp_path, prose, shared_writer):
    writer = shared_writer
    wiki = tmp_path / "wiki"
    write(wiki / "sources/report.md", {"type": "source", "title": "Report"}, "# Report\n" + prose)
    target = wiki / "entities/critical-threat.md"
    write(target, {"type": "actor", "title": "Critical Threat", "sources": ["sources/report"]},
          "Critical Threat is a criminal group.")
    before = target.read_bytes()
    with pytest.raises(ValueError, match="actor write refused"):
        writer.write_page(wiki, "entities/critical-threat", {}, "Critical Threat is a criminal group targeting banks.")
    assert target.read_bytes() == before


def test_raw_writer_keeps_same_name_actor_evidence_and_unknown_source_outcomes(tmp_path, shared_writer):
    writer = shared_writer
    wiki = tmp_path / "wiki"
    write(wiki / "sources/contrary.md", {"type": "source"}, "A critical Windows vulnerability was exploited.")
    write(wiki / "sources/actor.md", {"type": "source"}, "Critical Threat targeted banks.")
    assert writer._actor_source_error(wiki, {"title": "Critical Threat", "sources": ["sources/contrary", "sources/actor"]}) is None
    assert writer._actor_source_error(wiki, {"title": "Unfamiliar Delta", "sources": ["sources/contrary"]}) is None
    assert writer._actor_source_error(wiki, {"title": "Critical Threat", "sources": ["sources/missing", "sources/../../outside"]}) is None
    (wiki / "sources/unreadable.md").write_bytes(b"\xff")
    assert writer._actor_source_error(wiki, {"title": "Critical Threat", "sources": ["sources/unreadable"]}) is None


def test_source_adapter_does_not_read_a_symlink_escape(tmp_path, shared_writer):
    writer = shared_writer
    wiki = tmp_path / "wiki"
    outside = tmp_path / "outside.md"
    outside.write_text("A critical Windows vulnerability allows escalation.")
    (wiki / "sources").mkdir(parents=True)
    (wiki / "sources/escape.md").symlink_to(outside)
    assert writer._actor_source_error(wiki, {"title": "Critical Threat", "sources": ["sources/escape"]}) is None



def test_source_adapter_supports_schema_qualified_and_singular_source_refs(tmp_path, shared_writer):
    writer = shared_writer
    wiki = tmp_path / "wiki"
    (wiki / "research").mkdir(parents=True)
    (wiki / "research/schema.yaml").write_text("types: {}\n")
    write(wiki / "research/sources/report.md", {"type": "source"},
          "A critical Windows driver vulnerability allows escalation.")
    assert writer._actor_source_error(wiki, {"title": "Critical Threat", "source": "research/sources/report"}) == "vulnerability"
    assert writer._actor_source_error(wiki, {"title": "Critical Threat", "sources": ["research/sources/report"]}) == "vulnerability"
    assert writer._actor_source_error(wiki, {"title": "Critical Threat", "sources": [], "source": "research/sources/report"}) is None



def test_candidate_term_empty_and_one_character_boundaries():
    assert actor_mentions.terms_for({"aliases": ["", "X", "XY"]}) == {"xy"}


@pytest.mark.parametrize("text, expected", [
    ("Novel Threat-risk ratings increased", set()),
    ("This poses a novel threat", set()),
    ("Novel Threat was reported", {"novel-threat"}),
])
def test_nonseverity_threat_phrase_senses(text, expected):
    assert actor_mentions.mentions(text, {"novel threat": "novel-threat"}) == expected


def test_missing_installed_engine_actor_contract_fails_explicitly(monkeypatch):
    import builtins
    from unittest.mock import create_autospec
    original = builtins.__import__
    def importing(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "okengine.actor_identity":
            raise ImportError("required installed helper unavailable")
        return original(name, globals, locals, fromlist, level)
    monkeypatch.setattr(builtins, "__import__", create_autospec(original, side_effect=importing))
    with pytest.raises(RuntimeError, match="installed OKEngine actor identity guard"):
        lane("actor_mentions")


def test_source_adapter_ignores_nonreferences_and_wrong_namespaces(tmp_path, shared_writer):
    writer = shared_writer
    assert writer._actor_source_error(tmp_path, {"title": "Critical Threat", "sources": [None, 2, "", "/sources/report", "entities/report"]}) is None


def test_activity_stamp_never_creates_a_missing_actor(tmp_path, shared_writer):
    writer = shared_writer
    assert writer.write_page(tmp_path / "wiki", "entities/missing", {"recent_news": 9},
                             "Stale body", require_actor=True) == "ineligible"
    assert not (tmp_path / "wiki/entities/missing.md").exists()


def test_live_actor_import_cannot_restore_an_existing_tombstone(tmp_path, shared_writer):
    writer = shared_writer
    wiki = tmp_path / "wiki"
    target = wiki / "entities/silence.md"
    write(target, {"type": "actor", "title": "Silence", "status": "tombstoned"}, "Silence is a group.")
    before = target.read_bytes()
    with pytest.raises(ValueError, match="cannot be restored"):
        writer.write_page(wiki, "entities/silence", {"status": "active"}, "Silence is a group.")
    assert target.read_bytes() == before


def test_report_activity_ignores_unknown_retired_source_and_index_records(tmp_path):
    wiki = tmp_path / "wiki"
    target = wiki / "entities/silence.md"
    write(target, {"type": "actor", "title": "Silence", "recent_reports": 9}, "Silence is a group.")
    write(wiki / "sources/INDEX.md", {"type": "dashboard"}, "Index")
    write(wiki / "sources/retired.md", {"type": "source", "status": "tombstoned", "mentions_actors": ["silence"]}, "Silence targeted banks.")
    write(wiki / "sources/unknown.md", {"type": "source", "mentions_actors": ["not-in-roster"]}, "Other actor")
    assert lane("actor_activity").main(["--vault", str(tmp_path)]) == 0
    assert fm(target)["recent_reports"] == 0



def test_identity_audit_contrary_source_tombstone_preserves_software_migration():
    audit = lane("actor_identity_audit")
    assert audit.classify({"type": "actor", "title": "Critical Threat"},
                          "A critical Windows driver vulnerability allows escalation.", Path("actor.md"))[0] == "tombstone"
    assert audit.classify({"type": "actor", "title": "Mirage2FA"},
                          "Mirage2FA is a phishing-as-a-service toolkit.", Path("tool.md"))[0] == "malware"



def test_report_activity_retyped_during_source_attribution_is_not_stamped(tmp_path, monkeypatch):
    from unittest.mock import create_autospec
    activity = lane("actor_activity")
    wiki = tmp_path / "wiki"
    target = wiki / "entities/silence.md"
    write(target, {"type": "actor", "title": "Silence", "recent_reports": 9}, "Silence is a group.")
    write(wiki / "sources/report.md", {"type": "source", "mentions_actors": ["silence"]}, "Silence targeted banks.")
    original = activity._split
    reads = 0
    def reading(path):
        nonlocal reads
        if path == target:
            reads += 1
            if reads == 2:
                write(target, {"type": "malware", "title": "Silence", "recent_reports": 9}, "Preserved malware body.")
        return original(path)
    monkeypatch.setattr(activity, "_split", create_autospec(original, side_effect=reading))
    assert activity.main(["--vault", str(tmp_path)]) == 0
    assert fm(target)["type"] == "malware" and fm(target)["recent_reports"] == 9
    assert "Preserved malware body." in target.read_text()


def test_import_rosters_exclude_contrary_retired_and_retyped_entities(tmp_path):
    importer = lane("misp_galaxy_import")
    wiki = tmp_path / "wiki"
    for slug, fields, body in [
        ("critical-threat", {"type": "actor", "title": "Critical Threat"}, "A critical Windows vulnerability allows escalation."),
        ("retired", {"type": "actor", "title": "Retired", "status": "tombstoned"}, "Retired is a group."),
        ("tool", {"type": "malware", "title": "Tool"}, "Tool is software."),
        ("unfamiliar-delta", {"type": "actor", "title": "Unfamiliar Delta", "aliases": ["Silence"]}, "Named adversary reported by researchers."),
    ]:
        write(wiki / ("entities/" + slug + ".md"), fields, body)
    index = importer.index_actors(wiki)
    primary = importer.primary_actor_index(wiki)
    assert set(index) == {"unfamiliar delta", "silence"}
    assert set(primary) == {"unfamiliar delta"}


def test_report_activity_with_no_eligible_roster_has_no_actor_outputs(tmp_path):
    wiki = tmp_path / "wiki"
    target = wiki / "entities/retired.md"
    write(target, {"type": "actor", "title": "Retired", "status": "tombstoned"}, "Historical group.")
    before = target.read_bytes()
    assert lane("actor_activity").main(["--vault", str(tmp_path)]) == 0
    assert target.read_bytes() == before
    assert not (wiki / "dashboards/top-actors-by-activity.md").exists()


def test_shared_writer_missing_actor_helper_refuses_actor_but_keeps_nonactor_write(tmp_path, monkeypatch, shared_writer):
    import builtins
    from unittest.mock import create_autospec
    writer = shared_writer
    wiki = tmp_path / "wiki"
    actor = wiki / "entities/silence.md"
    other = wiki / "entities/tool.md"
    write(actor, {"type": "actor", "title": "Silence"}, "Silence targeted banks.")
    write(other, {"type": "malware", "title": "Tool"}, "Existing software.")
    before = actor.read_bytes()
    original = builtins.__import__
    def importing(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "okengine.actor_identity":
            raise ImportError("installed helper unsupported")
        return original(name, globals, locals, fromlist, level)
    monkeypatch.setattr(builtins, "__import__", create_autospec(original, side_effect=importing))
    with pytest.raises(RuntimeError, match="actor validation requires the installed OKEngine"):
        writer.write_page(wiki, "entities/silence", {}, "Silence targeted mailboxes.")
    assert actor.read_bytes() == before
    with pytest.raises(RuntimeError, match="actor source validation requires the installed OKEngine"):
        writer._actor_source_error(wiki, {"title": "Critical Threat"})
    writer.write_page(wiki, "entities/tool", {}, "Updated software.")
    assert "Updated software." in other.read_text()
