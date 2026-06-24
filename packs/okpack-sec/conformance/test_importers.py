#!/usr/bin/env python3
"""Conformance tests for the no_agent reference-data importers (okpacks-library#16).

Runs standalone (conformance-all.sh: `python3 conformance/test_importers.py`,
nonzero exit on failure) and is also pytest-discoverable. No network: every test
drives the importers' pure transforms with inline fixtures.
"""
import importlib.util
import json
import os
import sys
import tempfile
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent.parent / "crons" / "scripts"

# The importers import a sibling pack module (mdm_resolve) and the engine resolver
# (entity_resolve); at deploy both ship beside the importers in /opt/data/scripts/. Mirror
# that on sys.path so the importers' over-merge-guarded resolution (okengine#39) loads here.
sys.path.insert(0, str(SCRIPTS))
_ENGINE_SCRIPTS = Path(os.environ.get("ENGINE_DIR") or (SCRIPTS.parents[4] / "okengine")) / "scripts" / "cron"
if _ENGINE_SCRIPTS.is_dir():
    sys.path.insert(0, str(_ENGINE_SCRIPTS))
try:
    import entity_resolve  # noqa: F401 — engine over-merge-guarded resolver (okengine#39)
    _HAVE_ENGINE = True
except ImportError:
    _HAVE_ENGINE = False


def _skip_without_engine() -> bool:
    """Observation-resolution tests need the engine's entity_resolve (set ENGINE_DIR or
    check out okengine beside okpacks-library). Soft-skip when it isn't available so the
    rest of the standalone conformance suite still runs."""
    if not _HAVE_ENGINE:
        print("    (skipped: entity_resolve unavailable — set ENGINE_DIR)")
        return True
    return False


def _load(name):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


# ── ATT&CK ───────────────────────────────────────────────────────────────────
_BUNDLE = {"objects": [
    {"type": "attack-pattern", "name": "Drive-by Compromise",
     "description": "Adversaries may gain access.(Citation: Foo) More text.",
     "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}],
     "external_references": [{"source_name": "mitre-attack", "external_id": "T1189",
                              "url": "https://attack.mitre.org/techniques/T1189"}]},
    {"type": "attack-pattern", "name": "PowerShell", "x_mitre_is_subtechnique": True,
     "description": "Abuse PowerShell.",
     "external_references": [{"source_name": "mitre-attack", "external_id": "T1059.001"}]},
    {"type": "attack-pattern", "name": "Old Technique", "x_mitre_deprecated": True,
     "external_references": [{"source_name": "mitre-attack", "external_id": "T9999"}]},
    {"type": "intrusion-set", "name": "not a technique"},
]}


def test_attack_parse_and_clean():
    m = _load("okpack_sec_attack_import")
    recs = {r["mitre_id"]: r for r in m.parse_attack_patterns(_BUNDLE)}
    assert set(recs) == {"T1189", "T1059.001", "T9999"}          # intrusion-set skipped
    assert recs["T1189"]["tactics"] == ["initial-access"]
    assert "(Citation:" not in recs["T1189"]["description"]       # citation stripped
    assert recs["T9999"]["deprecated"] is True


def test_attack_import_idempotent_and_skips_deprecated():
    m = _load("okpack_sec_attack_import")
    with tempfile.TemporaryDirectory() as t:
        c1 = m.import_bundle(_BUNDLE, t, "2026-06-19")
        assert c1["created"] == 2 and c1["skipped_deprecated"] == 1   # T9999 not seeded
        p = m.page_path(t, "Drive-by Compromise", "T1189")
        assert p.is_file() and "type: attack-pattern" in p.read_text()
        c2 = m.import_bundle(_BUNDLE, t, "2026-06-19")
        assert c2["unchanged"] == 2 and c2["created"] == 0            # idempotent


def test_attack_import_preserves_agent_sections():
    m = _load("okpack_sec_attack_import")
    with tempfile.TemporaryDirectory() as t:
        m.import_bundle(_BUNDLE, t, "2026-06-19")
        p = m.page_path(t, "Drive-by Compromise", "T1189")
        p.write_text(p.read_text() + "\n## Used by\n- [[malware/s/foo]]\n")
        m.import_bundle({"objects": [_BUNDLE["objects"][0]]}, t, "2026-06-25")
        assert "## Used by" in p.read_text()                          # not clobbered


_GROUP_BUNDLE = {"objects": [
    {"type": "intrusion-set", "name": "Indrik Spider",
     "aliases": ["Indrik Spider", "Evil Corp", "UNC2165"],
     "description": "A Russia-based group.(Citation: X)",
     "external_references": [{"source_name": "mitre-attack", "external_id": "G0119"}]},
    {"type": "intrusion-set", "name": "Dead Group", "x_mitre_deprecated": True,
     "external_references": [{"source_name": "mitre-attack", "external_id": "G9999"}]},
]}


def test_attack_groups_seed_threat_actors_with_aliases():
    m = _load("okpack_sec_attack_import")
    recs = m.parse_groups(_GROUP_BUNDLE)
    g = [r for r in recs if r["mitre_id"] == "G0119"][0]
    assert g["aliases"] == ["Evil Corp", "UNC2165"]              # primary name dropped
    with tempfile.TemporaryDirectory() as t:
        c = m.import_groups(_GROUP_BUNDLE, t, "2026-06-19")
        assert c["created"] == 1 and c["skipped_deprecated"] == 1
        p = m.group_page_path(t, "Indrik Spider")
        txt = p.read_text()
        assert "type: intrusion-set" in txt and "aliases: [Evil Corp, UNC2165]" in txt


def test_attack_group_body_internalizes_links_and_fixes_typos():
    m = _load("okpack_sec_attack_import")
    desc = ("[APT29](https://attack.mitre.org/groups/G0016) is threat group that uses "
            "[Cobalt Strike](https://attack.mitre.org/software/S0154) and a "
            "[tactic](https://attack.mitre.org/tactics/TA0001).(Citation: X)")
    out = m.polish_group_body(desc, "APT29")
    assert out.startswith("APT29 is a threat group")          # self-link de-linked + typo fixed
    assert "[[Cobalt Strike]]" in out                          # software link -> internal wikilink
    assert "and a tactic." in out and "[[tactic]]" not in out  # non-entity category -> plain text
    assert "](https://attack.mitre.org" not in out and "(Citation:" not in out
    assert m.fix_mitre_typos("X is threat actor") == "X is a threat actor"   # 'actor' variant too


def test_attack_group_observation_body_is_internalized():
    if _skip_without_engine():
        return
    m = _load("okpack_sec_attack_import")
    bundle = {"objects": [
        {"type": "intrusion-set", "name": "APT29", "id": "intrusion-set--1",
         "description": "[APT29](https://attack.mitre.org/groups/G0016) is threat group linked to "
                        "[WellMess](https://attack.mitre.org/software/S0514).",
         "external_references": [{"source_name": "mitre-attack", "external_id": "G0016"}]},
    ]}
    with tempfile.TemporaryDirectory() as t:
        m.import_group_observations(bundle, t, "2026-06-20")
        txt = (Path(t) / "wiki" / "observations" / "mitre-attack" / "a" / "apt29.md").read_text()
        assert "APT29 is a threat group linked to [[WellMess]]." in txt
        assert "](https://attack.mitre.org" not in txt         # body de-linked (frontmatter ref ok)


_MITI_BUNDLE = {"objects": [
    {"type": "course-of-action", "name": "Network Intrusion Prevention",
     "description": "Use IDS signatures.(Citation: Y)",
     "external_references": [{"source_name": "mitre-attack", "external_id": "M1031"}]},
    {"type": "course-of-action", "name": "legacy no-id mitigation"},   # no Mxxxx -> skipped
]}


def test_attack_mitigations_seed_course_of_action():
    m = _load("okpack_sec_attack_import")
    recs = m.parse_mitigations(_MITI_BUNDLE)
    assert [r["mitre_id"] for r in recs] == ["M1031"]              # the no-id one skipped
    with tempfile.TemporaryDirectory() as t:
        c = m.import_mitigations(_MITI_BUNDLE, t, "2026-06-19")
        assert c["created"] == 1
        p = m.mitigation_page_path(t, "Network Intrusion Prevention", "M1031")
        txt = p.read_text()
        assert "type: course-of-action" in txt and "mitre_id: M1031" in txt
        assert "(Citation:" not in txt


def test_attack_mitigates_edges_render_on_mitigation():
    """okengine#44: a course-of-action --mitigates--> technique is imported as an internal
    [[wikilink]] on the mitigation page (no longer dropped); idempotent on re-import."""
    m = _load("okpack_sec_attack_import")
    bundle = {"objects": [
        {"type": "course-of-action", "name": "Network Intrusion Prevention", "id": "course-of-action--m1",
         "description": "Use IDS signatures.", "external_references": [{"source_name": "mitre-attack", "external_id": "M1031"}]},
        {"type": "attack-pattern", "name": "Exploit Public-Facing Application", "id": "attack-pattern--t1",
         "external_references": [{"source_name": "mitre-attack", "external_id": "T1190"}]},
        {"type": "relationship", "relationship_type": "mitigates",
         "source_ref": "course-of-action--m1", "target_ref": "attack-pattern--t1"},
    ]}
    with tempfile.TemporaryDirectory() as t:
        c = m.import_mitigations(bundle, t, "2026-06-20")
        assert c["created"] == 1 and c["rels"] == 1
        p = m.mitigation_page_path(t, "Network Intrusion Prevention", "M1031")
        txt = p.read_text()
        assert "## Associated (MITRE ATT&CK)" in txt and "Mitigates" in txt
        assert "[[entities/exploit-public-facing-application-t1190|Exploit Public-Facing Application]]" in txt
        m.import_mitigations(bundle, t, "2026-06-20")            # re-import is idempotent
        assert p.read_text().count("## Associated (MITRE ATT&CK)") == 1


def test_attack_parse_relationships_predicates():
    """okengine#44: parse_relationships keys edges by SOURCE slug and maps multiple predicates."""
    m = _load("okpack_sec_attack_import")
    bundle = {"objects": [
        {"type": "intrusion-set", "name": "APT29", "id": "is--1",
         "external_references": [{"source_name": "mitre-attack", "external_id": "G0016"}]},
        {"type": "attack-pattern", "name": "Phishing", "id": "ap--1",
         "external_references": [{"source_name": "mitre-attack", "external_id": "T1566"}]},
        {"type": "course-of-action", "name": "User Training", "id": "coa--1",
         "external_references": [{"source_name": "mitre-attack", "external_id": "M1017"}]},
        {"type": "relationship", "relationship_type": "uses", "source_ref": "is--1", "target_ref": "ap--1"},
        {"type": "relationship", "relationship_type": "mitigates", "source_ref": "coa--1", "target_ref": "ap--1"},
    ]}
    rels = m.parse_relationships(bundle, m._stix_index(bundle))
    assert rels["apt29"][0]["p"] == "uses-technique"             # actor uses (unchanged)
    assert rels["user-training-m1017"][0] == {"p": "mitigates", "t": "phishing-t1566", "n": "Phishing"}


def test_attack_subtechnique_of_renders_on_technique():
    """okengine#44: a sub-technique --subtechnique-of--> parent renders an internal link."""
    m = _load("okpack_sec_attack_import")
    bundle = {"objects": [
        {"type": "attack-pattern", "name": "PowerShell", "id": "ap--sub", "x_mitre_is_subtechnique": True,
         "external_references": [{"source_name": "mitre-attack", "external_id": "T1059.001"}]},
        {"type": "attack-pattern", "name": "Command and Scripting Interpreter", "id": "ap--parent",
         "external_references": [{"source_name": "mitre-attack", "external_id": "T1059"}]},
        {"type": "relationship", "relationship_type": "subtechnique-of",
         "source_ref": "ap--sub", "target_ref": "ap--parent"},
    ]}
    with tempfile.TemporaryDirectory() as t:
        c = m.import_bundle(bundle, t, "2026-06-20")
        assert c["rels"] == 1
        txt = m.page_path(t, "PowerShell", "T1059.001").read_text()
        assert "## Associated (MITRE ATT&CK)" in txt and "Sub-technique of" in txt
        assert "[[entities/command-and-scripting-interpreter-t1059|Command and Scripting Interpreter]]" in txt


def test_attack_software_uses_technique_renders():
    """okengine#44: malware/tool --uses--> technique renders an internal link on the software page."""
    m = _load("okpack_sec_attack_import")
    bundle = {"objects": [
        {"type": "malware", "name": "SUNBURST", "id": "mal--1",
         "external_references": [{"source_name": "mitre-attack", "external_id": "S0559"}]},
        {"type": "attack-pattern", "name": "Phishing", "id": "ap--1",
         "external_references": [{"source_name": "mitre-attack", "external_id": "T1566"}]},
        {"type": "relationship", "relationship_type": "uses", "source_ref": "mal--1", "target_ref": "ap--1"},
    ]}
    with tempfile.TemporaryDirectory() as t:
        c = m.import_software(bundle, t, "2026-06-20")
        assert c["rels"] == 1
        txt = m.group_page_path(t, "SUNBURST").read_text()
        assert "## Associated (MITRE ATT&CK)" in txt and "Uses techniques" in txt
        assert "[[entities/phishing-t1566|Phishing]]" in txt


# ── CISA KEV ─────────────────────────────────────────────────────────────────
_KEV = {"vulnerabilities": [
    {"cveID": "CVE-2026-20253", "vulnerabilityName": "Splunk RCE", "vendorProject": "Splunk",
     "product": "Enterprise", "dateAdded": "2026-06-18", "knownRansomwareCampaignUse": "Known",
     "shortDescription": "RCE."},
    {"cveID": "CVE-2025-36539", "vulnerabilityName": "Existing CVE", "vendorProject": "Rockwell",
     "product": "FactoryTalk", "dateAdded": "2026-05-01", "knownRansomwareCampaignUse": "Unknown",
     "shortDescription": "DoS."},
]}


def test_kev_flags_existing_and_stubs_new():
    m = _load("okpack_sec_kev_import")
    with tempfile.TemporaryDirectory() as t:
        # an existing vuln page the agent built — KEV must flag it, keep the body
        p = Path(t) / "wiki" / "entities" / "c" / "cve-2025-36539.md"
        p.parent.mkdir(parents=True)
        p.write_text("---\ntype: vulnerability\ncve_id: CVE-2025-36539\nseverity: medium\n---\nAgent analysis.\n")
        c = m.import_kev(_KEV, t, "2026-06-19")
        assert c["created"] == 1 and c["flagged"] == 1 and c["ransomware"] == 1
        flagged = p.read_text()
        assert "kev: true" in flagged and "actively-exploited" in flagged
        assert "Agent analysis." in flagged and "severity: medium" in flagged   # preserved
        stub = (Path(t) / "wiki" / "entities" / "c" / "cve-2026-20253.md").read_text()
        assert "kev_ransomware: true" in stub


# ── NVD ──────────────────────────────────────────────────────────────────────
_NVD = {"vulnerabilities": [
    {"cve": {"id": "CVE-2024-3094",
             "descriptions": [{"lang": "en", "value": "Malicious code in xz."}],
             "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 10.0, "baseSeverity": "CRITICAL", "version": "3.1"}}]},
             "weaknesses": [{"description": [{"value": "CWE-506"}]}]}},
    {"cve": {"id": "CVE-2025-0001",
             "descriptions": [{"lang": "en", "value": "Low thing."}],
             "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 3.1, "baseSeverity": "LOW", "version": "3.1"}}]}}},
]}


def test_nvd_enriches_existing_stubs_high_skips_low():
    m = _load("okpack_sec_nvd_import")
    recs = [m.nvd_record(v["cve"]) for v in _NVD["vulnerabilities"]]
    assert recs[0]["severity"] == "critical" and recs[0]["cwes"] == ["CWE-506"]
    with tempfile.TemporaryDirectory() as t:
        c = m.import_cves(recs, t, "2026-06-19")
        assert c["created"] == 1                                    # critical stubbed
        assert c["skipped_lowsev"] == 1                             # low-sev, no page -> skipped
        assert (Path(t) / "wiki" / "entities" / "c" / "cve-2024-3094.md").is_file()
    # an existing low-sev page is still enriched (body preserved)
    with tempfile.TemporaryDirectory() as t:
        p = Path(t) / "wiki" / "entities" / "c" / "cve-2025-0001.md"
        p.parent.mkdir(parents=True)
        p.write_text("---\ntype: vulnerability\ncve_id: CVE-2025-0001\n---\nAgent body.\n")
        m.import_cves(recs, t, "2026-06-19")
        assert "severity: low" in p.read_text() and "Agent body." in p.read_text()


# ── ThaiCERT Threat Group Cards ──────────────────────────────────────────────
_TGC = {"values": [
    {"value": "Lazarus Group", "meta": {"country": "KP", "motivation": ["Financial crime"],
     "synonyms": ["Hidden Cobra", "Labyrinth Chollima"], "cfr-target-category": ["Defense"],
     "refs": ["https://apt.etda.or.th/cgi-bin/showcard.cgi?u=abc"]}},
    {"value": "Fancy Bear", "meta": {"country": "RU", "synonyms": ["APT 28", "Sofacy"],
     "refs": ["https://apt.etda.or.th/x"]}},
    {"value": "Brand New Group", "meta": {"country": "IR", "synonyms": ["NewGuy"],
     "refs": ["https://apt.etda.or.th/y"]}},
]}


def _is_page(t, sub, name, fm):
    d = Path(t) / "wiki" / "entities" / sub
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{name}.md").write_text("---\n" + fm + "---\nAgent body.\n## Used by\n- [[x]]\n")


def test_tgc_dedup_enrich_and_create():
    m = _load("okpack_sec_tgc_import")
    with tempfile.TemporaryDirectory() as t:
        _is_page(t, "l", "lazarus-group", "type: intrusion-set\nname: Lazarus Group\naliases: [Hidden Cobra, Zinc]\ntlp: clear\n")
        _is_page(t, "a", "apt28", "type: intrusion-set\nname: APT28\nsuspected_origin: Russia\ntlp: clear\n")
        c = m.import_tgc(_TGC, Path(t), "2026-06-19")
        assert c == {"enriched": 2, "created": 1, "unchanged": 0, "total": 3}
        laz = (Path(t) / "wiki" / "entities" / "l" / "lazarus-group.md").read_text()
        assert "suspected_origin: North Korea" in laz       # ISO filled
        assert "Labyrinth Chollima" in laz and "Zinc" in laz  # aliases UNIONed (TGC + existing)
        assert "## Used by" in laz                           # agent body preserved
        apt = (Path(t) / "wiki" / "entities" / "a" / "apt28.md").read_text()
        assert "Sofacy" in apt                               # matched via normalized 'APT 28' alias
        assert "suspected_origin: Russia" in apt             # curated value NOT clobbered
        assert (Path(t) / "wiki" / "entities" / "b" / "brand-new-group.md").is_file()
        assert m.import_tgc(_TGC, Path(t), "2026-06-19")["unchanged"] == 3   # idempotent


# ── ThaiCERT Threat Group Cards — Tools ──────────────────────────────────────
_TGC_TOOLS = {"values": [
    {"value": "Cobalt Strike", "meta": {"category": "Tools", "type": ["Backdoor"],
     "synonyms": ["CobaltStrike", "Beacon"],
     "refs": ["https://apt.etda.or.th/cgi-bin/listtools.cgi?c=abc"]}},
    {"value": "Emotet", "meta": {"category": "Malware", "type": ["Loader", "Banking trojan"],
     "synonyms": ["Geodo"], "refs": ["https://apt.etda.or.th/x"]}},
    {"value": "EternalBlue", "meta": {"category": "Exploits", "type": ["Exploit"],
     "refs": ["https://apt.etda.or.th/y"]}},
    {"value": "Generic Thing", "meta": {"category": "Other", "refs": ["https://apt.etda.or.th/z"]}},
]}


def test_tgc_tools_skips_other_and_maps_category():
    m = _load("okpack_sec_tgc_tools_import")
    recs = {r["name"]: r for r in m.tgc_records(_TGC_TOOLS)}
    assert set(recs) == {"Cobalt Strike", "Emotet", "EternalBlue"}   # Other skipped
    assert recs["Cobalt Strike"]["type"] == "tool"
    assert recs["Emotet"]["type"] == "malware"
    assert recs["EternalBlue"]["type"] == "tool"                     # Exploits -> tool
    assert recs["Emotet"]["malware_type"] == ["Loader", "Banking trojan"]


def test_tgc_tools_dedup_enrich_and_create():
    m = _load("okpack_sec_tgc_tools_import")
    with tempfile.TemporaryDirectory() as t:
        # existing malware page (agent-built) matched via the 'Geodo' alias -> enrich, keep type
        _is_page(t, "e", "emotet", "type: malware\nname: Emotet\naliases: [Geodo, Heodo]\ncategory: trojan\ntlp: clear\n")
        c = m.import_tgc_tools(_TGC_TOOLS, Path(t), "2026-06-19")
        assert c == {"enriched": 1, "created": 2, "unchanged": 0, "total": 3}
        emo = (Path(t) / "wiki" / "entities" / "e" / "emotet.md").read_text()
        assert "Heodo" in emo and "malware_type: [Loader, Banking trojan]" in emo
        assert "category: trojan" in emo and "## Used by" in emo    # curated field + body preserved
        cs = (Path(t) / "wiki" / "entities" / "c" / "cobalt-strike.md").read_text()
        assert "type: tool" in cs and "Beacon" in cs
        eb = (Path(t) / "wiki" / "entities" / "e" / "eternalblue.md").read_text()
        assert "type: tool" in eb                                   # Exploits page typed as tool
        assert m.import_tgc_tools(_TGC_TOOLS, Path(t), "2026-06-19")["unchanged"] == 3  # idempotent


# ── TGC body summaries (readable profile, not a placeholder) ─────────────────
def test_tgc_body_summary_and_upgrade():
    m = _load("okpack_sec_tgc_import")
    rec = {"name": "APT 6", "aliases": ["1.php Group"], "origin": "China",
           "motivation": "Information theft and espionage", "sectors": ["Government"],
           "card": "https://apt.etda.or.th/x"}
    new = m.render_new(rec, "2026-06-20")
    assert "China-based adversary group" in new and "Full profile:" in new
    assert "tracked adversary group catalogued by ThaiCERT" not in new   # no placeholder
    # an existing placeholder body is upgraded in place
    stub = ("---\ntype: intrusion-set\nname: APT 6\ntlp: clear\n---\n"
            "APT 6 is a tracked adversary group catalogued by ThaiCERT's Threat Group Cards.\n\n> note\n")
    up = m.merge_existing(stub, rec, "2026-06-20")
    assert up and "China-based adversary group" in up and "Full profile:" in up
    # but an agent-enriched body (## section) is never clobbered
    rich = ("---\ntype: intrusion-set\nname: APT 6\nsuspected_origin: China\ntlp: clear\n---\n"
            "APT 6 is a tracked adversary group catalogued by ThaiCERT's Threat Group Cards.\n\n## Analysis\nreal.\n")
    up2 = m.merge_existing(rich, rec, "2026-06-20")
    assert up2 is None or "## Analysis" in up2


def test_tgc_tools_body_summary():
    m = _load("okpack_sec_tgc_tools_import")
    rec = {"name": "Cobalt Strike", "type": "tool", "aliases": ["Beacon"],
           "malware_type": ["Backdoor"], "card": "https://apt.etda.or.th/x"}
    new = m.render_new(rec, "2026-06-20")
    assert "is a tool (Backdoor)" in new and "Full profile:" in new
    assert "catalogued by ThaiCERT's Threat Group Cards.\n\n>" not in new   # not the bare stub


# ── observation mode (multi-source MDM; okengine#38) ─────────────────────────
def _copy_schema(t):
    import shutil
    shutil.copy(SCRIPTS.parent.parent / "schema.yaml", Path(t) / "schema.yaml")


def test_kev_observation_mode():
    m = _load("okpack_sec_kev_import")
    with tempfile.TemporaryDirectory() as t:
        _copy_schema(t)
        c = m.import_observations(_KEV, t, "2026-06-20")
        assert c == {"written": 2, "total": 2, "ransomware": 1}
        txt = (Path(t) / "wiki" / "observations" / "cisa-kev" / "c" / "cve-2026-20253.md").read_text()
        assert "source: cisa-kev" in txt and "canonical: cve-2026-20253" in txt
        assert "reliability: A" in txt and "credibility: '1'" in txt       # from source_registry
        assert "kev: true" in txt and "kev_ransomware: true" in txt
        assert not (Path(t) / "wiki" / "entities").exists()                # not merged in place


def test_nvd_observation_mode_keeps_severity_bound():
    m = _load("okpack_sec_nvd_import")
    recs = [m.nvd_record(v["cve"]) for v in _NVD["vulnerabilities"]]
    with tempfile.TemporaryDirectory() as t:
        _copy_schema(t)
        c = m.import_observations(recs, t, "2026-06-20")
        assert c == {"written": 1, "skipped_lowsev": 1, "total": 2}        # low-sev not observed
        txt = (Path(t) / "wiki" / "observations" / "nvd" / "c" / "cve-2024-3094.md").read_text()
        assert "source: nvd" in txt and "canonical: cve-2024-3094" in txt
        assert "reliability: A" in txt and "credibility: '2'" in txt
        assert "severity: critical" in txt and "cvss_base: 10.0" in txt


def test_nvd_read_bulk_filters_to_cve_list():
    """okengine#40: FKIE-CAD bulk feed (cve_items[] of API-2.0 cve objects) parses via the same
    nvd_record path and honors a CVE-id filter, so we can backfill nvd observations for the KEV
    set offline (no NVD rate limit)."""
    m = _load("okpack_sec_nvd_import")
    feed = {"feed_name": "CVE-2024", "cve_items": [
        {"id": "CVE-2024-3094", "descriptions": [{"lang": "en", "value": "xz backdoor."}],
         "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 10.0, "baseSeverity": "CRITICAL", "version": "3.1"}}]},
         "weaknesses": [{"description": [{"value": "CWE-506"}]}]},
        {"id": "CVE-2024-9999", "descriptions": [{"lang": "en", "value": "Not in KEV."}],
         "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 5.0, "baseSeverity": "MEDIUM", "version": "3.1"}}]}},
    ]}
    with tempfile.TemporaryDirectory() as t:
        fp = Path(t) / "CVE-2024.json"
        fp.write_text(json.dumps(feed), encoding="utf-8")
        recs = m.read_bulk([str(fp)], cve_filter={"cve-2024-3094"})        # KEV set = one CVE
        assert [r["cve_id"] for r in recs] == ["CVE-2024-3094"]            # the other is filtered out
        assert recs[0]["cvss_base"] == 10.0 and recs[0]["cwes"] == ["CWE-506"]
        assert len(m.read_bulk([str(fp)])) == 2                            # no filter -> all


def test_tgc_tools_observation_mode_resolves_and_stamps():
    if _skip_without_engine():
        return
    m = _load("okpack_sec_tgc_tools_import")
    with tempfile.TemporaryDirectory() as t:
        v = Path(t)
        _copy_schema(t)
        # existing malware/tool canonical; the TGC tool merges on a primary-name match.
        _is_page(t, "c", "cobalt-strike", "type: tool\nname: Cobalt Strike\naliases: [Beacon]\n")
        data = {"values": [{"value": "Cobalt Strike", "meta": {"category": "Tools",
                "synonyms": ["Beacon"], "refs": ["https://apt.etda.or.th/x"]}}]}
        c = m.import_observations(data, v, "2026-06-20")
        assert c["written"] == 1 and c["flagged"] == 0
        txt = (v / "wiki" / "observations" / "thaicert" / "c" / "cobalt-strike.md").read_text()
        assert "source: thaicert" in txt and "canonical: cobalt-strike" in txt   # primary-name merge
        assert "reliability: B" in txt and "credibility: '3'" in txt and "type: tool" in txt


def test_tgc_observation_mode_resolves_and_guards_over_merge():
    if _skip_without_engine():
        return
    m = _load("okpack_sec_tgc_import")
    with tempfile.TemporaryDirectory() as t:
        v = Path(t)
        # existing canonical lists UNC3524 as an alias of APT29
        _is_page(t, "a", "apt29", "type: intrusion-set\nname: APT29\naliases: [UNC3524]\ntlp: clear\n")
        data = {"values": [
            {"value": "APT29", "meta": {"country": "RU", "synonyms": ["Cozy Bear"],
             "refs": ["https://apt.etda.or.th/x"]}},
            {"value": "UNC3524", "meta": {"country": "RU", "refs": ["https://apt.etda.or.th/y"]}},
        ]}
        c = m.import_observations(data, v, "2026-06-20")
        assert c["written"] == 2
        apt = v / "wiki" / "observations" / "thaicert" / "a" / "apt29.md"
        unc = v / "wiki" / "observations" / "thaicert" / "u" / "unc3524.md"
        assert apt.is_file() and unc.is_file()
        # APT29 merges on a PRIMARY-name match
        assert "canonical: apt29" in apt.read_text()
        assert "source: thaicert" in apt.read_text() and "reliability:" in apt.read_text()
        # UNC3524's only tie to apt29 is a single ambiguous alias (primary names differ), so the
        # over-merge guard (okengine#39) declines: it mints its own canonical and is flagged.
        assert "canonical: unc3524" in unc.read_text()
        assert c["flagged"] == 1
        rq = (v / "wiki" / "_review-queue.md").read_text()
        assert "over-merge guard" in rq and "unc3524" in rq


def test_tgc_observation_guards_iridium_sandworm_over_merge():
    """okengine#39 regression: ThaiCERT's Iranian 'Iridium' must NOT fold into Sandworm, which
    carries 'IRIDIUM' as an alias (Microsoft's name for Sandworm). Single shared alias, distinct
    primary names -> guard declines the merge, mints a distinct canonical, flags it."""
    if _skip_without_engine():
        return
    m = _load("okpack_sec_tgc_import")
    with tempfile.TemporaryDirectory() as t:
        v = Path(t)
        _is_page(t, "s", "sandworm-team",
                 "type: intrusion-set\nname: Sandworm Team\naliases: [IRIDIUM, Voodoo Bear]\ntlp: clear\n")
        data = {"values": [
            {"value": "Iridium", "meta": {"country": "IR", "refs": ["https://apt.etda.or.th/z"]}},
        ]}
        c = m.import_observations(data, v, "2026-06-20")
        irid = (v / "wiki" / "observations" / "thaicert" / "i" / "iridium.md").read_text()
        assert "canonical: iridium" in irid                 # NOT sandworm-team
        assert "canonical: sandworm-team" not in irid
        assert c["flagged"] == 1
        rq = (v / "wiki" / "_review-queue.md").read_text()
        assert "sandworm-team" in rq and "Iridium" in rq


def test_seed_microsoft_coref_merges_vouched_single_alias():
    """okengine#39 'seed later' (okpacks-library#8 part 3): a lone shared alias the Microsoft
    mapping vouches for MERGES instead of declining. UNC3524 ties to apt29 only via a single
    alias, but a Microsoft observation (canonical apt29) lists UNC3524 -> trusted co-reference
    -> merge, not flagged. (Contrast the guard test above where there is no Microsoft voucher.)"""
    if _skip_without_engine():
        return
    m = _load("okpack_sec_tgc_import")
    with tempfile.TemporaryDirectory() as t:
        v = Path(t)
        _is_page(t, "a", "apt29",
                 "type: intrusion-set\nname: APT29\naliases: [Cozy Bear, UNC3524]\ntlp: clear\n")
        mo = v / "wiki" / "observations" / "microsoft" / "m"
        mo.mkdir(parents=True, exist_ok=True)
        (mo / "midnight-blizzard.md").write_text(
            "---\ntype: intrusion-set\nsource: microsoft\ncanonical: apt29\n"
            "name: Midnight Blizzard\naliases: [APT29, Cozy Bear, UNC3524]\n---\nbody\n",
            encoding="utf-8")
        data = {"values": [
            {"value": "UNC3524", "meta": {"country": "RU", "refs": ["https://apt.etda.or.th/y"]}},
        ]}
        c = m.import_observations(data, v, "2026-06-20")
        unc = (v / "wiki" / "observations" / "thaicert" / "u" / "unc3524.md").read_text()
        assert "canonical: apt29" in unc            # Microsoft vouched the alias -> merged
        assert c["flagged"] == 0                     # trusted merge is not flagged


def test_attack_group_observation_mode():
    if _skip_without_engine():
        return
    m = _load("okpack_sec_attack_import")
    with tempfile.TemporaryDirectory() as t:
        v = Path(t)
        c = m.import_group_observations(_GROUP_BUNDLE, v, "2026-06-20")
        assert c["written"] == 1 and c["skipped_deprecated"] == 1     # Dead Group skipped
        p = v / "wiki" / "observations" / "mitre-attack" / "i" / "indrik-spider.md"
        assert p.is_file()
        txt = p.read_text()
        assert "source: mitre-attack" in txt and "canonical: indrik-spider" in txt
        assert "refs:" in txt and "G0119" in txt                      # mitre id carried as a ref


def test_attack_group_observation_guards_single_alias_over_merge():
    """okengine#39: a MITRE group tied to an existing canonical by only a single shared alias
    (primary names differ) must NOT merge — the guard mints a distinct canonical + flags it."""
    if _skip_without_engine():
        return
    m = _load("okpack_sec_attack_import")
    with tempfile.TemporaryDirectory() as t:
        v = Path(t)
        _is_page(t, "s", "sandworm-team",
                 "type: intrusion-set\nname: Sandworm Team\naliases: [IRIDIUM, Voodoo Bear]\ntlp: clear\n")
        bundle = {"objects": [
            {"type": "intrusion-set", "name": "Iridium", "id": "intrusion-set--1",
             "aliases": ["Iridium", "Lyceum spinoff"],       # only 'Iridium' ties to sandworm-team
             "external_references": [{"source_name": "mitre-attack", "external_id": "G9001"}]},
        ]}
        c = m.import_group_observations(bundle, v, "2026-06-20")
        assert c["written"] == 1 and c["flagged"] == 1
        irid = (v / "wiki" / "observations" / "mitre-attack" / "i" / "iridium.md").read_text()
        assert "canonical: iridium" in irid                  # guard declined; NOT sandworm-team
        assert "canonical: sandworm-team" not in irid
        rq = (v / "wiki" / "_review-queue.md").read_text()
        assert "over-merge guard" in rq and "iridium" in rq


def test_attack_parse_relationships():
    m = _load("okpack_sec_attack_import")
    bundle = {"objects": [
        {"type": "intrusion-set", "name": "APT29",
         "id": "intrusion-set--1", "external_references": [{"source_name": "mitre-attack", "external_id": "G0016"}]},
        {"type": "attack-pattern", "name": "Phishing", "id": "attack-pattern--2",
         "external_references": [{"source_name": "mitre-attack", "external_id": "T1566"}]},
        {"type": "malware", "name": "SUNBURST", "id": "malware--3"},
        {"type": "relationship", "relationship_type": "uses",
         "source_ref": "intrusion-set--1", "target_ref": "attack-pattern--2"},
        {"type": "relationship", "relationship_type": "uses",
         "source_ref": "intrusion-set--1", "target_ref": "malware--3"},
    ]}
    rels = m.parse_relationships(bundle, m._stix_index(bundle))
    edges = rels.get("apt29", [])
    preds = {e["p"]: e for e in edges}
    assert preds["uses-technique"]["t"] == "phishing-t1566"      # technique slug = name-id
    assert preds["uses-malware"]["t"] == "sunburst"              # malware slug = kebab(name)


def test_attack_import_software():
    m = _load("okpack_sec_attack_import")
    bundle = {"objects": [
        {"type": "malware", "name": "SUNBURST", "id": "malware--1", "x_mitre_aliases": ["SUNBURST", "Solorigate"],
         "description": "A backdoor.(Citation: X)",
         "external_references": [{"source_name": "mitre-attack", "external_id": "S0559"}]},
        {"type": "tool", "name": "BloodHound", "id": "tool--2",
         "external_references": [{"source_name": "mitre-attack", "external_id": "S0521"}]},
    ]}
    recs = {r["name"]: r for r in m.parse_software(bundle)}
    assert recs["SUNBURST"]["sw_type"] == "malware" and recs["BloodHound"]["sw_type"] == "tool"
    assert recs["SUNBURST"]["aliases"] == ["Solorigate"]        # primary name dropped
    with tempfile.TemporaryDirectory() as t:
        c = m.import_software(bundle, t, "2026-06-20")
        assert c["created"] == 2
        p = m.group_page_path(t, "SUNBURST")                    # slug = kebab(name) -> resolves group rels
        txt = p.read_text()
        assert "type: malware" in txt and "mitre_id: S0559" in txt and "(Citation:" not in txt
    # existing ThaiCERT-typed page is NOT retyped (type not owned)
    with tempfile.TemporaryDirectory() as t:
        _is_page(t, "s", "sunburst", "type: tool\nname: SUNBURST\ncategory: backdoor\n")
        m.import_software(bundle, t, "2026-06-20")
        assert "type: tool" in (Path(t) / "wiki" / "entities" / "s" / "sunburst.md").read_text()


# ── Microsoft / Rosetta Stone mapping (observation-only; #38 'A3') ────────────
_MSFT = [
    {"Threat actor name": "Midnight Blizzard", "Origin/Threat": "Russia",
     "Other names": "NOBELIUM, APT29, Cozy Bear, Midnight Blizzard"},   # own name + match aliases
    {"Threat actor name": "Cinnamon Tempest", "Origin/Threat": "China, Financially motivated",
     "Other names": "DEV-0401, HighGround"},
    {"Threat actor name": "Storm-0230", "Origin/Threat": "Group in development",
     "Other names": "WIZARD SPIDER, Conti Team 1"},                     # no origin/motivation
    {"Threat actor name": "Carmine Tsunami", "Origin/Threat": "Private sector offensive actor",
     "Other names": ""},                                                # no aliases
    {"Threat actor name": "", "Origin/Threat": "China", "Other names": "x"},   # nameless -> skipped
]


def test_msft_parse_origin_threat_and_aliases():
    m = _load("okpack_sec_msft_import")
    assert m.split_origin_threat("Russia") == ("Russia", [])
    assert m.split_origin_threat("China, Financially motivated") == ("China", ["financially motivated"])
    assert m.split_origin_threat("Russia, Influence operations") == ("Russia", ["influence operations"])
    assert m.split_origin_threat("Türkiye") == ("Turkey", [])               # diacritic normalized
    assert m.split_origin_threat("Korea") == ("South Korea", [])            # MS 'Korea' = South Korea (#11)
    assert m.split_origin_threat("North Korea") == ("North Korea", [])      # DPRK unaffected
    assert m.split_origin_threat("Group in development") == ("", [])        # record-marker ignored
    assert m.split_origin_threat("Israel, Private sector offensive actor") == \
        ("Israel", ["private sector offensive actor"])
    recs = {r["name"]: r for r in m.msft_records(_MSFT)}
    assert "" not in recs and len(recs) == 4                              # nameless row dropped
    mb = recs["Midnight Blizzard"]
    assert mb["origin"] == "Russia" and mb["motivation"] == []
    assert "Midnight Blizzard" not in mb["aliases"]                       # own name dropped
    assert "APT29" in mb["aliases"] and "Cozy Bear" in mb["aliases"]
    assert recs["Carmine Tsunami"]["aliases"] == []                       # empty Other names


def test_msft_observation_mode_resolves_canonical_via_aliases():
    if _skip_without_engine():
        return
    m = _load("okpack_sec_msft_import")
    with tempfile.TemporaryDirectory() as t:
        v = Path(t)
        # existing canonical APT29 — Microsoft's weather name resolves to it via its 'Other names'
        _is_page(t, "a", "apt29", "type: intrusion-set\nname: APT29\naliases: [Cozy Bear]\ntlp: clear\n")
        c = m.import_observations(_MSFT, v, "2026-06-20")
        # Midnight Blizzard merges via TWO shared keys (APT29 + Cozy Bear) — strong enough,
        # not flagged; the others mint (no overlap). nameless row not written.
        assert c == {"written": 4, "total": 4, "flagged": 0}
        mb = v / "wiki" / "observations" / "microsoft" / "m" / "midnight-blizzard.md"
        assert mb.is_file()
        txt = mb.read_text()
        assert "source: microsoft" in txt and "reliability:" in txt
        assert "canonical: apt29" in txt                                  # resolved via Other names
        assert "suspected_origin: Russia" in txt
        # a record matching no canonical mints its own slug
        storm = v / "wiki" / "observations" / "microsoft" / "s" / "storm-0230.md"
        assert storm.is_file() and "canonical: storm-0230" in storm.read_text()
        # motivation carried as a union list
        assert "financially motivated" in \
            (v / "wiki" / "observations" / "microsoft" / "c" / "cinnamon-tempest.md").read_text()
        m.import_observations(_MSFT, v, "2026-06-20")
        assert mb.read_text() == txt                                      # deterministic / idempotent


def test_msft_observation_guards_single_alias_over_merge():
    """okengine#39: a Microsoft actor whose ONLY tie to an existing canonical is a single shared
    alias (primary names differ) must NOT merge — the guard mints a distinct canonical + flags it."""
    if _skip_without_engine():
        return
    m = _load("okpack_sec_msft_import")
    with tempfile.TemporaryDirectory() as t:
        v = Path(t)
        _is_page(t, "s", "sandworm-team",
                 "type: intrusion-set\nname: Sandworm Team\naliases: [IRIDIUM, Voodoo Bear]\ntlp: clear\n")
        data = [{"Threat actor name": "Plaid Rain", "Origin/Threat": "Lebanon",
                 "Other names": "IRIDIUM"}]                   # lone shared alias with sandworm-team
        c = m.import_observations(data, v, "2026-06-20")
        assert c == {"written": 1, "total": 1, "flagged": 1}
        pr = (v / "wiki" / "observations" / "microsoft" / "p" / "plaid-rain.md").read_text()
        assert "canonical: plaid-rain" in pr                  # guard declined the merge
        assert "canonical: sandworm-team" not in pr
        rq = (v / "wiki" / "_review-queue.md").read_text()
        assert "over-merge guard" in rq and "plaid-rain" in rq


# ── ATT&CK bibliography -> citing source pages (okpacks-library#2) ────────────
_REFS_BUNDLE = {"objects": [
    {"type": "intrusion-set", "name": "APT29", "id": "intrusion-set--1",
     "external_references": [
        {"source_name": "mitre-attack", "external_id": "G0016",
         "url": "https://attack.mitre.org/groups/G0016"},
        {"source_name": "CrowdStrike StellarParticle January 2022",
         "url": "https://www.crowdstrike.com/blog/stellarparticle/",
         "description": "CrowdStrike report."},
        {"source_name": "CISA AA20-352A",
         "url": "https://www.cisa.gov/news-events/alerts/aa20-352a"}]},
    {"type": "intrusion-set", "name": "APT28", "id": "intrusion-set--2",
     "external_references": [
        # the SAME CrowdStrike report, cited by a second actor -> one page, two actor links
        {"source_name": "CrowdStrike StellarParticle 2022",
         "url": "https://www.crowdstrike.com/blog/stellarparticle/"},
        {"source_name": "Krebs DNC 2016", "url": "https://krebsonsecurity.com/2016/07/dnc/"}]},
    {"type": "intrusion-set", "name": "Dead Group", "x_mitre_deprecated": True,
     "id": "intrusion-set--3",
     "external_references": [{"source_name": "X", "url": "https://example.org/x"}]},
]}


def test_refs_classify_and_publish():
    m = _load("okpack_sec_attack_refs_import")
    assert m.classify("https://www.cisa.gov/x") == {"publisher": "CISA", "reliability": "A",
        "credibility": 2, "source_kind": "advisory", "bias_flags": []}
    cs = m.classify("https://www.crowdstrike.com/blog/y")
    assert cs["reliability"] == "A" and cs["source_kind"] == "vendor-research"
    assert cs["bias_flags"] == ["vendor-commercial"]
    assert m.classify("https://krebsonsecurity.com/z")["reliability"] == "C"
    unk = m.classify("https://some-random-blog.example/p")
    assert unk["reliability"] == "D" and unk["source_kind"] == "blog" and unk["publisher"]
    assert m.classify("https://www.gov.uk/government/x")["reliability"] == "A"   # broadened gov match
    # dates: explicit Month YYYY -> month precision; bare year -> Jan; none -> ''
    assert m.parse_published("CrowdStrike StellarParticle January 2022", "") == "2022-01-01"
    assert m.parse_published("Report 2016", "") == "2016-01-01"
    assert m.parse_published("No date here", "") == ""
    # Wayback unwrap (single-slash + scheme-less) attributes the real publisher; ts -> date
    assert m._domain(m._unwrap(
        "https://web.archive.org/web/20180808125108/https:/www.fireeye.com/a")) == "fireeye.com"
    assert m._domain(m._unwrap(
        "https://web.archive.org/web/20201123042131/www.welivesecurity.com/a")) == "welivesecurity.com"
    assert m.parse_published(
        "Symantec", "https://web.archive.org/web/20170823094836/http:/www.symantec.com/a") == "2017-08-23"


def test_refs_dedup_aggregates_actors_and_skips_deprecated():
    m = _load("okpack_sec_attack_refs_import")
    recs = {r["url"]: r for r in m.parse_group_refs(_REFS_BUNDLE)}
    assert "https://example.org/x" not in recs                # deprecated group's ref excluded
    assert not any("attack.mitre.org" in u for u in recs)     # mitre self-refs excluded
    cs = recs["https://www.crowdstrike.com/blog/stellarparticle/"]
    assert cs["actors"] == ["apt28", "apt29"]                 # one page, both citing actors, sorted
    assert cs["reliability"] == "A" and cs["published"] == "2022-01-01"
    assert cs["description"] == "CrowdStrike report."         # longest description across cites wins


def test_refs_import_creates_and_is_non_destructive():
    m = _load("okpack_sec_attack_refs_import")
    with tempfile.TemporaryDirectory() as t:
        v = Path(t)
        c = m.import_sources(_REFS_BUNDLE, v, "2026-06-20")
        assert c["created"] == 3 and c["total"] == 3          # CS (shared), CISA, Krebs
        files = list((v / "wiki" / "sources").rglob("*.md"))
        assert len(files) == 3
        csf = [p for p in files if "stellarparticle" in p.name][0]
        cs = csf.read_text()
        assert "type: source" in cs and "related-to:" in cs
        assert "[[apt29]]" in cs and "[[apt28]]" in cs        # both citing actors linked
        assert "CrowdStrike report." in cs                    # MITRE description -> body
        assert "/sources/2022/01/" in str(csf)                # foldered by published date
        c2 = m.import_sources(_REFS_BUNDLE, v, "2026-06-20")  # re-run is non-destructive
        assert c2["created"] == 0 and c2["exists"] == 3


# ── mdm_resolve: review-queue flag dedup (okpacks-library#8 follow-up) ────────
class _Amb:
    def __init__(self, candidate, shared):
        self.candidate, self.shared = candidate, shared


def test_mdm_flag_over_merge_dedups_on_rerun():
    m = _load("mdm_resolve")   # flag_over_merge writes the queue only; no engine needed
    with tempfile.TemporaryDirectory() as t:
        v = Path(t)
        m.flag_over_merge(v, "iridium", "Iridium", _Amb("sandworm-team", ["iridium"]),
                          "thaicert", "2026-06-20")
        m.flag_over_merge(v, "iridium", "Iridium", _Amb("sandworm-team", ["iridium"]),
                          "thaicert", "2026-06-27")          # weekly re-run, later date
        rq = (v / "wiki" / "_review-queue.md").read_text()
        assert rq.count("entities/i/iridium.md") == 1        # deduped, not duplicated on re-run
        # a genuinely different decline still appends
        m.flag_over_merge(v, "fallow-squall", "Fallow Squall", _Amb("platinum", ["platinum"]),
                          "microsoft", "2026-06-27")
        assert (v / "wiki" / "_review-queue.md").read_text().count("over-merge guard") == 2


# ── strict failure mode (okpacks-library#16) ─────────────────────────────────
def test_kev_strict_mode_fetch_and_write():
    m = _load("okpack_sec_kev_import")
    # fetch/parse failure: best-effort returns 0; --strict returns nonzero
    assert m.main(["--src", "/nonexistent-kev.json"]) == 0
    assert m.main(["--src", "/nonexistent-kev.json", "--strict"]) == 1
    with tempfile.TemporaryDirectory() as t:
        src = Path(t) / "kev.json"
        src.write_text('{"vulnerabilities":[{"cveID":"CVE-2026-1","vulnerabilityName":"x",'
                       '"dateAdded":"2026-01-01"}]}')
        bad = Path(t) / "afile"
        bad.write_text("not a dir")        # vault is a file -> observation mkdir/write OSErrors
        # best-effort swallows the write error; --strict propagates it (nonzero exit)
        assert m.main(["--src", str(src), "--vault", str(bad), "--observations"]) == 0
        try:
            m.main(["--src", str(src), "--vault", str(bad), "--observations", "--strict"])
            raise AssertionError("strict write failure should have raised")
        except OSError:
            pass


# ── runner ───────────────────────────────────────────────────────────────────
def _run():
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


def test_schema_declares_field_drift_normalization():
    """okengine#46: the pack declares field/value drift normalization so the okengine-write path
    converges agent writes (country->suspected_origin; ISO codes -> the vault's full names).
    `status` is deliberately absent (active is valid for predictions/exploitation_status)."""
    import yaml
    pack = Path(__file__).resolve().parent.parent
    s = yaml.safe_load((pack / "schema.yaml").read_text(encoding="utf-8"))
    fa, va = s.get("field_aliases") or {}, s.get("value_aliases") or {}
    assert fa.get("country") == "suspected_origin" and fa.get("origin") == "suspected_origin"
    so = va.get("suspected_origin") or {}
    assert so.get("CN") == "China" and so.get("IR") == "Iran" and so.get("KP") == "North Korea"
    assert "status" not in va


def test_brief_linkfix_canonicalizes_and_demotes():
    """okpacks-library#42: brief wikilinks normalize to canonical entity paths (by slug or
    mitre_id), prefer the canonical over an observation twin, and dead targets demote to text."""
    m = _load("okpack_sec_brief_linkfix")
    with tempfile.TemporaryDirectory() as td:
        tmp_path = Path(td)
        w = tmp_path / "wiki"
        (w / "entities" / "s").mkdir(parents=True)
        (w / "entities" / "s" / "sapphire-sleet.md").write_text("---\ntype: intrusion-set\nname: Sapphire Sleet\n---\n")
        (w / "entities" / "e").mkdir(parents=True)
        (w / "entities" / "e" / "exploit-priv-esc-t1068.md").write_text("---\ntype: attack-pattern\nmitre_id: T1068\n---\n")
        (w / "observations" / "microsoft" / "s").mkdir(parents=True)
        (w / "observations" / "microsoft" / "s" / "sapphire-sleet.md").write_text("---\ntype: intrusion-set\nsource: microsoft\n---\n")
        (w / "briefings").mkdir(parents=True)
        page = w / "briefings" / "2026-06-21.md"
        page.write_text("---\ntype: dashboard\n---\n"
            "[[intrusion-set/s/sapphire-sleet|Sapphire Sleet]] used [[attack-pattern/t1068|T1068]]; "
            "see [[concepts/cms-exploitation|CMS exploitation]].\n")
        idx = m.build_index(tmp_path)
        rw, dr = m.fix_page(page, idx, str(tmp_path))
        t = page.read_text()
        assert "[[entities/s/sapphire-sleet|Sapphire Sleet]]" in t
        assert "[[entities/e/exploit-priv-esc-t1068|T1068]]" in t
        assert "concepts/cms-exploitation" not in t and "CMS exploitation" in t
        assert dr == 1

if __name__ == "__main__":
    print("== importer conformance ==")
    n = _run()
    print("all importer tests pass" if not n else f"{n} importer test(s) failed")
    sys.exit(1 if n else 0)
