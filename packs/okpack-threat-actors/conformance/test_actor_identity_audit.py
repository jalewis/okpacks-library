#!/usr/bin/env python3
import importlib.util
import sys
from pathlib import Path

import yaml

SCRIPTS = Path(__file__).resolve().parent.parent / "crons" / "scripts"


def _load():
    for name in ("_okf_write", "okf_migrate", "actor_identity_audit"):
        sys.modules.pop(name, None)
    sys.path.insert(0, str(SCRIPTS))
    spec = importlib.util.spec_from_file_location("actor_identity_audit", SCRIPTS / "actor_identity_audit.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _write(path: Path, fm: dict, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("---\n" + yaml.safe_dump(fm, sort_keys=False) + "---\n\n" + body + "\n")


def _fm(path: Path) -> dict:
    text = path.read_text()
    return yaml.safe_load(text[3:text.find("\n---", 3)])


def test_classifies_production_regressions_without_touching_real_names(tmp_path):
    audit = _load()
    cases = {
        "unsafe": ({"type": "actor", "title": "Unsafe"}, "Imported placeholder", "tombstone"),
        "outsider": ({"type": "actor", "title": "Outsider"}, "Claimed group", "tombstone"),
        "sleepwalker": ({"type": "actor", "title": "SLEEPWALKER"}, "SLEEPWALKER is a Windows backdoor.", "malware"),
        "mirage2fa": ({"type": "actor", "title": "Mirage2FA"}, "Mirage2FA is a phishing-as-a-service toolkit.", "malware"),
        "bridgepay": ({"type": "actor", "title": "BridgePay Ransomware"}, "This ransomware affected billing systems.", "malware"),
        "comment-crew": ({"type": "actor", "title": "Comment Crew"}, "A named intrusion set.", "keep"),
        "scattered-spider": ({"type": "actor", "title": "Scattered Spider"}, "A named group.", "keep"),
        "sparklinggoblin": (
            {"type": "actor", "title": "SparklingGoblin"},
            "A modular backdoor, SideWalk, is used by an APT group named SparklingGoblin.",
            "keep",
        ),
        "gunra": (
            {"type": "actor", "title": "Gunra"},
            "Gunra is a ransomware-as-a-service (RaaS) operation targeting government entities.",
            "keep",
        ),
        "apt29": ({"type": "actor", "title": "APT29", "attack_id": "G0016"}, "Malware operators.", "keep"),
    }
    for slug, (fm, body, expected) in cases.items():
        assert audit.classify(fm, body, Path(f"{slug}.md"))[0] == expected


def test_apply_retypes_and_tombstones_then_is_idempotent(tmp_path, capsys):
    audit = _load()
    (tmp_path / "schema.yaml").write_text(
        "identity_admission:\n"
        "  actor:\n"
        "    excluded_exact_titles: {KP: North Korea, IR: Iran}\n"
    )
    wiki = tmp_path / "wiki" / "entities"
    _write(wiki / "unsafe.md", {"type": "actor", "title": "Unsafe", "recent_news": 5}, "bad")
    _write(wiki / "sleepwalker.md", {"type": "actor", "title": "SLEEPWALKER", "actor_type": "unknown"},
           "SLEEPWALKER is a Windows backdoor.")
    _write(wiki / "north-korea.md", {"type": "actor", "title": "North Korea"}, "Country.")
    _write(wiki / "lazarus.md", {"type": "actor", "title": "Lazarus Group"}, "Named group.")
    assert audit.main(["--vault", str(tmp_path), "--apply"]) == 0
    unsafe = _fm(wiki / "unsafe.md")
    sleepwalker = _fm(wiki / "sleepwalker.md")
    north_korea = _fm(wiki / "north-korea.md")
    assert unsafe["status"] == "tombstoned"
    assert north_korea["status"] == "tombstoned"
    assert "geopolitical entity" in north_korea["tombstone_reason"]
    assert "status" not in _fm(wiki / "lazarus.md")
    assert sleepwalker["type"] == "malware"
    assert "actor_type" not in sleepwalker
    assert audit.main(["--vault", str(tmp_path), "--apply"]) == 0
    assert "tombstoned 0, retyped malware 0" in capsys.readouterr().out


def test_reserved_titles_support_list_schema_and_fail_closed_on_bad_shapes(tmp_path):
    audit = _load()
    wiki_schema = tmp_path / "wiki" / "schema.yaml"
    wiki_schema.parent.mkdir(parents=True)
    wiki_schema.write_text(
        "identity_admission:\n  actor:\n    excluded_exact_titles: [North Korea, Iran]\n"
    )
    assert audit._reserved_actor_titles(tmp_path) == frozenset({"north korea", "iran"})

    wiki_schema.write_text("identity_admission:\n  actor:\n    excluded_exact_titles: North Korea\n")
    assert audit._reserved_actor_titles(tmp_path) == frozenset()
    wiki_schema.write_text("[broken")
    assert audit._reserved_actor_titles(tmp_path) == frozenset()
    wiki_schema.unlink()
    assert audit._reserved_actor_titles(tmp_path) == frozenset()
