import importlib.util
import sys
from pathlib import Path


SCRIPTS = Path(__file__).resolve().parent.parent / "crons" / "scripts"


def _load():
    sys.path.insert(0, str(SCRIPTS))
    spec = importlib.util.spec_from_file_location(
        "actor_identity_audit_unit", SCRIPTS / "actor_identity_audit.py"
    )
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def test_country_vocabulary_drives_exact_actor_exclusion(tmp_path):
    audit = _load()
    (tmp_path / "schema.yaml").write_text(
        "identity_admission:\n"
        "  actor:\n"
        "    excluded_exact_titles: {KP: North Korea, IR: Iran}\n"
    )
    reserved = audit._reserved_actor_titles(tmp_path)
    assert reserved == frozenset({"north korea", "iran"})
    action, reason = audit.classify(
        {"type": "actor", "title": "North Korea"}, "Country.", Path("north-korea.md"), reserved
    )
    assert action == "tombstone"
    assert "attribution value" in reason
    assert audit.classify(
        {"type": "actor", "title": "North Korean Lazarus Group"},
        "Named intrusion set.",
        Path("lazarus.md"),
        reserved,
    )[0] == "keep"
