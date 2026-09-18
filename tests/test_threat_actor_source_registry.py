from pathlib import Path

import yaml


PACK = Path(__file__).resolve().parents[1] / "packs" / "okpack-threat-actors"


def test_established_threat_research_publishers_have_review_policy():
    schema = yaml.safe_load((PACK / "schema.yaml").read_text(encoding="utf-8"))
    registry = schema["source_registry"]

    assert registry["Cisco Talos"]["reliability"] == "A"
    assert registry["BleepingComputer"]["reliability"] == "B"
    assert registry["The Hacker News"]["reliability"] == "B"
