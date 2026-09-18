"""Cross-pack canonical type names must never be context-dependent aliases."""
from pathlib import Path
import re

import yaml

ROOT = Path(__file__).resolve().parents[1]


def _schema(pack):
    return yaml.safe_load((ROOT / "packs" / pack / "schema.yaml").read_text()) or {}


def test_technique_always_means_attack_technique_when_packs_compose():
    ai = _schema("okpack-ai-research")
    threat = _schema("okpack-threat-actors")
    assert "technique" in threat["types"]
    assert "technique" not in (ai.get("type_aliases") or {})
    assert "method" in ai["types"]


def test_product_always_means_market_product_when_packs_compose():
    threat = _schema("okpack-threat-actors")
    competitive = _schema("okpack-competitive")
    assert "product" in competitive["types"]
    assert "product" not in (threat.get("type_aliases") or {})
    assert "tool" in threat["types"]


def test_library_gate_treats_future_cross_pack_alias_ambiguity_as_failure():
    validator = (ROOT / "scripts" / "validate-library.py").read_text()
    assert re.search(r"if owner and owner != m\.get\(\"name\"\):\s+fail\(f\"composition:",
                     validator)
