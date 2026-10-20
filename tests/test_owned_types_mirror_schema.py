"""A pack's `owns.types` mirrors the types its own schema.yaml defines.

pack.yaml documents `owns.types` as mirroring schema.yaml `types:`, and composition relies on it:
ownership is how co-installed packs are checked for disjointness. When a schema grows types and
pack.yaml is not updated, the pack under-claims what it defines and nothing notices -- one pack
drifted by fifteen types this way before a live comparison caught it. Every pack that ships a
schema.yaml is held to this; a bundle recipe (no schema of its own) is not.
"""
from __future__ import annotations

import pathlib

import pytest
import yaml

PACKS = sorted(p.parent for p in (pathlib.Path(__file__).resolve().parents[1] / "packs").glob("*/pack.yaml")
               if (p.parent / "schema.yaml").is_file())


def test_there_are_packs_to_check():
    assert PACKS, "no pack with a schema.yaml found -- the check examined nothing"


@pytest.mark.parametrize("pack", PACKS, ids=lambda p: p.name)
def test_owned_types_are_exactly_the_schema_types(pack):
    owned = set(((yaml.safe_load((pack / "pack.yaml").read_text()) or {}).get("owns") or {}).get("types") or [])
    defined = set(((yaml.safe_load((pack / "schema.yaml").read_text()) or {}).get("types") or {}).keys())
    assert owned == defined, (
        f"{pack.name}: pack.yaml owns.types must mirror schema.yaml types -- "
        f"defined but not owned: {sorted(defined - owned)}; owned but not defined: {sorted(owned - defined)}")


def test_the_check_rejects_a_pack_that_under_claims(tmp_path):
    """Negative fixture: the assertion must fire on the drift it exists to catch."""
    pack = tmp_path / "okpack-demo"
    pack.mkdir()
    (pack / "pack.yaml").write_text("owns:\n  types: [vendor]\n")
    (pack / "schema.yaml").write_text("types:\n  vendor: {}\n  segment: {}\n")
    with pytest.raises(AssertionError, match=r"defined but not owned: \['segment'\]"):
        test_owned_types_are_exactly_the_schema_types(pack)
