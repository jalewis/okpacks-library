"""Catalog pack releases must match their installable pack metadata."""

import importlib.util
from pathlib import Path


VALIDATOR = Path(__file__).resolve().parents[1] / "scripts" / "validate-library.py"


def _load():
    spec = importlib.util.spec_from_file_location("validate_library_catalog", VALIDATOR)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_catalog_pack_version_mismatch_fails(tmp_path: Path) -> None:
    module = _load()
    module.ROOT = tmp_path
    module.fails.clear()
    pack = tmp_path / "packs" / "example"
    pack.mkdir(parents=True)
    (pack / "pack.yaml").write_text(
        "name: example\nversion: 0.1.2\ntrust: public\n", encoding="utf-8"
    )
    (pack / "engine.version").write_text(
        "engine: okengine\nversion: v0.14.3\nhermes_pin: v2026.9.14\n", encoding="utf-8"
    )
    catalog = {"packs": [{
        "name": "example", "version": "0.1.1", "subdir": "packs/example",
        "trust": "public", "engine_version": "v0.14.3", "validated_against": "v0.14.3",
    }]}

    module.check_catalog_consistency(catalog)

    assert module.fails == [
        "catalog: example: catalog version '0.1.1' != pack.yaml version '0.1.2'"
    ]
