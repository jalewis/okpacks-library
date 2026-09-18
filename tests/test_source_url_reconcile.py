import importlib.util
from pathlib import Path

import yaml


SCRIPT = (
    Path(__file__).resolve().parents[1]
    / "packs/okpack-threat-actors/crons/scripts/source_url_reconcile.py"
)


def _load():
    spec = importlib.util.spec_from_file_location("source_url_reconcile", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(module)
    return module


def test_replace_title_removes_folded_continuation_and_keeps_yaml_valid():
    module = _load()
    page = (
        "---\n"
        "type: source\n"
        "title: Trump executive order tightens defense supply chain oversight, mandates domestic\n"
        "  sourcing of critical materials\n"
        "url: https://example.test/old\n"
        "---\n"
        "# Report\n"
    )
    title = "Trump executive order tightens defense supply chain oversight, mandates domestic ..."

    fixed = module.replace_top_level_scalar(page, "title", title)
    frontmatter = yaml.safe_load(module.FM.match(fixed).group(1))

    assert frontmatter["title"] == title
    assert "  sourcing of critical materials" not in fixed
    assert frontmatter["url"] == "https://example.test/old"
    assert fixed.endswith("---\n# Report\n")
