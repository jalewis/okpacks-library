from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_public_validation_uses_the_catalog_pinned_engine():
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")

    assert "p['engine_version']" in workflow
    assert "repository: jalewis/OKEngine" in workflow
    assert "ref: ${{ steps.engine.outputs.ref }}" in workflow
    assert "ENGINE_DIR: ${{ github.workspace }}/.okengine-engine" in workflow
    assert "OKENGINE_DIR: ${{ github.workspace }}/.okengine-engine" in workflow
