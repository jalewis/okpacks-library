"""Generated engine namespaces must never be claimed by a domain pack (#95)."""
from pathlib import Path

import pytest
import yaml


PACKS = Path(__file__).resolve().parents[1] / "packs"


@pytest.mark.parametrize("manifest", sorted(PACKS.glob("*/pack.yaml")),
                         ids=lambda path: path.parent.name)
def test_pack_does_not_claim_engine_generated_namespaces(manifest):
    metadata = yaml.safe_load(manifest.read_text())
    owned = set((metadata.get("owns") or {}).get("namespaces") or [])
    assert not owned & {"dashboards", "operational"}, (
        f"{manifest.parent.name} claims engine-generated namespaces: {sorted(owned)}"
    )
