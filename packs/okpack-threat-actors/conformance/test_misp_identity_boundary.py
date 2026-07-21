import importlib.util
import sys
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "crons/scripts"
sys.path.insert(0, str(SCRIPTS))
spec = importlib.util.spec_from_file_location("misp_galaxy_import", SCRIPTS / "misp_galaxy_import.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def _actor(path: Path, title: str, aliases=()):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("---\n" + yaml.safe_dump({"type": "actor", "title": title,
                    "aliases": list(aliases)}, sort_keys=False) + "---\n\nBody\n")


def test_primary_index_does_not_treat_shared_short_alias_as_identity(tmp_path):
    entities = tmp_path / "entities"
    _actor(entities / "d/dragonforce.md", "DragonForce ransomware cartel", ["DragonForce"])
    _actor(entities / "d/dragonforce-malaysia.md", "DragonForce Malaysia", ["DFM"])

    primary = module.primary_actor_index(tmp_path)
    aliases = module.index_actors(tmp_path)

    assert "dragonforce" not in primary
    assert aliases["dragonforce"] == "entities/d/dragonforce.md"
    assert primary["dragonforce malaysia"] == "entities/d/dragonforce-malaysia.md"


def test_line_aware_existing_parser_accepts_url_hyphens(tmp_path):
    path = tmp_path / "entities/d/dragonforce.md"
    path.parent.mkdir(parents=True)
    path.write_text("---\ntype: actor\ntitle: DragonForce\n"
                    "url: https://example.test/?source=rss------2\n---\n\nBody\n")
    assert module.primary_actor_index(tmp_path)["dragonforce"] == "entities/d/dragonforce.md"
