import importlib.util
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "crons" / "scripts" / "naics_sector.py"


def _load():
    spec = importlib.util.spec_from_file_location("naics_sector", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules["naics_sector"] = module
    spec.loader.exec_module(module)
    return module


def test_naics_sector_rollup():
    sector = _load().naics_sector
    assert sector("622110") == "Health care & social assistance"
    assert sector(522110) == "Finance & insurance"
    assert sector("31") == "Manufacturing"
    assert sector("NA") is None


if __name__ == "__main__":
    test_naics_sector_rollup()
    print("all NAICS-sector tests pass")
