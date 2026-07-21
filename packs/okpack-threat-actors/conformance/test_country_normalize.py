"""Country normalization is deterministic and refuses geopolitical prose."""
import importlib.util
import sys
import tempfile
from pathlib import Path

import yaml

SCRIPT = Path(__file__).resolve().parent.parent / "crons" / "scripts" / "country_normalize.py"
NORMALIZER = SCRIPT.with_name("origin_country_normalize.py")


def _load():
    spec = importlib.util.spec_from_file_location("country_normalize", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules["country_normalize"] = module
    spec.loader.exec_module(module)
    return module


def test_country_normalization():
    normalize = _load().normalize_country
    assert normalize("Iran") == "IR"
    assert normalize("ru") == "RU"
    assert normalize(["North Korea"]) == "KP"
    assert normalize("Russia-Ukraine conflict zone") is None
    assert normalize(["RU", "UA"]) is None


def test_normalizer_quarantines_non_country_values():
    _load()
    spec = importlib.util.spec_from_file_location("origin_country_normalize", NORMALIZER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        page = root / "wiki" / "entities" / "a" / "actor.md"
        page.parent.mkdir(parents=True)
        page.write_text("---\ntype: actor\norigin_country: Russia-Ukraine conflict zone\n---\nbody\n")
        assert module.main(["--vault", str(root)]) == 0
        fm = yaml.safe_load(page.read_text().split("---", 2)[1])
        assert "origin_country" not in fm
        assert fm["origin_country_raw"] == "Russia-Ukraine conflict zone"
        assert fm["needs_review"] is True


if __name__ == "__main__":
    test_country_normalization()
    test_normalizer_quarantines_non_country_values()
    print("all country-normalize tests pass")
