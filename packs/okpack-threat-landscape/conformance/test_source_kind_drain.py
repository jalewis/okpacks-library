#!/usr/bin/env python3
import importlib.util
import sys
import tempfile
from pathlib import Path

import yaml


PACK = Path(__file__).resolve().parents[1]
SCRIPT = PACK / "crons" / "scripts" / "source_kind_drain.py"
SPEC = importlib.util.spec_from_file_location("source_kind_drain", SCRIPT)
drain = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(drain)


def test_aliases_collapse_to_core_vocabulary():
    with tempfile.TemporaryDirectory() as temp:
        path = Path(temp) / "annual.md"
        path.write_text("---\ntype: source\nsource_kind: annual-report\n---\nbody\n")
        assert drain.drain_page(path) == ("change", "annual-report->report")
        text = path.read_text()
        fm = yaml.safe_load(text[3:text.find("\n---", 3)])
        assert fm["source_kind"] == "report"
        assert text.endswith("body\n")


if __name__ == "__main__":
    try:
        test_aliases_collapse_to_core_vocabulary()
        print("  ok   test_aliases_collapse_to_core_vocabulary")
    except AssertionError as exc:
        print(f"  FAIL test_aliases_collapse_to_core_vocabulary: {exc}")
        sys.exit(1)
