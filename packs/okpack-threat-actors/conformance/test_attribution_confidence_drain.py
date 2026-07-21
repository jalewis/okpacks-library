#!/usr/bin/env python3
import importlib.util
import sys
import tempfile
from pathlib import Path

import yaml


PACK = Path(__file__).resolve().parents[1]
SCRIPT = PACK / "crons" / "scripts" / "attribution_confidence_drain.py"
SPEC = importlib.util.spec_from_file_location("attribution_confidence_drain", SCRIPT)
drain = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(drain)


def _page(root: Path, name: str, typ: str, value: str) -> Path:
    path = root / f"{name}.md"
    path.write_text(
        f"---\ntype: {typ}\nattribution_confidence: {value}\n---\n\n# Body\n",
        encoding="utf-8",
    )
    return path


def _fm(path: Path) -> dict:
    text = path.read_text()
    return yaml.safe_load(text[3:text.find("\n---", 3)])


def test_conservative_mapping_preserves_rationale():
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        page = _page(root, "actor", "actor",
                     "low-medium — one detailed vendor report without independent confirmation")
        assert drain.drain_page(page) == ("change", "lower-bound-and-rationale-split")
        fm = _fm(page)
        assert fm["attribution_confidence"] == "low"
        assert "one detailed vendor report" in fm["attribution_notes"]
        assert fm["needs_review"] is True


def test_non_attribution_page_loses_inapplicable_field():
    with tempfile.TemporaryDirectory() as temp:
        page = _page(Path(temp), "vuln", "vulnerability_discovery",
                     "vulnerability_research_not_campaign_attribution")
        assert drain.drain_page(page) == ("change", "remove-inapplicable")
        assert "attribution_confidence" not in _fm(page)


def test_unknown_value_is_rejected_without_mutation():
    with tempfile.TemporaryDirectory() as temp:
        page = _page(Path(temp), "actor", "actor", "roughly plausible")
        before = page.read_bytes()
        assert drain.drain_page(page) == ("reject", "roughly plausible")
        assert page.read_bytes() == before


if __name__ == "__main__":
    failures = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"  ok   {name}")
            except AssertionError as exc:
                failures += 1
                print(f"  FAIL {name}: {exc}")
    sys.exit(1 if failures else 0)
