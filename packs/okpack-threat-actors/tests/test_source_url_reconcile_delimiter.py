"""source_url_reconcile — front matter ends at a delimiter LINE, never at a line that merely starts
with "---" (okpacks-library#102).

`FM = r"\\A---\\s*\\n(.*?\\n)---"` closed on the first line BEGINNING with three dashes. A page another
writer had damaged -- a stray `---tail` line left inside its header when that writer split a URL
containing `---` -- therefore read here as a short, *valid* header whose url stopped mid-string.
The lane saw a url mismatch against the raw feed and wrote the full URL back, which the damaging
writer split again on its next run: one page grew hundreds of junk blocks that way. A page this lane
cannot read under a strict reader must be skipped, left byte-identical, and counted.
"""
import importlib.util
import json
import sys
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

PACK = Path(__file__).resolve().parents[1]
SCRIPT = PACK / "crons" / "scripts" / "source_url_reconcile.py"

pytestmark = pytest.mark.skipif(not SCRIPT.is_file(), reason="lane absent")

REAL = "https://research.example.test/gateway-sql-injection---actively-exploited"


def _mod():
    spec = importlib.util.spec_from_file_location("source_url_reconcile", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(SCRIPT.parent))
    try:
        spec.loader.exec_module(mod)
    finally:
        sys.path.pop(0)
    return mod


def _vault(tmp_path, page: str, raw_url: str = REAL) -> Path:
    (tmp_path / "raw" / "feed").mkdir(parents=True)
    (tmp_path / "raw" / "feed" / "item.md").write_text(
        f"---\ntitle: Gateway SQL Injection Exploited\nurl: {raw_url}\n---\n\nraw\n", encoding="utf-8")
    src = tmp_path / "wiki" / "sources" / "2026" / "page.md"
    src.parent.mkdir(parents=True)
    src.write_text(page, encoding="utf-8")
    return src


def _run(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("WIKI_PATH", str(tmp_path))
    assert _mod().main() == 0
    capsys.readouterr()
    return json.loads((tmp_path / ".okengine" / "url-reconcile-receipt.json").read_text())


# The damaged shape: the header was cut at the `---` inside the URL, and the remainder of the
# URL became a `---tail` line with the true fields after it.
DAMAGED = ("---\ntype: source\ntitle: Gateway SQL Injection Exploited\n"
           "url: https://research.example.test/gateway-sql-injection\n"
           "publisher: example.test\n---actively-exploited\npublished: '2026-09-15'\n"
           "id: sources:example\n---\n\n# Gateway SQL Injection Exploited\n\nBody.\n")


def test_a_dash_prefixed_line_is_not_a_closing_delimiter():
    assert _mod().FM.match(DAMAGED).group(1).count("\n") > 5, \
        "the header must run to the real delimiter line, not stop at `---actively-exploited`"


def test_a_page_whose_front_matter_does_not_parse_is_skipped_untouched(tmp_path, monkeypatch, capsys):
    page = _vault(tmp_path, DAMAGED)
    receipt = _run(tmp_path, monkeypatch, capsys)
    assert page.read_text(encoding="utf-8") == DAMAGED, "an unreadable page must not be edited"
    assert receipt["fixed"] == 0
    assert receipt["unparseable"] == ["sources/2026/page.md"], "and it must be counted, by name"


def test_a_url_containing_dashes_is_read_whole_and_left_alone_when_correct(tmp_path, monkeypatch, capsys):
    clean = (f"---\ntype: source\ntitle: Gateway SQL Injection Exploited\nurl: {REAL}\n"
             "publisher: example.test\n---\n\nBody.\n")
    page = _vault(tmp_path, clean)
    receipt = _run(tmp_path, monkeypatch, capsys)
    assert page.read_text(encoding="utf-8") == clean
    assert (receipt["agreed"], receipt["fixed"]) == (1, 0)


def test_a_wrong_url_on_a_readable_page_is_still_repaired_and_recorded(tmp_path, monkeypatch, capsys):
    """The negative half: strictness must not switch the lane off."""
    wrong = ("---\ntype: source\ntitle: Gateway SQL Injection Exploited\n"
             "url: https://research.example.test/gateway-sql-injection\npublisher: example.test\n"
             "---\n\nBody.\n")
    page = _vault(tmp_path, wrong)
    receipt = _run(tmp_path, monkeypatch, capsys)
    fm = yaml.safe_load(_mod().FM.match(page.read_text(encoding="utf-8")).group(1))
    assert fm["url"] == REAL and fm["publisher"] == "example.test"
    assert receipt["fixed"] == 1
    assert receipt["fixes"] == [{"page": "sources/2026/page.md", "url": REAL}], \
        "every write is named in the receipt, which survives a silent run"


def test_a_raw_item_with_a_damaged_header_is_not_used_as_truth(tmp_path, monkeypatch, capsys):
    wrong = ("---\ntype: source\ntitle: Gateway SQL Injection Exploited\n"
             "url: https://research.example.test/other\n---\n\nBody.\n")
    page = _vault(tmp_path, wrong)
    (tmp_path / "raw" / "feed" / "item.md").write_text(
        "---\ntitle: Gateway SQL Injection Exploited\nurl: https://research.example.test/a\n"
        "---b\nextra: [\n---\n\nraw\n", encoding="utf-8")
    receipt = _run(tmp_path, monkeypatch, capsys)
    assert page.read_text(encoding="utf-8") == wrong
    assert receipt["fixed"] == 0


def test_a_page_with_no_front_matter_is_skipped_but_not_counted_as_damaged(tmp_path, monkeypatch, capsys):
    page = _vault(tmp_path, "# Just a heading\n\nNo front matter at all.\n")
    receipt = _run(tmp_path, monkeypatch, capsys)
    assert page.read_text(encoding="utf-8").startswith("# Just a heading")
    assert receipt["unparseable"] == [], "only pages that HAVE front matter can be unreadable"


def test_a_receipt_that_cannot_be_written_warns_and_the_lane_still_succeeds(tmp_path, monkeypatch, capsys):
    _vault(tmp_path, "# page\n")
    (tmp_path / ".okengine").write_text("a file where the state directory should be", encoding="utf-8")
    monkeypatch.setenv("WIKI_PATH", str(tmp_path))
    assert _mod().main() == 0
    assert "WARNING receipt not written" in capsys.readouterr().out
