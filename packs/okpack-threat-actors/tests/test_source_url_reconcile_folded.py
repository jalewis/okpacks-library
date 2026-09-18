"""source_url_reconcile — replacing a URL must not strand its continuation lines.

The lane rewrote the url with `re.sub(r"^url:.*$", ..., flags=re.M)`. That matches one
PHYSICAL line. A long URL is routinely emitted as a folded YAML scalar whose remainder sits
on indented continuation lines, so the replacement stranded the remainder as a bare line
inside the frontmatter and the page stopped parsing.

It broke six source pages on a live vault in one run. The URLs carried an RSS tracking
suffix (`?source=rss----<hex>---<n>`) which made them long enough to fold — and made the
orphaned tail look like a `---` delimiter, so the damage read as a mangled frontmatter
boundary rather than a truncated value.
"""
import ast
import importlib.util
import re
import sys
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

PACK = Path(__file__).resolve().parents[1]
SCRIPT = PACK / "crons" / "scripts" / "source_url_reconcile.py"

pytestmark = pytest.mark.skipif(not SCRIPT.is_file(), reason="lane absent")

FM_RE = re.compile(r"\A---[ \t]*\n(.*?\n)---[ \t]*(?:\n|\Z)", re.S)


def _mod():
    spec = importlib.util.spec_from_file_location("source_url_reconcile", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(SCRIPT.parent))
    try:
        spec.loader.exec_module(mod)
    finally:
        sys.path.pop(0)
    return mod


def rewrite(text: str, real: str) -> str:
    """The lane's own substitution, read out of the source so the test cannot drift from it."""
    src = SCRIPT.read_text(encoding="utf-8")
    m = re.search(r'txt = re\.sub\((r"\^url:[^"]*"), f"url: \{real\}", txt, count=1, '
                  r'flags=re\.M\)', src)
    assert m, "the url substitution is no longer where this test reads it from"
    # ast.literal_eval, not eval: this lifts a STRING LITERAL out of the module under test,
    # and a test helper is exactly the wrong place to normalise arbitrary execution.
    pattern = ast.literal_eval(m.group(1))
    return re.sub(pattern, f"url: {real}", text, count=1, flags=re.M)


FOLDED = ("---\n"
          "type: source\n"
          "url: https://example.test/a-long-article-slug-that-wrapped?source=rss\n"
          "  ----2983bc435765---4\n"
          "publisher: Example\n"
          "---\n\nbody\n")


def test_a_folded_url_is_replaced_whole_and_the_page_still_parses():
    out = rewrite(FOLDED, "https://example.test/real")
    fm = FM_RE.match(out)
    assert fm, "frontmatter boundary survived"
    parsed = yaml.safe_load(fm.group(1))
    assert parsed["url"] == "https://example.test/real"
    assert parsed["publisher"] == "Example"
    assert "2983bc435765" not in out, "the folded remainder must not survive as a bare line"


def test_a_single_line_url_still_works():
    single = "---\ntype: source\nurl: https://a.test/x\npublisher: Example\n---\n\nbody\n"
    out = rewrite(single, "https://b.test/y")
    parsed = yaml.safe_load(FM_RE.match(out).group(1))
    assert parsed["url"] == "https://b.test/y" and parsed["publisher"] == "Example"


def test_the_key_after_a_folded_url_is_never_consumed():
    """The continuation pattern must require indentation, or it would eat the next key."""
    out = rewrite(FOLDED, "https://example.test/real")
    assert "publisher: Example" in out


def test_the_module_still_imports():
    assert _mod() is not None
