"""A page's `raw:` backlink is a vault-relative capture path, never a `raw:<ns>/<slug>` pseudo-ref.

OKEngine records the capture a source page was compiled from as its vault path (`raw/ai/x.md`):
raw-compile and converge_source write it, and the raw selectors read it back to know a capture
is processed. okpack-ai-research's golden source page and its page-shapes example showed
`raw: raw:ai/<slug>` instead, and the old daily-papers importer copied that shape onto 638
source pages of one live vault (okpacks-library#105) -- a backlink no engine lane can resolve. The importer no longer
writes pages (c766844); this keeps the shape from being taught again by an example or a writer.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

PACKS = Path(__file__).resolve().parents[1] / "packs"
# `raw: raw:ai/x` in YAML/markdown, or a writer building "raw:<ns>/..." as a string value.
_PSEUDO = re.compile(r"""(^\s*-?\s*raw:\s*["']?raw:[a-z0-9_-]+/)|(["']raw:[a-z0-9_{-]+/)""",
                     re.IGNORECASE | re.MULTILINE)
FILES = sorted(p for p in PACKS.rglob("*") if p.suffix in {".md", ".yaml", ".yml", ".py"}
               and p.is_file())


def _hits(text: str) -> list[int]:
    return [text.count("\n", 0, m.start()) + 1 for m in _PSEUDO.finditer(text)]


def test_no_pack_file_carries_a_pseudo_raw_backlink():
    assert FILES, "no pack files found — the scan would pass on an empty set"
    bad = {str(p.relative_to(PACKS)): lines for p in FILES
           if (lines := _hits(p.read_text(encoding="utf-8", errors="replace")))}
    assert not bad, (
        f"`raw:` must name the capture's vault path (raw/<ns>/<file>.md), not a `raw:<ns>/...` "
        f"pseudo-ref no engine lane can resolve: {bad}")


@pytest.mark.parametrize("text", [
    "---\ntype: source\nraw: raw:ai/example\n---\n",
    "raw: 'raw:ai/example'\n",
    '    fm["raw"] = f"raw:ai/hf-daily-{rec[\'arxiv\']}"\n',
])
def test_the_matcher_sees_the_defect(text):
    """A scan that matched nothing would pass vacuously; prove it catches each shape it claims."""
    assert _hits(text)


@pytest.mark.parametrize("text", [
    "raw: raw/ai/example.md\n",
    "raw:\n  - raw/ai/a.md\n",
    "keyed by `raw:` for dedupe\n",
])
def test_the_matcher_passes_a_real_backlink(text):
    assert not _hits(text)
