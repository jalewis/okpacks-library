#!/usr/bin/env python3
"""Conformance: actor_correlation + signature_ttps link the entities they cite (count-lane gap).

Both lanes wrote a body section naming other actors / techniques in BOLD TEXT with no link — a
dead end for the analyst and no graph edge. They must emit wikilinks: correlated actors as
[[entities/<shard>/<slug>|Name]], signature techniques as [[techniques/<attack_id>|<attack_id>]].
Drives the real scripts with inline actor fixtures sharing rare tradecraft.

Standalone (conformance-all.sh) and pytest-discoverable.
"""
import importlib.util
import sys
import tempfile
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent.parent / "crons" / "scripts"


def _load(name):
    sys.path.insert(0, str(SCRIPTS))
    sys.modules.pop(name, None)
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _actor(root, shard, slug, title, techniques, software=(), sectors=()):
    p = root / "wiki" / "entities" / shard / f"{slug}.md"
    p.parent.mkdir(parents=True, exist_ok=True)
    tq = "".join(f"  - {t}\n" for t in techniques)
    sq = "".join(f"  - {s}\n" for s in software)
    cq = "".join(f"  - {s}\n" for s in sectors)
    p.write_text(f"---\ntype: actor\nid: {slug}\ntitle: {title}\ntechniques:\n{tq}"
                 + (f"software:\n{sq}" if software else "")
                 + (f"target_sector:\n{cq}" if sectors else "")
                 + "---\nbody\n", encoding="utf-8")


def _vault(t):
    v = Path(t)
    # two actors sharing a RARE custom technique (T1583.001) + tool, plus filler so idf is non-zero
    _actor(v, "a", "apt-alpha", "APT Alpha", ["T1583.001", "T1071.001", "T1059", "T1105"], ["CustomRAT"])
    _actor(v, "b", "apt-beta", "APT Beta", ["T1583.001", "T1071.001", "T1059", "T1105"], ["CustomRAT"])
    _actor(v, "c", "apt-gamma", "APT Gamma", ["T1566", "T1059", "T1105", "T1027"])
    return v


def test_actor_correlation_links_correlated_actors():
    m = _load("actor_correlation")
    with tempfile.TemporaryDirectory() as t:
        v = _vault(t)
        assert m.main(["--vault", str(v), "--min-shared", "2", "--min-score", "0"]) == 0
        page = (v / "wiki" / "entities" / "a" / "apt-alpha.md").read_text(encoding="utf-8")
        assert "## Correlated actors" in page
        # APT Beta is cited as a LINK (with .md stripped), not bold text
        assert "[[entities/b/apt-beta|APT Beta]]" in page, page
        assert "**APT Beta**" not in page
        assert ".md|" not in page                         # no stray .md leaked into a wikilink


def test_signature_ttps_links_techniques():
    m = _load("signature_ttps")
    with tempfile.TemporaryDirectory() as t:
        v = _vault(t)
        assert m.main(["--vault", str(v), "--min-techniques", "3", "--top-k", "5"]) == 0
        page = (v / "wiki" / "entities" / "c" / "apt-gamma.md").read_text(encoding="utf-8")
        assert "## Signature tradecraft" in page
        # a rare technique is linked to its page (stem == attack_id)
        assert "[[techniques/T1027|T1027]]" in page or "[[techniques/T1566|T1566]]" in page, page
        assert "- **T" not in page                        # no bold-text technique dead ends


def _run() -> int:
    fails = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn(); print(f"  ok   {name}")
            except AssertionError as e:
                fails += 1; print(f"  FAIL {name}: {e}")
    return fails


if __name__ == "__main__":
    print("== okpack-threat-actors count-lane link conformance ==")
    n = _run()
    print("all count-lane tests pass" if not n else f"{n} test(s) failed")
    sys.exit(1 if n else 0)
