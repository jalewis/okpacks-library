#!/usr/bin/env python3
"""Conformance for actor_activity.py — the report-pedigree counts on each actor page.

Invariants:
  1. `recent_reports` never exceeds `total_mentions`. The lane owns both fields; a value that drifted
     above total from another writer (an agent once hand-set `recent_reports` to a list of paths) is
     corrected on the next run — the field is overwritten AND clamped, not preserved.
  2. The dashboard ranks by report-mention volume (recent, then total).

(NEWS recency — news_last_seen — lives in a separate lane, actor_news_activity.py, tested alongside;
mentions_actors is written only by the report importers, so this lane can't see the news firehose.)

Drives the REAL actor_activity against the REAL _okf_write, co-located as deploy-cron-scripts stages
them. Runs standalone (conformance-all.sh) and is pytest-discoverable.
"""
import importlib.util
import sys
import tempfile
from pathlib import Path

import yaml

SCRIPTS = Path(__file__).resolve().parent.parent / "crons" / "scripts"


def _load(name: str):
    """Import a co-located cron script fresh, so its sibling `from _okf_write import ...` resolves to
    the pack's own copy (no engine okf_migrate present -> legacy flat write, which round-trips each
    page back to its own rel_path — exactly what these flat-vault assertions need)."""
    for m in ("_okf_write", "okf_migrate", name):
        sys.modules.pop(m, None)
    sys.path.insert(0, str(SCRIPTS))
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _write(p: Path, fm: dict, body: str = "x") -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("---\n" + yaml.safe_dump(fm, sort_keys=False) + "---\n\n" + body + "\n", encoding="utf-8")


def _fm(p: Path) -> dict:
    t = p.read_text(encoding="utf-8")
    return yaml.safe_load(t[3:t.find("\n---", 3)]) or {}


def _build(vault: Path) -> None:
    wiki = vault / "wiki"
    # three actors; `charlie` carries a DRIFTED recent_reports (above its true count) to prove the
    # lane overwrites/clamps it rather than preserving the stale value.
    _write(wiki / "entities" / "alpha.md", {"type": "actor", "title": "Alpha"})
    _write(wiki / "entities" / "bravo.md", {"type": "actor", "title": "Bravo"})
    _write(wiki / "entities" / "charlie.md", {"type": "actor", "title": "Charlie", "recent_reports": 99})
    # sources: alpha = 2 mentions, newest 2026-07-01 (recent, low volume);
    #          bravo = 3 mentions, newest 2026-06-01 (recent, HIGHER volume, but OLDER);
    #          charlie = 1 mention.
    S = wiki / "sources"
    _write(S / "s1.md", {"type": "source", "published": "2026-05-10", "mentions_actors": ["alpha", "bravo"]})
    _write(S / "s2.md", {"type": "source", "published": "2026-07-01", "mentions_actors": ["alpha"]})
    _write(S / "s3.md", {"type": "source", "published": "2026-06-01", "mentions_actors": ["bravo"]})
    _write(S / "s4.md", {"type": "source", "published": "2026-04-01", "mentions_actors": ["bravo", "charlie"]})


def test_actor_activity_clamps_and_ranks_by_volume():
    aa = _load("actor_activity")
    with tempfile.TemporaryDirectory() as t:
        vault = Path(t)
        _build(vault)
        rc = aa.main(["--vault", str(vault)])
        assert rc == 0

        ent = vault / "wiki" / "entities"
        alpha, bravo, charlie = _fm(ent / "alpha.md"), _fm(ent / "bravo.md"), _fm(ent / "charlie.md")

        # 1) recent_reports <= total_mentions on every actor; charlie's drifted 99 is corrected to 1
        for a in (alpha, bravo, charlie):
            assert a["recent_reports"] <= a["total_mentions"], a
        assert charlie["recent_reports"] == 1 and charlie["total_mentions"] == 1, charlie
        assert bravo["total_mentions"] == 3 and alpha["total_mentions"] == 2
        # the report lane must NOT write news recency — that field belongs to actor_news_activity
        assert "news_last_seen" not in alpha, alpha

        # 2) dashboard ranks by report volume: bravo (3) > alpha (2) > charlie (1)
        dash = (vault / "wiki" / "dashboards" / "top-actors-by-activity.md").read_text(encoding="utf-8")
        assert dash.index("Bravo") < dash.index("Alpha") < dash.index("Charlie"), dash


if __name__ == "__main__":
    test_actor_activity_clamps_and_ranks_by_volume()
    print("ok")
