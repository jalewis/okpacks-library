#!/usr/bin/env python3
"""Conformance for actor_news_activity.py — the NEWS-recency signal behind the cockpit "Recently
active" board (the thing report-derived mentions_actors could never provide).

Asserts the behaviour the board depends on:
  1. news_last_seen = the NEWEST news date whose text names the actor (title or aliases), and
     recent_news = the count within the window. So an actor in this week's news outranks one whose
     newest news is months old.
  2. The precision filters hold: a single-token English word ("Cleaver") or brand ("Alibaba") is NOT
     a match term — an article about Alibaba's XQUIC library, or one that merely uses the word
     "cleaver", must not tag the Cleaver actor. Its distinctive multi-word alias ("Operation Cleaver")
     still matches.
  3. The report lane's field is untouched (separate ownership).

Dates are computed relative to today so the windowing assertions never rot. Drives the REAL lane
against the REAL _okf_write (flat write when no engine okf_migrate is co-located — round-trips each
page to its own rel_path). Runs standalone and is pytest-discoverable.
"""
import importlib.util
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

SCRIPTS = Path(__file__).resolve().parent.parent / "crons" / "scripts"


def _load(name: str):
    for m in ("_okf_write", "okf_migrate", name):
        sys.modules.pop(m, None)
    sys.path.insert(0, str(SCRIPTS))
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _write(p: Path, fm: dict, body: str = "") -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("---\n" + yaml.safe_dump(fm, sort_keys=False) + "---\n\n" + body + "\n", encoding="utf-8")


def _fm(p: Path) -> dict:
    t = p.read_text(encoding="utf-8")
    return yaml.safe_load(t[3:t.find("\n---", 3)]) or {}


def test_news_recency_matches_by_name_and_respects_filters():
    aa = _load("actor_news_activity")
    today = datetime.now(timezone.utc).date()
    d = lambda n: (today - timedelta(days=n)).isoformat()   # noqa: E731

    with tempfile.TemporaryDirectory() as t:
        vault = Path(t)
        wiki = vault / "wiki"
        _write(wiki / "entities" / "sandworm.md", {"type": "actor", "title": "Sandworm Team"})
        _write(wiki / "entities" / "lazarus.md", {"type": "actor", "title": "Lazarus Group"})
        _write(wiki / "entities" / "cleaver.md",
               {"type": "actor", "title": "Cleaver", "aliases": ["Alibaba", "Operation Cleaver"]})

        S = wiki / "sources"
        _write(S / "n1.md", {"type": "source", "source_kind": "news", "published": d(2),
                             "title": "Sandworm Team disrupts a power grid"})
        _write(S / "n2.md", {"type": "source", "source_kind": "news", "published": d(1),
                             "title": "Alibaba patches its XQUIC library"}, body="a cleaver-sharp new exploit")
        _write(S / "n3.md", {"type": "source", "source_kind": "news", "published": d(3),
                             "title": "Operation Cleaver campaign resurfaces"})
        _write(S / "n4.md", {"type": "source", "source_kind": "news", "published": d(50),
                             "title": "Lazarus Group linked to a crypto heist"})
        # a non-news source naming an actor must be ignored (this lane is news-only)
        _write(S / "r1.md", {"type": "source", "source_kind": "report", "published": d(0),
                             "title": "Sandworm Team annual review"})
        # a TOMBSTONED same-story duplicate must NOT be counted (else dedup can't fix the count):
        # this would otherwise be Sandworm's newest news (d(1) > d(2)) and bump recent_news to 2
        _write(S / "n5.md", {"type": "source", "source_kind": "news", "published": d(1),
                             "status": "tombstoned", "superseded_by": "sources/n1",
                             "title": "Sandworm Team disrupts a power grid (duplicate)"})

        assert aa.main(["--vault", str(vault)]) == 0
        ent = wiki / "entities"
        sandworm, lazarus, cleaver = _fm(ent / "sandworm.md"), _fm(ent / "lazarus.md"), _fm(ent / "cleaver.md")

        # 1) newest NEWS date + in-window count; the report source (d0) is NOT counted
        assert str(sandworm["news_last_seen"]) == d(2), sandworm
        assert sandworm["recent_news"] == 1, sandworm
        # 2) Cleaver matched ONLY via "Operation Cleaver" (d3) — never via the Alibaba/"cleaver" article (d1)
        assert str(cleaver["news_last_seen"]) == d(3), cleaver
        assert cleaver["recent_news"] == 1, cleaver
        # 3) Lazarus: last seen 50d ago -> stamped, but recent_news 0 (outside the 30d window)
        assert str(lazarus["news_last_seen"]) == d(50), lazarus
        assert lazarus["recent_news"] == 0, lazarus
        # 4) the report lane's field is not written here
        assert "recent_reports" not in sandworm, sandworm
        # 5) provenance: the matched article rides the count as a PLAIN page ref (the reader's
        #    fact panel linkifies plain paths; [[brackets]] defeat it). The lane stamps [] when
        #    the window is empty and write_page strips empty values, so the key CLEARS (absent)
        #    instead of persisting stale refs.
        assert sandworm["recent_news_refs"] == ["sources/n1"], sandworm
        assert cleaver["recent_news_refs"] == ["sources/n3"], cleaver
        assert lazarus.get("recent_news_refs") in (None, []), lazarus


if __name__ == "__main__":
    test_news_recency_matches_by_name_and_respects_filters()
    print("ok")
