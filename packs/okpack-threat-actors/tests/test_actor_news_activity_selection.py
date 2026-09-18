"""actor_news_activity — which sources the lane reads, and what it does when it reads none.

This lane selected `source_kind == "news"`: one exact token out of a corpus vocabulary of
thirteen. Two consequences, both live.

It never saw most of the firehose. On the corpus this was measured against, `news` was 657
sources while `report`, `threat-report`, `commentary`, `advisory`, `incident-report`,
`vendor-blog` and `cyber-news` together were another 1,660 — all of them reporting, none of
them read.

And an exact include-list fails SILENTLY when the vocabulary moves. On 2026-07-28 every
source page on that vault began being written `source_kind: report`, the selection dropped
to zero, and the lane printed "scanned 0 news sources, no actor names matched" and exited 0
every day for three weeks. The actor board it feeds froze on 2026-07-25 while the whole
pipeline reported success.

So: EXCLUDE rather than include (an unrecognised kind is counted, never dropped unseen), and
an empty selection drawn from a non-empty corpus is `undetectable`, not `no activity`.
"""
import importlib.util
import json
import sys
from pathlib import Path

import pytest

PACK = Path(__file__).resolve().parents[1]
SCRIPT = PACK / "crons" / "scripts" / "actor_news_activity.py"

pytestmark = pytest.mark.skipif(not SCRIPT.is_file(), reason="lane absent")


def _mod():
    spec = importlib.util.spec_from_file_location("actor_news_activity", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def _vault(tmp_path: Path, sources, actor="Scattered Spider"):
    wiki = tmp_path / "wiki"
    (wiki / "entities" / "s").mkdir(parents=True)
    (wiki / "entities" / "s" / "scattered-spider.md").write_text(
        f"---\ntype: actor\ntitle: {actor}\n---\n\nbody\n", encoding="utf-8")
    for i, (kind, day) in enumerate(sources):
        d = wiki / "sources" / "2026" / "08"
        d.mkdir(parents=True, exist_ok=True)
        kind_line = f"source_kind: {kind}\n" if kind is not None else ""
        (d / f"item-{i}.md").write_text(
            f"---\ntype: source\n{kind_line}title: {actor} strikes again\n"
            f"published: {day}\n---\n\n{actor} was reported today.\n", encoding="utf-8")
    return tmp_path


def _run(mod, vault, monkeypatch, capsys, argv=("--dry-run",)):
    monkeypatch.setattr(sys, "argv", ["actor_news_activity.py", "--vault", str(vault), *argv])
    rc = mod.main(["--vault", str(vault), *argv])
    return rc, capsys.readouterr()


def _today(mod):
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).date().isoformat()


def test_reporting_that_is_not_typed_news_is_still_read(tmp_path, monkeypatch, capsys):
    """`report`/`threat-report`/`commentary` are reporting. The old filter read none of them."""
    mod = _mod()
    day = _today(mod)
    vault = _vault(tmp_path, [("report", day), ("threat-report", day), ("commentary", day)])
    rc, out = _run(mod, vault, monkeypatch, capsys)
    assert rc == 0
    assert "3 news sources scanned" in out.out, out.out


def test_an_unfamiliar_kind_is_counted_rather_than_dropped_unseen(tmp_path, monkeypatch, capsys):
    """The polarity IS the fix: a vocabulary this list has never seen must not vanish."""
    mod = _mod()
    day = _today(mod)
    vault = _vault(tmp_path, [("brand-new-kind-nobody-declared", day)])
    rc, out = _run(mod, vault, monkeypatch, capsys)
    assert rc == 0
    assert "1 news sources scanned" in out.out


def test_a_source_with_no_kind_at_all_is_still_read(tmp_path, monkeypatch, capsys):
    mod = _mod()
    vault = _vault(tmp_path, [(None, _today(mod))])
    rc, out = _run(mod, vault, monkeypatch, capsys)
    assert rc == 0 and "1 news sources scanned" in out.out


def test_bulk_reference_data_is_excluded(tmp_path, monkeypatch, capsys):
    """Catalogue rows are not reporting; thousands of them would drown the count."""
    mod = _mod()
    assert "reference-data" in mod.EXCLUDED_KINDS
    day = _today(mod)
    vault = _vault(tmp_path, [("reference-data", day), ("news", day)])
    rc, out = _run(mod, vault, monkeypatch, capsys)
    assert rc == 0 and "1 news sources scanned" in out.out


def test_an_empty_selection_from_a_NON_empty_corpus_is_undetectable_not_quiet_success(
        tmp_path, monkeypatch, capsys):
    """The three-week failure, pinned.

    Sources keep arriving, none survive the kind filter, and the lane must NOT report a
    calm zero. It has to say the run proves nothing and name the vocabulary it actually saw.
    """
    mod = _mod()
    monkeypatch.setenv("NEWS_EXCLUDED_KINDS", "report")
    mod = _mod()  # re-import so the env-derived constant is rebuilt
    day = _today(mod)
    vault = _vault(tmp_path, [("report", day), ("report", day)])
    rc, out = _run(mod, vault, monkeypatch, capsys)
    assert rc == 1, "a run that proves nothing must not exit 0"
    assert "UNDETECTABLE" in out.err
    assert "2 dated source(s)" in out.err
    payload = json.loads(out.out.strip().splitlines()[-1])
    assert payload["status"] == "undetectable"
    assert payload["dated_sources"] == 2 and payload["selected"] == 0
    assert payload["kinds_seen"]["report"] == 2


def test_a_genuinely_empty_corpus_is_not_reported_as_undetectable(tmp_path, monkeypatch, capsys):
    """No sources in range is a real answer; only a non-empty corpus yielding zero is not."""
    mod = _mod()
    vault = _vault(tmp_path, [])
    rc, out = _run(mod, vault, monkeypatch, capsys)
    assert rc == 0
    assert "UNDETECTABLE" not in out.err


def test_the_zero_match_message_shows_both_numbers(tmp_path, monkeypatch, capsys):
    """'scanned N' alone hid this. Selected-vs-available is the number that reveals it."""
    mod = _mod()
    day = _today(mod)
    vault = _vault(tmp_path, [("news", day)], actor="Scattered Spider")
    # rewrite the source so no actor term appears in it
    for page in (vault / "wiki" / "sources").rglob("*.md"):
        page.write_text(f"---\ntype: source\nsource_kind: news\ntitle: unrelated\n"
                        f"published: {day}\n---\n\nnothing relevant here\n", encoding="utf-8")
    rc, out = _run(mod, vault, monkeypatch, capsys)
    assert rc == 0
    assert "of 1 dated source(s)" in out.out


def test_a_tombstoned_actor_is_not_a_roster_member(tmp_path, monkeypatch, capsys):
    """Retiring a page must not leave it consuming the firehose.

    The lane already skips tombstoned SOURCES. Skipping tombstoned ACTORS matters more: a
    retired page left in the roster still matches articles, still gets stamped with fresh
    activity, and a generic retired name can shadow a real one by making a shared term
    ambiguous — so the retirement would quietly degrade the signal it was meant to clean up.
    """
    mod = _mod()
    day = _today(mod)
    vault = _vault(tmp_path, [("news", day)])
    wiki = vault / "wiki"
    # a DISTINCTIVE name, so the term filters cannot be what excludes it — the first draft of
    # this test used "Attacker", which _terms_for already drops as a generic single token, so it
    # passed against the unfixed lane and proved nothing
    (wiki / "entities" / "v").mkdir(parents=True, exist_ok=True)
    retired = wiki / "entities" / "v" / "velvet-tempest.md"
    retired.write_text(
        "---\ntype: actor\ntitle: Velvet Tempest\nstatus: tombstoned\n"
        "tombstone_reason: duplicate\n---\n\nbody\n", encoding="utf-8")
    for page in (wiki / "sources").rglob("*.md"):
        page.write_text(f"---\ntype: source\nsource_kind: news\ntitle: Velvet Tempest strikes\n"
                        f"published: {day}\n---\n\nVelvet Tempest was reported today.\n",
                        encoding="utf-8")
    # argv=() — NOT the default --dry-run. The first version of this test inherited the dry
    # run and therefore asserted that nothing was written by a lane that writes nothing.
    rc, out = _run(mod, vault, monkeypatch, capsys, argv=())
    assert rc == 0
    assert _fm_of(retired).get("recent_news") is None, \
        "a tombstoned actor must not be stamped with fresh activity"
    assert "status: tombstoned" in retired.read_text(encoding="utf-8"), "still retired"


def _fm_of(path):
    import yaml
    text = path.read_text(encoding="utf-8")
    return yaml.safe_load(text.split("---", 2)[1]) or {}
