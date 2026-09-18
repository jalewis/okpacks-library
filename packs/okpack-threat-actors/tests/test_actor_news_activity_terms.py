"""actor_news_activity._terms_for — which names are allowed to match the news firehose.

`recent_news` is the count of news items whose text contains one of these terms. It is not just a
board column: `actor-assessment-priority` records inherit it, so the terms chosen here decide what
the analysis pipeline works on FIRST.

On a live corpus that produced an inversion. `Attacker` scored 18 matches against 1 cited source and
`Threat Actor` scored 58 against 1, while `Scattered Spider` -- a heavily reported real actor --
scored 9 against 35. The generic names ranked first precisely because they mean least.

Half of these cases exist to stop the fix over-reaching. Real codenames are built from common words
too, so a compositional rule ("drop it if every word is generic") is WRONG: it deletes `Comment
Crew`, which is APT1 and is the example the module docstring cites. That rule was written, measured
against these names, and replaced with a curated phrase list because of this test.
"""
import importlib.util
import sys
from pathlib import Path

import pytest

PACK = Path(__file__).resolve().parents[1]
SCRIPT = PACK / "crons" / "scripts" / "actor_news_activity.py"

pytestmark = pytest.mark.skipif(not SCRIPT.is_file(), reason="lane absent")


def _mod():
    sys.path.insert(0, str(SCRIPT.parent))
    try:
        spec = importlib.util.spec_from_file_location("actor_news_activity", SCRIPT)
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        return m
    finally:
        sys.path.pop(0)


# Every one of these was a live actor page on a real corpus.
GENERIC = ["Attacker", "Threat Actor", "Threat Actors", "Malware Campaign", "Ransomware Gang",
           "AI Agents", "Autonomous LLM Agent", "Intruder", "Unknown", "Cybercriminal Group"]

# Real actors, including several whose words are individually generic.
REAL = ["Comment Crew", "Scattered Spider", "Volt Typhoon", "Fancy Bear", "BRONZE BUTLER",
        "APT29", "Qilin", "Storm-1567", "Sandworm Team"]


@pytest.mark.parametrize("title", GENERIC)
def test_a_generic_name_is_never_a_match_term(title):
    assert _mod()._terms_for({"title": title}) == set(), (
        f"{title!r} matches ordinary prose, so its news count measures the firehose, not the actor "
        "-- and that count ranks the assessment queue")


@pytest.mark.parametrize("title", REAL)
def test_a_real_actor_still_matches(title):
    assert _mod()._terms_for({"title": title}), (
        f"{title!r} must keep matching; a precision fix that silences real actors has traded one "
        "broken board for another")


def test_a_generic_alias_is_dropped_without_dropping_the_page(title="Storm-1567"):
    """An actor legitimately carrying a generic alias keeps its distinctive terms and loses only the
    alias — the page is not silenced for one bad alias."""
    terms = _mod()._terms_for({"title": title, "aliases": ["Ransomware Gang", "Akira"]})
    assert "ransomware gang" not in terms
    assert "storm-1567" in terms and "akira" in terms


def test_the_phrase_list_is_lowercase_and_matched_whole():
    """Matching is on the lowercased whole term. An uppercase entry would silently never fire, and a
    substring rule would delete real actors whose names contain a generic word."""
    m = _mod()
    assert all(p == p.lower() and p.strip() == p for p in m._GENERIC_PHRASE)
    assert m._terms_for({"title": "Threat Actor Group Sandworm"}), (
        "a phrase entry must not match as a substring of a longer, distinctive name")
