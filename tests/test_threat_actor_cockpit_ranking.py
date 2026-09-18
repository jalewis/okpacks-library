"""Product-level ranking invariants for the threat-actor cockpit."""

from __future__ import annotations

from pathlib import Path

import yaml


SCHEMA = Path(__file__).resolve().parents[1] / "packs" / "okpack-threat-actors" / "schema.yaml"


def test_actor_news_panels_never_rank_on_unvalidated_mention_volume() -> None:
    schema = yaml.safe_load(SCHEMA.read_text(encoding="utf-8"))
    boxes = (
        box
        for tab in schema["cockpit"]["tab_defs"].values()
        for box in tab.get("boxes", [])
        if isinstance(box, dict)
    )
    news_panels = [
        box
        for box in boxes
        if box.get("dataset") == {"dir": "entities", "type": "actor", "has": ["recent_news"]}
    ]

    assert news_panels, "the actor-news cockpit ranking disappeared instead of being governed"
    for panel in news_panels:
        assert panel["sort"] == {
            "field": "news_last_seen",
            "desc": True,
            "require": True,
            "date": True,
            "then": "title",
        }, panel
