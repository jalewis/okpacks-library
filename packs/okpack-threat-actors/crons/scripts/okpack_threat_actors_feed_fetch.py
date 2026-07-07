#!/usr/bin/env python3
"""okpack-threat-actors feed pull — fetch the threat-actors OPML into raw/threat-actors/ for the ingest lane.

A thin wrapper over the engine's generic feed_fetch.py (co-deployed to
/opt/data/scripts/). Pure script / no_agent: it writes new feed items as raw
markdown; the raw-backfill ingest agent compiles them into wiki/ on its next pass.

Env: WIKI_PATH (default /opt/vault), OKPACK_THREAT_ACTORS_FEEDS (default the deployed
/opt/data/config/feeds.opml).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import feed_fetch  # engine-provided, co-located after deploy-cron-scripts  # noqa: E402

WIKI = os.environ.get("WIKI_PATH", "/opt/vault")
raise SystemExit(feed_fetch.main([
    "--opml", os.environ.get("OKPACK_THREAT_ACTORS_FEEDS", "/opt/data/config/feeds.opml"),
    "--out-dir", f"{WIKI}/raw/threat-actors",
    "--state", "/opt/data/scripts/okpack-threat-actors-feed-state.json",
    "--source-tag", "threat-actors",
]))
