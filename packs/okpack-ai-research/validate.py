#!/usr/bin/env python3
"""Validate the okpack-ai-research domain pack — parse + cross-consistency checks.

Runs with no engine checkout and no Docker: it only reads this pack. Catches the class of bug
that ships silently in a config/data pack — a YAML/JSON/OPML parse error, or drift between what
the crons write and what schema.yaml declares (e.g. a cron writing to a namespace with no
partitioning/tier rule, or a field_enums entry naming an undefined enum).

The common checks (parse, OPML/feeds, cron-jitter, namespace/type consistency, schema cross-drift,
pack.yaml, enum well-formedness) live in the shared validator lib, vendored beside this file as
`_pack_validate_lib.py` (canonical: scripts/pack_validate_lib.py; okpacks-library#17). This pack
adds no pack-specific checks (page VALUES are checked by the conformance suite).

Usage:
    python3 validate.py            # parse + consistency checks (offline, fast)
    python3 validate.py --fix      # rewrite the feeds.opml.example count comment if it drifted
    python3 validate.py --probe    # HTTP-probe the suggested feeds in feeds.opml.example (network)

Exit 0 = all checks pass. Exit 1 = at least one FAIL (warnings never fail the run).
Dependency: PyYAML (schema.yaml). Everything else is stdlib.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))  # find the vendored lib next to us
import _pack_validate_lib as lib  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(lib.run())
