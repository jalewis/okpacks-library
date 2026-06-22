#!/usr/bin/env python3
"""Validate the okpack-example domain pack — parse + cross-consistency checks.

Runs with no engine checkout and no Docker: it only reads this pack. Catches the class of
bug that ships silently in a config/data pack — a YAML/JSON/OPML parse error, or drift between
what the crons write and what schema.yaml declares (e.g. a cron writing to a namespace that has
no partitioning/tier rule).

The common checks (parse, OPML/feeds, cron-jitter, namespace/type consistency, schema cross-drift,
pack.yaml, enum well-formedness) live in the shared validator lib, vendored beside this file as
`_pack_validate_lib.py` (canonical: scripts/pack_validate_lib.py; okpacks-library#17). This file
is the pack's thin entrypoint — the place to add pack-SPECIFIC config and checks.

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

# ── pack-specific config / checks ────────────────────────────────────────────
# Require a human-only write gate on these namespaces (regression guard). Default none;
# e.g. set ["findings"] if your pack ships an analyst-authored namespace:
lib.REQUIRED_HUMAN_ONLY = []

# Add a pack-specific check by defining `def check_x(schema): ... lib.fail(...)` and passing
# it to lib.run([check_x]). okpack-sec is the worked example (page-level enum/refs/defang checks).
EXTRA_CHECKS = []


if __name__ == "__main__":
    raise SystemExit(lib.run(EXTRA_CHECKS))
