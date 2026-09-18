#!/usr/bin/env python3
"""Structured run markers for the no_agent importers (okpacks-library#25).

Deployed scheduled importers only leave transient logs; this writes a durable, machine-readable
status file per importer so an operator (or a future engine/reader surface) can see health at a
glance — when it last ran, last SUCCEEDED, what it wrote, and why it failed.

Marker: `<vault>/wiki/operational/importer-status/<key>.json` (the operational namespace is excluded
from OKF processing, so markers never pollute the knowledge tree). Each write records the latest run
and carries `last_success_at` forward, so a failing importer still shows its last good run:

    {
      "key": "kev", "status": "success|degraded|failed",
      "started_at": "...Z", "ended_at": "...Z", "duration_s": 12.3,
      "counts": { ... },          # the importer's own summary counts (success only)
      "error": null,              # or the error string (degraded/failed)
      "last_success_at": "...Z"   # carried across runs; null until the first success
    }

`record_run` is best-effort: a marker-write failure never crashes the importer (observability must
not break ingestion). VENDORED into each pack's crons/scripts/ — keep the copies identical
(scripts/validate-library.py checks this).
"""
from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

STATUS_DIR = ("wiki", "operational", "importer-status")
_VALID = {"success", "degraded", "failed"}


def record_run(vault, key: str, started: datetime, status: str,
               counts: dict | None = None, error: str | None = None,
               dry_run: bool = False) -> dict | None:
    """Write/update the run marker for importer `key`. No-op on dry_run. Best-effort (returns the
    record, or None if skipped/unwritable)."""
    if dry_run:
        return None
    if status not in _VALID:
        status = "failed"
    ended = datetime.now(timezone.utc)
    rec = {
        "key": key,
        "status": status,
        "started_at": started.isoformat(),
        "ended_at": ended.isoformat(),
        "duration_s": round((ended - started).total_seconds(), 1),
        "counts": counts or {},
        "error": (str(error)[:500] if error else None),
        "last_success_at": ended.isoformat() if status == "success" else None,
    }
    try:
        d = Path(vault).joinpath(*STATUS_DIR)
        d.mkdir(parents=True, exist_ok=True)
        path = d / f"{key}.json"
        if status != "success" and path.exists():          # carry the prior success forward
            try:
                rec["last_success_at"] = json.loads(path.read_text()).get("last_success_at")
            except (OSError, ValueError):
                pass
        fd, tmp = tempfile.mkstemp(dir=str(d), prefix=f".{key}.", suffix=".tmp")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(rec, f, indent=2, sort_keys=False)
        os.replace(tmp, path)
    except OSError:
        return None   # observability is best-effort; never break the import
    return rec
