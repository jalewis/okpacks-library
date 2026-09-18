#!/usr/bin/env python3
"""landscape_shifts.py — dated landscape-shift digest for the cockpit's shifts stream.

The cockpit's "Landscape shifts" stream is DATE-keyed (it lists dated documents, like the
briefings stream), but `theme_trends.py` maintains IN-PLACE theme pages — so the stream was
empty by construction. This lane closes it: each run diffs the current theme set against the
snapshot embedded in the PREVIOUS shift page and writes a dated `trends/shift-YYYY-MM-DD.md`
(type: trend, so the stream's type filter picks it up).

Reported shifts: new themes · direction changes · trend_status changes · coverage-count moves.
First run (no prior shift page) writes a baseline. State lives IN the shift page frontmatter
(`theme_snapshot:`) — self-contained, inspectable, no side-channel state file.

Deterministic no_agent script; wakeAgent=false.

Env:
  WIKI_PATH   vault root (default /opt/vault)
"""
from __future__ import annotations

import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _okf_write import content_root, write_page  # noqa: E402

_FM = re.compile(r"\A---\s*\n(.*?\n)---\s*(?:\n|\Z)", re.S)


def _pages(tdir: Path):
    for p in sorted(tdir.glob("theme-*.md")):
        try:
            txt = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue  # page moved/deleted by a concurrent lane mid-scan
        m = _FM.match(txt)
        if not m:
            continue
        try:
            fm = yaml.safe_load(m.group(1)) or {}
        except yaml.YAMLError:
            continue
        if str(fm.get("type")) == "trend":
            yield p.stem, fm


def _snapshot(tdir: Path) -> dict:
    snap = {}
    for stem, fm in _pages(tdir):
        cby = fm.get("count_by_year") or {}
        total = sum(v for v in cby.values() if isinstance(v, int))
        snap[stem] = {"direction": str(fm.get("direction") or "?"),
                      "status": str(fm.get("trend_status") or "?"),
                      "total": total,
                      "title": str(fm.get("title") or stem)}
    return snap


def _prev_snapshot(tdir: Path) -> tuple[dict, str | None]:
    shifts = sorted(tdir.glob("shift-*.md"), reverse=True)
    for p in shifts:
        try:
            txt = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue  # page moved/deleted by a concurrent lane mid-scan
        m = _FM.match(txt)
        if not m:
            continue
        try:
            fm = yaml.safe_load(m.group(1)) or {}
        except yaml.YAMLError:
            continue
        snap = fm.get("theme_snapshot")
        if isinstance(snap, dict):
            return snap, p.stem.replace("shift-", "")
    return {}, None


def main() -> int:
    vault = Path(__import__("os").environ.get("WIKI_PATH", "/opt/vault"))
    wiki = content_root(vault)
    tdir = wiki / "trends"
    if not tdir.is_dir():
        print("landscape-shifts: no trends/ dir — nothing to diff")
        print(json.dumps({"wakeAgent": False}))
        return 0

    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    cur = _snapshot(tdir)
    prev, prev_date = _prev_snapshot(tdir)

    lines: list[str] = []
    if not prev:
        lines.append(f"Baseline established over **{len(cur)}** tracked themes; future runs "
                     "report movement against this snapshot.")
        lines.append("")
        lines += [f"- [[trends/{s}]] — {v['direction']}, {v['total']} reports"
                  for s, v in sorted(cur.items())]
    else:
        new = sorted(set(cur) - set(prev))
        gone = sorted(set(prev) - set(cur))
        dir_moves, status_moves, count_moves = [], [], []
        for s in sorted(set(cur) & set(prev)):
            c, p = cur[s], prev[s]
            if c["direction"] != p["direction"]:
                dir_moves.append(f"- [[trends/{s}]] direction **{p['direction']} → {c['direction']}**")
            if c["status"] != p["status"]:
                status_moves.append(f"- [[trends/{s}]] status **{p['status']} → {c['status']}**")
            if c["total"] != p["total"]:
                count_moves.append(f"- [[trends/{s}]] coverage {p['total']} → **{c['total']}** reports")
        if new:
            lines += ["## New themes", *[f"- [[trends/{s}]] ({cur[s]['direction']})" for s in new], ""]
        if dir_moves:
            lines += ["## Direction changes", *dir_moves, ""]
        if status_moves:
            lines += ["## Status changes", *status_moves, ""]
        if count_moves:
            lines += ["## Coverage moves", *count_moves, ""]
        if gone:
            lines += ["## Dropped themes", *[f"- `{s}`" for s in gone], ""]
        if not (new or gone or dir_moves or status_moves or count_moves):
            lines.append(f"No landscape movement since {prev_date} — "
                         f"{len(cur)} themes steady.")

    fm = {"type": "trend", "title": f"Landscape shifts — {today}",
          "published": today, "generated_by": "landscape_shifts.py",
          "theme_snapshot": cur}
    body = "\n".join([f"# Landscape shifts — {today}", "",
                      *lines, "",
                      "> Computed no_agent by diffing `trends/theme-*` metrics against the "
                      "previous shift snapshot (embedded in this page's frontmatter)."])
    write_page(wiki, f"trends/shift-{today}.md", fm, body)
    print(f"landscape-shifts: {len(cur)} themes vs {prev_date or 'baseline'} -> trends/shift-{today}.md")
    print(json.dumps({"wakeAgent": False}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
