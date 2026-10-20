"""A pack lane that creates wiki pages must not write them directly (okengine#886).

The ai-research HF importer hand-built `sources/**` seats and wrote pages with `write_text`, with
no `id` and a pseudo backlink. On a live vault that minted ~600 pages the engine's write path could
neither update nor find by identity, so the same paper compiled later from another feed became a
duplicate. Producers now hand structured RAW captures to the engine (raw-compile compiles them
through the write path) or write through the write path themselves.

Deterministic lanes may still operate below the write path when they create no pages — in-place
field normalizers, enrichers of existing pages, a lane's own dashboard. Those are listed in ALLOWED
with the verified reason (they bypass the write path's update guards, a separate concern). The
list may only SHRINK: a new direct page writer fails here and must either route through the
engine or be reviewed onto the list.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

PACKS = Path(__file__).resolve().parents[1] / "packs"
LANES = sorted(PACKS.glob("*/crons/scripts/*.py"))

# lane (relative to packs/) -> why its direct wiki writes are acceptable. Shrink-only.
ALLOWED = {
    # In-place updaters: rewrite fields on EXISTING pages, create none.
    "okpack-incidents/crons/scripts/incident_sector_normalize.py":
        "rewrites one field on existing incident pages in place; creates no pages",
    "okpack-threat-actors/crons/scripts/origin_country_normalize.py":
        "rewrites one field on existing actor pages in place; creates no pages",
    "okpack-threat-actors/crons/scripts/source_url_reconcile.py":
        "repairs `url` on existing source pages from their raw captures; creates no pages",
    "okpack-threat-actors/crons/scripts/actor_identity_audit.py":
        "re-evaluates existing actor pages in place; creates no pages",
    "okpack-vuln/crons/scripts/severity_normalize.py":
        "rewrites `severity` on existing pages in place; creates no pages",
    "okpack-vuln/crons/scripts/cve_mentions.py":
        "stamps mention counts on existing CVE pages (skips absent ones) + its own dashboard",
    "okpack-vuln/crons/scripts/epss_import.py":
        "enriches existing CVE pages in place + its own epss-watch dashboard",
    "okpack-vuln/crons/scripts/osv_import.py":
        "enriches existing CVE pages in place (its docstring: never creates or merges pages)",
    "okpack-vuln/crons/scripts/vulnerability_action_queue.py":
        "writes only its own vulnerability-action-queue dashboard page",
    # Not a page writer: reads pages, writes an export bundle outside wiki/.
    "okpack-threat-actors/crons/scripts/actor_evidence_export.py":
        "writes an export bundle outside wiki/; only reads pages",
    # Page CREATORS outside the shared helper — tracked for migration, not blessed.
    "okpack-vuln/crons/scripts/kev_import.py":
        "creates CVE pages (with id) outside _okf_write.write_page — okpacks-library#104",
}
# The shared helper IS the sanctioned direct writer (write_key + find_page + importer_guard).
HELPERS = {"_okf_write.py"}


def _direct_page_writers(path: Path) -> list[str]:
    """Write calls in a lane that also names the `wiki` tree, anywhere in the module.

    Module-wide, not per function: the old HF importer built the `wiki/sources/...` seat in one
    function and called `write_text` in another, and a per-function check passed it."""
    tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"), str(path))
    if not any(isinstance(n, ast.Constant) and n.value == "wiki" for n in ast.walk(tree)):
        return []
    return [f"line {n.lineno}" for n in ast.walk(tree)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
            and n.func.attr in ("write_text", "write_bytes")]


@pytest.mark.parametrize("lane", LANES, ids=lambda p: f"{p.parents[2].name}/{p.name}")
def test_no_new_direct_wiki_page_writer(lane):
    rel = lane.relative_to(PACKS).as_posix()
    hits = _direct_page_writers(lane)
    if rel in ALLOWED or lane.name in HELPERS:
        return
    assert not hits, (
        f"{rel} writes wiki pages directly ({', '.join(hits)}). Hand the engine a raw capture "
        f"(raw-compile compiles it through the write path) or write through the write path; a "
        f"reviewed exception goes in ALLOWED with its reason, or write through the pack's "
        f"_okf_write.write_page helper (okengine#886).")


def test_the_allow_list_only_names_lanes_that_still_need_it():
    """Shrink-only: an entry whose lane no longer writes directly (or no longer exists) must be
    removed, so the list tracks real exceptions rather than history."""
    stale = [rel for rel in ALLOWED
             if not (PACKS / rel).is_file() or not _direct_page_writers(PACKS / rel)]
    assert not stale, f"remove from ALLOWED (no longer a direct writer): {stale}"


def test_the_scan_detects_a_direct_writer(tmp_path):
    """A scan that matched nothing would pass vacuously; prove the matcher fires."""
    probe = tmp_path / "probe.py"
    probe.write_text("def seat(v):\n    return v / 'wiki' / 'sources' / 'x.md'\n"
                     "def write(p):\n    p.write_text('---')\n")
    assert _direct_page_writers(probe) == ["line 4"], "seat and write in different functions"
    probe.write_text("def f(v):\n    (v / 'raw' / 'hf' / 'x.md').write_text('---')\n")
    assert _direct_page_writers(probe) == [], "a raw capture writer is not a page writer"
