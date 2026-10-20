"""A pack lane must seat pages with write_key, never the drain's base key (okengine#818).

`canonical_key` returns the BASE bucket — one level above where `reshard_oversized` keeps a bucket
it has split. A writer using it re-mints strays there every run for the nightly sweep to push back
down, and any consumer that stored a page path holds a stale one in between. Measured on a live
vault: 448 pages loose in 23 already-split buckets between two sweeps, and 17 of 25 entity links
on a pack's own dashboard resolving to nothing.

`write_key` is the writer's contract: an existing page is updated in place (so a reshard that has
not run yet cannot fork it) and a new page gets the `reshard_by` segment immediately (#243).
"""
import ast
from pathlib import Path

import pytest

PACKS = Path(__file__).resolve().parents[1] / "packs"
LANES = sorted(PACKS.glob("*/crons/scripts/*.py"))


def _canonical_key_calls(path: Path) -> list[int]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"), str(path))
    except SyntaxError:  # pragma: no cover - the compile gate owns syntax, not this test
        return []
    return [node.lineno for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and (node.func.attr if isinstance(node.func, ast.Attribute)
                 else node.func.id if isinstance(node.func, ast.Name) else None) == "canonical_key"]


@pytest.mark.parametrize("lane", LANES, ids=lambda p: f"{p.parents[2].name}/{p.name}")
def test_lane_does_not_seat_pages_by_the_drains_base_key(lane):
    hits = _canonical_key_calls(lane)
    assert not hits, (
        f"{lane.relative_to(PACKS)} calls canonical_key() at line(s) {hits} — that is the drain's "
        f"base bucket. Use okf_migrate.write_key() so a new page lands on the reshard segment and "
        f"an existing one is updated in place (okengine#818, #243)."
    )


def test_the_scan_actually_sees_a_call():
    """A parametrized scan that matched nothing would pass vacuously; prove the matcher works."""
    assert LANES, "no pack lane scripts found — the scan would pass on an empty set"
    probe = Path(__file__).parent / "_probe_canonical_key.py"
    probe.write_text("import okf_migrate\nrel = okf_migrate.canonical_key(r, n, s, f)\n")
    try:
        assert _canonical_key_calls(probe) == [2]
    finally:
        probe.unlink()
