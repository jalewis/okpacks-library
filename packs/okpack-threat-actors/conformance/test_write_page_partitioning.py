#!/usr/bin/env python3
"""Conformance for _okf_write.write_page partition routing (okengine#54).

The shared page writer must file a page at the canonical shard the engine reshelve drain would
choose — merging against any existing copy WHEREVER it sits — so a partition-unaware rel_path can
never create a duplicate the drain then re-shards (the KEV/NVD/entity double-count). This drives
the REAL _okf_write against the REAL engine okf_migrate, co-located as deploy-cron-scripts stages
them. Skips when the engine lib isn't locatable (pack-only CI); the fallback path (no engine ->
legacy flat write) is asserted inline since it needs no engine.

Runs standalone (conformance-all.sh) and is pytest-discoverable.
"""
import importlib.util
import os
import shutil
import sys
import tempfile
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent.parent / "crons" / "scripts"
LIB_ROOT = Path(__file__).resolve().parents[3]


def _engine_okf_migrate() -> Path | None:
    """okf_migrate.py from a sibling engine checkout (OKENGINE_DIR, else ../okengine)."""
    for cand in (os.environ.get("OKENGINE_DIR"), str(LIB_ROOT.parent / "okengine")):
        if cand and (Path(cand) / "scripts" / "cron" / "okf_migrate.py").is_file():
            return Path(cand) / "scripts" / "cron" / "okf_migrate.py"
    return None


def _load_write(dirpath: Path):
    """Import _okf_write from `dirpath` (fresh), so its `import okf_migrate` resolves to whatever
    is co-located there — engine present or not."""
    sys.modules.pop("_okf_write", None)
    sys.modules.pop("okf_migrate", None)
    sys.path.insert(0, str(dirpath))
    spec = importlib.util.spec_from_file_location("_okf_write", dirpath / "_okf_write.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def test_write_page_routes_to_canonical_shard_and_collapses_stale():
    engine = _engine_okf_migrate()
    if engine is None:
        print("  skip test_write_page_routes... (engine okf_migrate not found; set OKENGINE_DIR)")
        return
    with tempfile.TemporaryDirectory() as t:
        d = Path(t)
        (d / "scripts").mkdir()
        shutil.copy(engine, d / "scripts" / "okf_migrate.py")
        shutil.copy(SCRIPTS / "_okf_write.py", d / "scripts" / "_okf_write.py")
        vault = d / "vault"
        (vault / "wiki" / "entities").mkdir(parents=True)
        (vault / "schema.yaml").write_text(
            "partitioning:\n  namespaces:\n    entities: {strategy: by-letter}\n"
            "types: {actor: {}}\n")
        # pre-existing STALE FLAT copy carrying a curated field owned by another lane
        (vault / "wiki" / "entities" / "havij.md").write_text(
            "---\ntype: actor\nid: S0224\nattribution_confidence: high\n---\nold\n")

        w = _load_write(d / "scripts")
        content = w.content_root(vault)                  # == vault/wiki
        # importer passes a FLAT rel_path; write_page must route to the by-letter shard, twice = idempotent
        for _ in range(2):
            act = w.write_page(content, "entities/havij.md",
                               {"type": "actor", "id": "S0224", "aliases": ["havij"]}, "fresh")
        pages = sorted(p.relative_to(content).as_posix() for p in (content / "entities").rglob("*.md"))
        assert pages == ["entities/h/havij.md"], pages          # routed + stale flat collapsed
        assert act == "updated"
        fm, _ = w._split_frontmatter((content / "entities" / "h" / "havij.md").read_text())
        assert fm.get("attribution_confidence") == "high"       # curated field merged from the stale copy
        assert fm.get("aliases") == ["havij"]


def test_write_page_falls_back_to_flat_without_engine():
    """No engine okf_migrate on the path -> write_page keeps rel_path verbatim (legacy behavior),
    never crashing the importer. Loaded from a dir with NO okf_migrate.py."""
    with tempfile.TemporaryDirectory() as t:
        d = Path(t)
        (d / "scripts").mkdir()
        shutil.copy(SCRIPTS / "_okf_write.py", d / "scripts" / "_okf_write.py")   # engine absent
        vault = d / "vault"
        (vault / "wiki").mkdir(parents=True)
        (vault / "schema.yaml").write_text(
            "partitioning:\n  namespaces:\n    entities: {strategy: by-letter}\ntypes: {actor: {}}\n")
        w = _load_write(d / "scripts")
        assert w.okf_migrate is None                            # guard tripped, no crash
        content = w.content_root(vault)
        w.write_page(content, "entities/havij.md", {"type": "actor"}, "b")
        assert (content / "entities" / "havij.md").is_file()    # verbatim flat, as before


def _run() -> int:
    fails = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"  ok   {name}")
            except AssertionError as e:
                fails += 1
                print(f"  FAIL {name}: {e}")
    return fails


if __name__ == "__main__":
    print("== okpack-threat-actors write_page partition conformance ==")
    n = _run()
    print("all write_page tests pass" if not n else f"{n} test(s) failed")
    sys.exit(1 if n else 0)
