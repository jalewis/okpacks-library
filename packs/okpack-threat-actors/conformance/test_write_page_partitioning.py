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


def _engine_authority_lib() -> Path | None:
    for cand in (os.environ.get("OKENGINE_DIR"), str(LIB_ROOT.parent / "okengine")):
        if cand and (Path(cand) / "scripts" / "cron" / "authority_lib.py").is_file():
            return Path(cand) / "scripts" / "cron" / "authority_lib.py"
    return None


def _load_write(dirpath: Path):
    """Import _okf_write from `dirpath` (fresh), so its `import okf_migrate` resolves to whatever
    is co-located there — engine present or not."""
    sys.modules.pop("_okf_write", None)
    sys.modules.pop("okf_migrate", None)
    sys.modules.pop("importer_guard", None)
    sys.modules.pop("authority_lib", None)
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


def test_write_page_runs_importer_guard_after_merge(capsys=None):
    """The direct-writer boundary sees preserved legacy fields as well as incoming fields."""
    with tempfile.TemporaryDirectory() as t:
        d = Path(t)
        scripts = d / "scripts"
        scripts.mkdir()
        shutil.copy(SCRIPTS / "_okf_write.py", scripts / "_okf_write.py")
        (scripts / "importer_guard.py").write_text(
            "def guard(fm, *, vault, namespace=''):\n"
            "    fm['guard_saw'] = fm.get('attribution_confidence')\n"
            "    return ['invalid attribution_confidence']\n"
        )
        vault = d / "vault"
        page = vault / "wiki" / "entities" / "legacy.md"
        page.parent.mkdir(parents=True)
        page.write_text(
            "---\ntype: actor\nattribution_confidence: free-text legacy value\n---\nold\n"
        )
        w = _load_write(scripts)
        w.write_page(w.content_root(vault), "entities/legacy.md",
                     {"type": "actor", "aliases": ["Legacy"]}, "fresh")
        fm, _ = w._split_frontmatter(page.read_text())
        assert fm["guard_saw"] == "free-text legacy value"
        assert fm["needs_review"] is True


def test_authority_policy_is_the_only_path_that_clears_sticky_review():
    authority = _engine_authority_lib()
    if authority is None:
        print("  skip authority test (engine authority_lib not found; set OKENGINE_DIR)")
        return
    with tempfile.TemporaryDirectory() as t:
        d = Path(t)
        scripts = d / "scripts"
        scripts.mkdir()
        shutil.copy(SCRIPTS / "_okf_write.py", scripts / "_okf_write.py")
        shutil.copy(authority, scripts / "authority_lib.py")
        vault = d / "vault"
        page = vault / "wiki" / "entities" / "apt1.md"
        page.parent.mkdir(parents=True)
        page.write_text("---\ntype: actor\nneeds_review: true\n---\nold\n")
        policy = {
            "id": "test-mitre", "authority": "MITRE ATT&CK", "eligible_types": ["actor"],
            "source_names": ["MITRE ATT&CK"], "url_hosts": ["attack.mitre.org"],
            "url_path_pattern": r"/groups/G\d{4}/?", "id_field": "attack_id",
            "id_pattern": r"G\d{4}", "verified_fields": ["title"],
            "required_values": {"authority_import": "mitre-attack-stix"},
        }
        incoming = {"type": "actor", "attack_id": "G0006", "sources": ["MITRE ATT&CK"],
                    "url": "https://attack.mitre.org/groups/G0006/",
                    "authority_import": "mitre-attack-stix"}
        w = _load_write(scripts)
        w.write_page(w.content_root(vault), "entities/apt1.md", incoming, "fresh",
                     authority_policy=policy, reviewed_at="2026-07-19T12:34:56Z")
        fm, _ = w._split_frontmatter(page.read_text())
        assert fm["needs_review"] is False
        assert fm["review_state"] == "approved"
        assert fm["reviewed_by"] == "policy:test-mitre"
        assert fm["reviewed_at"] == "2026-07-19T12:34:56Z"


def test_authority_policy_fails_closed_on_spoofed_url():
    authority = _engine_authority_lib()
    if authority is None:
        return
    with tempfile.TemporaryDirectory() as t:
        scripts = Path(t) / "scripts"
        scripts.mkdir()
        shutil.copy(SCRIPTS / "_okf_write.py", scripts / "_okf_write.py")
        shutil.copy(authority, scripts / "authority_lib.py")
        w = _load_write(scripts)
        vault = Path(t) / "vault"
        policy = {
            "id": "test", "authority": "MITRE", "eligible_types": ["actor"],
            "source_names": ["MITRE ATT&CK"], "url_hosts": ["attack.mitre.org"],
            "id_field": "attack_id", "id_pattern": r"G\d{4}", "verified_fields": ["title"],
        }
        try:
            w.write_page(w.content_root(vault), "entities/fake.md",
                         {"type": "actor", "sources": ["MITRE ATT&CK"], "attack_id": "G0001",
                          "url": "https://attack.mitre.org.evil.example/groups/G0001/"}, "fake",
                         authority_policy=policy)
        except ValueError:
            pass
        else:
            raise AssertionError("spoofed authority URL was accepted")
        assert not (vault / "wiki" / "entities" / "fake.md").exists()


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
