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

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _identity_standins  # noqa: E402  (stand-ins for engine identity libs a pack-only run lacks)

SCRIPTS = Path(__file__).resolve().parent.parent / "crons" / "scripts"
LIB_ROOT = Path(__file__).resolve().parents[3]


def _engine_okf_migrate() -> Path | None:
    """okf_migrate.py from an engine checkout (OKENGINE_DIR, ENGINE_DIR -- what CI and the
    validate scripts set -- else a sibling ../okengine)."""
    for cand in (os.environ.get("OKENGINE_DIR"), os.environ.get("ENGINE_DIR"),
                 str(LIB_ROOT.parent / "okengine")):
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
    # The copied writer now requires its real sibling actor guard adapter.
    sys.path.insert(0, str(SCRIPTS))
    sys.path.insert(0, str(dirpath))
    spec = importlib.util.spec_from_file_location("_okf_write", dirpath / "_okf_write.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def test_write_page_updates_an_existing_page_in_place_and_shards_a_new_one():
    """write_key contract (okengine#243/#818): an EXISTING page is updated where it sits -- never
    forked into the shard beside it -- and the reshelve drain owns relocation. A NEW page is
    minted at its by-letter shard straight away. The previous expectation (a write moves a stale
    flat page into its shard) predates #818; it went unnoticed because the test skipped silently
    whenever the engine was located only through ENGINE_DIR."""
    engine = _engine_okf_migrate()
    if engine is None:
        print("  skip test_write_page_updates... (engine okf_migrate not found; set OKENGINE_DIR)")
        return
    # The copied okf_migrate imports `tools.schema_validator` and the `okengine` package
    # (okengine#997), which the gateway resolves from /opt/hermes: give it this checkout's two roots.
    root = engine.parents[2]
    saved_path = list(sys.path)
    sys.path[:0] = [str(root), str(root / "src")]
    try:
        _write_page_updates_in_place(engine)
    finally:
        sys.path[:] = saved_path
        for name in [n for n in sys.modules if n == "tools" or n.startswith("tools.")]:
            sys.modules.pop(name)


def _write_page_updates_in_place(engine: Path) -> None:
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
        # pre-existing FLAT copy carrying a curated field owned by another lane
        (vault / "wiki" / "entities" / "havij.md").write_text(
            "---\ntype: actor\nid: S0224\nattribution_confidence: high\n---\nold\n")

        w = _load_write(d / "scripts")
        content = w.content_root(vault)                  # == vault/wiki
        for _ in range(2):                               # twice = idempotent
            act = w.write_page(content, "entities/havij.md",
                               {"type": "actor", "id": "S0224", "aliases": ["havij"]}, "fresh")
        pages = sorted(p.relative_to(content).as_posix() for p in (content / "entities").rglob("*.md"))
        assert pages == ["entities/havij.md"], pages     # updated in place, no shard duplicate
        assert act == "updated"
        fm, _ = w._split_frontmatter((content / "entities" / "havij.md").read_text())
        assert fm.get("attribution_confidence") == "high"       # curated field kept
        assert fm.get("aliases") == ["havij"]

        # A NEW page's seat, as write_page computes it (creating needs the engine identity libs,
        # proven separately in tests/test_okf_write_page_id.py).
        assert w.okf_migrate.write_key(vault, "entities", "lazarus", {"type": "actor"}) \
            == "entities/l/lazarus"

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
        if w.missing_identity_libs():
            # No engine identity libs either: a CREATE is refused rather than landing a page with
            # no id, which the write path could never update (okpacks-library#105).
            assert w.write_page(content, "entities/havij.md", {"type": "actor"}, "b") == \
                "unverifiable"
            assert not (content / "entities" / "havij.md").exists()
        _identity_standins.install(w)                           # identity available, seat not
        assert w.write_page(content, "entities/havij.md", {"type": "actor"}, "b") == "created"
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
        _identity_standins.install(w)      # a create needs identity; the POLICY is under test
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
