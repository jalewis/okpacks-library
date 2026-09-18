"""The vendored pack validator — the checks that drifted, and the ones that gate every pack.

This file is `packs/okpack-example/validate.py`, which okengine#606 made byte-identical across
every pack and the engine skeleton. Before that it existed in four vintages under one
`VALIDATE_VERSION` stamp, and the differences between them were not cosmetic: the okengine#178
`@jitter`-base check was in six copies and missing from four, https-only feed probing was in the
pack copies and not the skeleton, and only the skeleton handled a string-form `schedule`.

Nothing tested any of it. The identity gate now stops the copies diverging; these tests are what
stops the shared file losing a check silently, which is how the divergence started.

The module uses module-level `fails`/`warns` accumulators and a module-level `ROOT`, so each test
gets a scratch pack and a cleared accumulator.
"""
from __future__ import annotations

import importlib.util
import json
import pathlib

import pytest
import yaml

REPO = pathlib.Path(__file__).resolve().parent.parent
VALIDATOR = REPO / "packs" / "okpack-example" / "validate.py"


def load():
    spec = importlib.util.spec_from_file_location("pack_validator", VALIDATOR)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def pack(tmp_path, monkeypatch):
    """A scratch pack rooted at tmp_path, with the validator pointed at it."""
    mod = load()
    monkeypatch.setattr(mod, "ROOT", tmp_path)
    mod.fails.clear()
    mod.warns.clear()
    (tmp_path / "crons").mkdir()
    (tmp_path / "feeds").mkdir()
    mod.pack_dir = tmp_path
    return mod


def write_crons(mod, jobs):
    (mod.ROOT / "crons" / "domain-crons.json").write_text(json.dumps(jobs), encoding="utf-8")


# --- okengine#178: the check that was missing from four vintages ---------------------------

@pytest.mark.parametrize("base", ["hourly", "2h", "4h", "6h", "12h", "daily", "weekly"])
def test_every_supported_jitter_base_is_accepted(pack, base):
    """The set has to match the engine's `cron_jitter._SENTINEL_RE`. Rejecting a base the engine
    supports would block a legitimate pack at the earliest gate."""
    write_crons(pack, [{"name": "x", "enabled": True, "schedule": {"expr": f"@jitter:{base}"}}])
    pack.check_crons_jittered()
    assert pack.fails == []


def test_an_unsupported_jitter_base_fails(pack):
    """okengine#178. `@jitter:3h` passes a naive prefix check, never expands, and cron-plus then
    errors every tick while the lane silently never fires. Four pack copies lost this check and
    still reported the same VALIDATE_VERSION as the copies that had it."""
    write_crons(pack, [{"name": "hourly-ish", "enabled": True,
                        "schedule": {"expr": "@jitter:3h"}}])
    pack.check_crons_jittered()
    assert len(pack.fails) == 1
    assert "unsupported @jitter base" in pack.fails[0] and "hourly-ish" in pack.fails[0]


def test_a_jitter_base_with_a_suffix_is_read_without_it(pack):
    """`@jitter:daily@02` names a supported base. Splitting on `@` is what the skeleton had and
    the pack copies did not — without it every suffixed sentinel is rejected as unsupported."""
    write_crons(pack, [{"name": "x", "enabled": True,
                        "schedule": {"expr": "@jitter:daily@02"}}])
    pack.check_crons_jittered()
    assert pack.fails == []


def test_a_string_form_schedule_is_read_not_ignored(pack):
    """`schedule` may be a bare cron string rather than `{expr: ...}`. Only the skeleton handled
    that; the pack copies read `{}.get("expr")` off a string and saw an empty expr, which made
    every string-scheduled cron look herd-prone."""
    write_crons(pack, [{"name": "x", "enabled": True, "schedule": "@jitter:daily"}])
    pack.check_crons_jittered()
    assert pack.fails == []


# --- the herd-prone-schedule invariant ------------------------------------------------------

@pytest.mark.parametrize("expr", ["0 */2 * * *", "* * * * *", "*/1 * * * *", ""])
def test_a_herd_prone_schedule_fails(pack, expr):
    """A committed minute-0 (or every-minute) schedule points every install at upstream on the
    same minute — the reason the sentinel exists."""
    write_crons(pack, [{"name": "x", "enabled": True, "schedule": {"expr": expr}}])
    pack.check_crons_jittered()
    assert len(pack.fails) == 1 and "herd-prone" in pack.fails[0]


def test_an_already_jittered_concrete_schedule_passes(pack):
    """A non-:00 minute is already spread; requiring a sentinel there would reject a correct pack."""
    write_crons(pack, [{"name": "x", "enabled": True, "schedule": {"expr": "37 */2 * * *"}}])
    pack.check_crons_jittered()
    assert pack.fails == []


def test_a_disabled_cron_is_not_judged(pack):
    """The invariant is about what ships ENABLED. A disabled job cannot herd."""
    write_crons(pack, [{"name": "x", "enabled": False, "schedule": {"expr": "0 * * * *"}}])
    pack.check_crons_jittered()
    assert pack.fails == []


def test_unparseable_crons_are_left_to_the_parse_check(pack):
    """Reporting a JSON error twice, from two checks, buries the one that says where it is."""
    (pack.ROOT / "crons" / "domain-crons.json").write_text("{not json", encoding="utf-8")
    pack.check_crons_jittered()
    assert pack.fails == []


# --- https-only feed probing (present in the pack copies, absent from the skeleton) ---------

def test_a_non_https_feed_url_is_skipped_with_a_warning(pack):
    """The probe fetches URLs from the pack's own OPML. Restricting it to https is what makes
    the `# nosec B310` annotation on the urlopen call true rather than a silencer."""
    pack.probe_feeds(["http://insecure.example/feed.xml", "ftp://old.example/feed"])
    assert len(pack.warns) == 2
    assert all("non-https URL skipped" in w for w in pack.warns)
    assert pack.fails == []


def test_an_unreachable_https_feed_warns_rather_than_fails(pack):
    """A probe is advisory — the network is not the pack's contract. `--probe` is opt-in and a
    dead upstream must not make a valid pack invalid."""
    pack.probe_feeds(["https://127.0.0.1:9/never-listening"])
    assert len(pack.warns) == 1 and "unreachable" in pack.warns[0]
    assert pack.fails == []


# --- schema/meta consistency ---------------------------------------------------------------

def test_a_cron_writing_to_an_undeclared_namespace_fails(pack):
    """The drift this validator exists for: a cron telling the agent to write under a wiki
    directory that schema.yaml has no partitioning or exclude rule for."""
    schema = {"types": {"thing": {}},
              "partitioning": {"namespaces": {"things": {"strategy": "flat"}}}}
    write_crons(pack, [{"name": "x", "enabled": True, "schedule": {"expr": "@jitter:daily"},
                        "prompt": "write the page to wiki/nowhere/ when it is ready"}])
    (pack.ROOT / "crons" / "engine-template-prompts.json").write_text("{}", encoding="utf-8")
    pack.check_namespace_consistency(schema)
    assert any("wiki/nowhere/" in f for f in pack.fails)


def test_a_cron_writing_a_declared_namespace_passes(pack):
    """Otherwise the test above would pass on a check that rejects everything."""
    schema = {"types": {}, "partitioning": {"namespaces": {"things": {"strategy": "flat"}}}}
    write_crons(pack, [{"name": "x", "enabled": True, "schedule": {"expr": "@jitter:daily"},
                        "prompt": "write the page to wiki/things/ when it is ready"}])
    (pack.ROOT / "crons" / "engine-template-prompts.json").write_text("{}", encoding="utf-8")
    pack.check_namespace_consistency(schema)
    assert pack.fails == []


def test_a_cron_writing_an_undeclared_type_fails(pack):
    """The same class one level down: a literal `type:` in a prompt that schema.yaml never
    declares produces pages the write path will reject, one lane run at a time."""
    schema = {"types": {"thing": {}}, "partitioning": {"namespaces": {}}}
    write_crons(pack, [{"name": "x", "enabled": True, "schedule": {"expr": "@jitter:daily"},
                        "prompt": "set type: widget in the frontmatter"}])
    (pack.ROOT / "crons" / "engine-template-prompts.json").write_text("{}", encoding="utf-8")
    pack.check_type_consistency(schema)
    assert any("widget" in f for f in pack.fails)


def test_a_base_type_needs_no_pack_declaration(pack):
    """`source`/`concept`/`briefing` and friends come from the engine's base schema — requiring
    every pack to redeclare them would fail every correct pack."""
    schema = {"types": {}, "partitioning": {"namespaces": {}}}
    write_crons(pack, [{"name": "x", "enabled": True, "schedule": {"expr": "@jitter:daily"},
                        "prompt": "set type: source in the frontmatter"}])
    (pack.ROOT / "crons" / "engine-template-prompts.json").write_text("{}", encoding="utf-8")
    pack.check_type_consistency(schema)
    assert pack.fails == []


def test_pack_meta_owning_an_undeclared_type_fails(pack):
    """`pack.yaml` owns what `schema.yaml` declares. Owning a type that is not there means the
    composed vault has an owner for something that does not exist."""
    (pack.ROOT / "pack.yaml").write_text(
        yaml.safe_dump({"name": "okpack-demo", "trust": "public",
                        "owns": {"types": ["ghost"]}}), encoding="utf-8")
    pack.check_pack_meta({"types": {"thing": {}}, "partitioning": {"namespaces": {}}})
    assert any("ghost" in f for f in pack.fails)


def test_pack_meta_owning_an_undeclared_namespace_warns(pack):
    """A WARN, not a FAIL: a guest pack legitimately owns a namespace the HOST declares."""
    (pack.ROOT / "pack.yaml").write_text(
        yaml.safe_dump({"name": "okpack-demo", "trust": "public",
                        "owns": {"namespaces": ["elsewhere"]}}), encoding="utf-8")
    pack.check_pack_meta({"types": {}, "partitioning": {"namespaces": {}}})
    assert pack.fails == [] and any("elsewhere" in w for w in pack.warns)


# --- the property the identity gate rests on ------------------------------------------------

def test_the_validator_takes_its_pack_name_from_the_directory():
    """The two `{{PACK}}` literals were the only per-pack difference, and they are why no two
    copies could ever be compared byte-for-byte. Deriving the name is what made one shared file
    possible — a literal coming back re-forks it silently."""
    text = VALIDATOR.read_text(encoding="utf-8")
    assert "PACK_NAME = ROOT.name" in text
    assert "{{PACK}}" not in text
    assert 'f"{PACK_NAME}-validate"' in text, "the probe User-Agent stopped using the derived name"
