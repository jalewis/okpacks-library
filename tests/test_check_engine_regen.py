"""The library runs the engine's own cron regen over every pack (library#103).

Three packs at main failed the step a deploy runs -- weekly-brief lanes without `max_iterations` --
while their live deployments passed on hand-fixed copies. These tests drive the checker against a
fake engine whose `regen()` accepts or rejects a pack, so every branch is exercised without a real
engine; CI additionally runs it against a real engine clone through validate-all.sh.
"""
from __future__ import annotations

import importlib.util
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("check_engine_regen", ROOT / "scripts" / "check_engine_regen.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

FAKE_ENGINE = '''
import json, os, pathlib
PACK_DIR = pathlib.Path(os.environ.get("CRON_PACK_DIR", "/nowhere"))
JOBS = pathlib.Path("/must/not/be/written")
def regen():
    if (PACK_DIR / "BAD").exists():
        raise SystemExit("cron agent-bound errors (not deploying):\\n  job 'x': requires max_iterations")
    JOBS.write_text(json.dumps([]))   # proves the checker redirected JOBS away from the engine
'''


@pytest.fixture
def world(tmp_path):
    engine = tmp_path / "engine"
    (engine / "scripts").mkdir(parents=True)
    (engine / "scripts" / "cron_pack_split.py").write_text(FAKE_ENGINE)
    packs = tmp_path / "packs"
    for name in ("good", "bad", "schema-only"):
        (packs / name).mkdir(parents=True)
    (packs / "good" / "crons").mkdir()
    (packs / "bad" / "crons").mkdir()
    (packs / "bad" / "BAD").write_text("")
    return engine, packs


def test_only_packs_with_crons_are_regenerated(world):
    _engine, packs = world
    assert [p.name for p in mod.packs(packs)] == ["bad", "good"]


def test_a_pack_the_engine_rejects_fails_with_the_engines_reason(world, monkeypatch, capsys):
    engine, packs = world
    monkeypatch.setenv("ENGINE_DIR", str(engine))
    assert mod.main([str(packs)]) == 1
    out = capsys.readouterr().out
    assert "FAIL bad" in out and "ok   good" in out
    assert "requires max_iterations" in out, "the engine's own error is shown"


def test_all_packs_accepted_passes(world, monkeypatch):
    engine, packs = world
    (packs / "bad" / "BAD").unlink()
    monkeypatch.setenv("ENGINE_DIR", str(engine))
    assert mod.main([str(packs)]) == 0


def test_regen_pack_reports_a_bare_exit_code_when_the_engine_prints_nothing(world, tmp_path):
    engine, packs = world
    (engine / "scripts" / "cron_pack_split.py").write_text("def regen():\n    raise SystemExit(7)\n")
    assert mod.regen_pack(engine, packs / "good") == "exit 7"


@pytest.mark.parametrize("ci, expected", [("true", 1), ("", 0)])
def test_without_an_engine_the_check_is_undetectable_not_a_pass(world, monkeypatch, capsys, ci, expected):
    _engine, packs = world
    monkeypatch.delenv("ENGINE_DIR", raising=False)
    monkeypatch.setenv("CI", ci)
    assert mod.main([str(packs)]) == expected
    assert "UNDETECTABLE" in capsys.readouterr().out


def test_the_default_root_is_the_library_packs_dir(monkeypatch, capsys):
    monkeypatch.setenv("ENGINE_DIR", "/nonexistent-engine")
    monkeypatch.delenv("CI", raising=False)
    assert mod.main([]) == 0 and "UNDETECTABLE" in capsys.readouterr().out


def test_the_engines_own_src_package_is_importable_and_wins(world, monkeypatch):
    """Regression: the engine's scripts import `okengine` from the checkout's src/.

    CI clones the engine without installing it, so the regen failed on every pack with
    `No module named 'okengine'` once the engine stopped swallowing that error (engine#857). The
    package must resolve from ENGINE_DIR's own src/ -- ahead of any installed `okengine`, which may
    be a different revision than the one under test.
    """
    engine, packs = world
    pkg = engine / "src" / "okengine"
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text("")
    (pkg / "regen_probe.py").write_text("FROM_CHECKOUT = True\n")
    (engine / "scripts" / "cron_pack_split.py").write_text(
        "import pathlib, okengine\n"
        "from okengine.regen_probe import FROM_CHECKOUT\n"
        "PACK_DIR = JOBS = None\n"
        "def regen():\n"
        f"    assert pathlib.Path(okengine.__file__).is_relative_to({str(engine)!r}), okengine.__file__\n"
        "    assert FROM_CHECKOUT\n")
    (packs / "bad" / "BAD").unlink()
    monkeypatch.setenv("ENGINE_DIR", str(engine))
    assert mod.regen_pack(engine, packs / "good") is None

