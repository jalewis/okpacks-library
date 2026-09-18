"""okpacks-library#89 — the compose check must be able to import what it loads.

`bundle-compose-check.sh` loads engine modules out of an engine checkout by path. Those
modules import from the `okengine` PACKAGE, which lives in the engine's `src/` directory and is
normally reachable because a deployment pip-installs the engine. The check does not install
anything, so every directory it needs has to be on `sys.path` explicitly.

`src/` was missing. `corpus_audit` imports `okengine.actor_identity`, so the moment the engine
added that import the compose-integration job began failing with `ModuleNotFoundError: No module
named 'okengine'` — on EVERY merge request in this repo, regardless of content, and with nothing
on the engine side to signal it.

This pins the path list so a future engine module that imports from the package does not
rediscover it the same way.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "bundle-compose-check.sh"


@pytest.fixture(scope="module")
def sys_path_line() -> str:
    text = SCRIPT.read_text(encoding="utf-8")
    match = re.search(r"sys\.path\[:0\] = \[(.*?)\]", text, re.S)
    assert match, "compose check no longer sets sys.path in the recognised form"
    return match.group(1)


@pytest.mark.parametrize("needed", [
    'data / "scripts"',                    # staged engine scripts
    'engine / "scripts"',                  # framework modules
    'engine / "scripts" / "cron"',         # the cron modules under test
    'engine / "src"',                      # the `okengine` package they import from
])
def test_every_required_root_is_on_the_path(sys_path_line, needed):
    assert needed in sys_path_line, (
        f"{needed} missing from the compose check's sys.path. Engine modules loaded by this "
        "script import from the okengine package; omitting a root makes them unimportable and "
        "fails compose-integration on every MR in this repo."
    )


def test_the_engine_package_root_is_named_src(sys_path_line):
    """NEGATIVE-ish guard: if the engine ever relocates its package, this test should fail
    loudly here rather than the job failing with an opaque ModuleNotFoundError."""
    engine_root = Path(__file__).resolve().parents[2] / "okengine" / "src" / "okengine"
    if not engine_root.is_dir():
        pytest.skip("engine checkout not adjacent; path contract still pinned by the test above")
    assert (engine_root / "__init__.py").is_file()
    assert 'engine / "src"' in sys_path_line
