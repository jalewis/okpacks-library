#!/usr/bin/env python3
"""Every pack must survive the engine's cron regen -- the exact step a deploy runs (library#103).

`deploy-cron-plus-jobs.sh` generates a deployment's cron fleet with the engine's
`cron_pack_split.regen()`, which enforces the composed-fleet rules (agent bounds such as
`max_iterations`, writer names, prompt bindings, ordering, id uniqueness). Nothing in this library
ran it, so three packs at main failed it -- their weekly-brief lanes lacked `max_iterations` --
while their live deployments passed on hand-fixed copies. A fresh install from the library would
have stopped at cron deploy.

This loads the engine's own module from ENGINE_DIR (never a mirrored copy, which can agree with
itself while disagreeing with the engine) and runs regen per pack with the generated jobs file
redirected to a temp path, so a developer's engine checkout is never written to.

The engine checkout's `src/` goes on the path ahead of anything installed. The engine's
`scripts/pack_meta.py` imports the `okengine` package from `src/okengine`. CI clones the engine
without installing it, so that import failed and the regen quietly fell back to the directory
name as the pack name -- until engine#857 made that fallback an error, failing every pack. A
developer venv hid the gap the other way: it resolved `okengine` from an installed wheel, which
is not necessarily the ENGINE_DIR revision under test.

Requires ENGINE_DIR. Without it this cannot check anything, so it says so and -- under CI --
fails, rather than reporting a pass it did not earn.
"""
from __future__ import annotations

import os
import pathlib
import subprocess
import sys
import tempfile

_RUNNER = r"""
import importlib.util, os, pathlib, sys
engine, pack, jobs = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]), pathlib.Path(sys.argv[3])
sys.path.insert(0, str(engine / "scripts"))
# The engine's `okengine` package lives in src/ of the SAME checkout. Put it first so the regen
# imports this engine's package, never whatever `okengine` the running Python has installed.
sys.path.insert(0, str(engine / "src"))
spec = importlib.util.spec_from_file_location("cron_pack_split", engine / "scripts" / "cron_pack_split.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
mod.PACK_DIR, mod.JOBS = pack, jobs
mod.regen()
"""


def packs(root: pathlib.Path) -> list[pathlib.Path]:
    """Pack directories that carry cron definitions (bundles and schema-only packs have none)."""
    return sorted(p for p in root.iterdir() if p.is_dir() and (p / "crons").is_dir())


def regen_pack(engine: pathlib.Path, pack: pathlib.Path) -> str | None:
    """None when the engine's regen accepts the pack, else its error text."""
    with tempfile.TemporaryDirectory() as tmp:
        env = {**os.environ, "CRON_PACK_DIR": str(pack)}
        result = subprocess.run(
            [sys.executable, "-c", _RUNNER, str(engine), str(pack), str(pathlib.Path(tmp) / "jobs.json")],
            capture_output=True, text=True, env=env, timeout=300)
    if result.returncode == 0:
        return None
    return (result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}")[-1500:]


def main(argv: list[str]) -> int:
    root = pathlib.Path(argv[0]) if argv else pathlib.Path(__file__).resolve().parents[1] / "packs"
    engine_dir = os.environ.get("ENGINE_DIR", "")
    engine = pathlib.Path(engine_dir) if engine_dir else None
    if engine is None or not (engine / "scripts" / "cron_pack_split.py").is_file():
        print("engine regen: UNDETECTABLE -- set ENGINE_DIR to an okengine checkout; this is not a pass")
        return 1 if os.environ.get("CI") else 0
    failures = []
    for pack in packs(root):
        error = regen_pack(engine, pack)
        print(f"  {'ok  ' if error is None else 'FAIL'} {pack.name}")
        if error is not None:
            failures.append((pack.name, error))
    for name, error in failures:
        print(f"\n{name}: the engine's cron regen rejects this pack --\n{error}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
