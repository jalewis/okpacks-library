#!/usr/bin/env python3
"""Regression for validate-library's engine-currency gate.

Before this check, the library gate verified only that packs agreed with EACH OTHER
(check_engine_coherence); a whole library uniformly lagging one engine MINOR passed silently, so
every from-scratch `framework pull` died at the engine's version gate (the v0.10.8-vs-v0.11.3 drift).
check_engine_currency FAILs a pack whose engine.version is a different release series than the engine
the library is validated against, and WARNs (never a vacuous pass) when the engine isn't locatable.
"""
import importlib.util
import os
import tempfile
from pathlib import Path

VL = Path(__file__).resolve().parent.parent / "scripts" / "validate-library.py"


def _load():
    spec = importlib.util.spec_from_file_location("validate_library", VL)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _mk(root: Path, name: str, ver: str) -> None:
    d = root / "packs" / name
    d.mkdir(parents=True, exist_ok=True)
    (d / "engine.version").write_text(f"engine: okengine\nversion: {ver}\nhermes_pin: v2026.7.7.2\n")
    (d / "pack.yaml").write_text(f"name: {name}\n")     # pack_dirs() only counts dirs with a pack.yaml


def _run_currency(lib_root: Path, engine_release):
    m = _load()
    m.fails.clear(); m.warns.clear()
    if engine_release is None:
        os.environ.pop("OKENGINE_DIR", None)
        m.ROOT = Path("/nonexistent-no-sibling")        # also defeats the ../okengine fallback
    else:
        m.ROOT = lib_root
        eng = lib_root / "_engine"
        eng.mkdir(parents=True, exist_ok=True)
        (eng / "engine-manifest.yaml").write_text(f"engine_release: {engine_release}\n")
        os.environ["OKENGINE_DIR"] = str(eng)
    m.check_engine_currency()
    return m.fails, m.warns


def test_currency_fails_a_cross_series_pin_passes_a_matching_one():
    with tempfile.TemporaryDirectory() as t:
        root = Path(t)
        _mk(root, "okpack-good", "v0.11.3")             # matches engine
        _mk(root, "okpack-stale", "v0.10.8")            # lags a minor -> uninstallable
        fails, _ = _run_currency(root, "v0.11.3")
        blob = " ".join(fails)
        assert "okpack-stale" in blob and "different release series" in blob, fails
        assert "okpack-good" not in blob, fails         # the current pack must not fail


def test_currency_passes_a_patch_newer_engine_same_series():
    with tempfile.TemporaryDirectory() as t:
        root = Path(t)
        _mk(root, "okpack-good", "v0.11.0")             # same minor, older patch -> compatible
        fails, _ = _run_currency(root, "v0.11.3")
        assert fails == [], fails


def test_currency_warns_when_engine_not_locatable():
    with tempfile.TemporaryDirectory() as t:
        root = Path(t)
        _mk(root, "okpack-good", "v0.11.3")
        fails, warns = _run_currency(root, None)
        assert fails == [] and any("undetectable" in w for w in warns), (fails, warns)


if __name__ == "__main__":
    test_currency_fails_a_cross_series_pin_passes_a_matching_one()
    test_currency_passes_a_patch_newer_engine_same_series()
    test_currency_warns_when_engine_not_locatable()
    print("ok")
