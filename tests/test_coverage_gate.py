"""`scripts/coverage_gate.py` — the floor, the ratchet, and the boundary that keeps them honest.

A coverage percentage is easy to make go up by measuring less. These tests are mostly about the
ways this gate could report a pass it did not earn: a tree quietly dropping out of the measured
surface, an exemption that stopped being true, a total floor masking one file being gutted, or a
surface that enumerated to nothing at all.

The gate reads the repo's real file list, so tests that need a fabricated surface inject one by
rebinding the module's own helpers rather than by building a fake repo on disk.
"""
from __future__ import annotations

import importlib.util
import json
import pathlib

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
SCRIPT = REPO / "scripts" / "coverage_gate.py"

spec = importlib.util.spec_from_file_location("coverage_gate", SCRIPT)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


def coverage_doc(files: dict[str, float], statements: int = 100) -> dict:
    """A minimal coverage.json: {path: percent}."""
    covered = sum(files.values()) / len(files) if files else 0.0
    return {
        "files": {p: {"summary": {"percent_covered": pct}} for p, pct in files.items()},
        "totals": {"percent_covered": covered, "num_statements": statements,
                   "covered_lines": int(statements * covered / 100), "num_branches": 0},
    }


@pytest.fixture
def sandbox(tmp_path, monkeypatch):
    """Point the gate at a scratch baseline and a fabricated tracked surface."""
    monkeypatch.setattr(gate, "BASELINE", tmp_path / "coverage-baseline.json")
    monkeypatch.setattr(gate, "COVERAGE_JSON", tmp_path / "coverage.json")
    monkeypatch.setattr(gate, "exempt_paths", lambda: {})
    monkeypatch.setattr(gate, "verify_exemptions", lambda paths: [])
    monkeypatch.setattr(gate, "tracked_python", lambda: ["a.py", "b.py"])
    return tmp_path


def stamp_then_check(cov_stamp: dict, cov_check: dict) -> int:
    gate.stamp(cov_stamp)
    return gate.check(cov_check)


# --- the floor ----------------------------------------------------------------------------

def test_a_run_that_matches_its_baseline_passes(sandbox, capsys):
    """The gate must be capable of passing, or every failure below proves nothing."""
    cov = coverage_doc({"a.py": 40.0, "b.py": 60.0})
    assert stamp_then_check(cov, cov) == 0
    assert "coverage-gate: PASS" in capsys.readouterr().out


def test_falling_below_the_total_floor_fails(sandbox, capsys):
    before = coverage_doc({"a.py": 40.0, "b.py": 60.0})
    after = coverage_doc({"a.py": 30.0, "b.py": 60.0})
    assert stamp_then_check(before, after) == 1
    assert "below the 50.00% floor" in capsys.readouterr().out


def test_one_file_may_not_be_gutted_behind_a_healthy_total(sandbox, capsys):
    """The reason a total-only floor is not enough: b.py improving pays for a.py collapsing,
    the aggregate holds, and the regression ships."""
    before = coverage_doc({"a.py": 40.0, "b.py": 60.0})
    after = coverage_doc({"a.py": 10.0, "b.py": 90.0})
    assert after["totals"]["percent_covered"] == before["totals"]["percent_covered"]
    assert stamp_then_check(before, after) == 1
    out = capsys.readouterr().out
    assert "a.py: 10.00% is below its own 40.00% baseline" in out
    assert "TOTAL" not in out, "the total was fine — only the per-file check should have fired"


# --- the ratchet --------------------------------------------------------------------------

def test_rising_well_past_the_floor_asks_for_a_re_stamp(sandbox, capsys):
    """Without this the floor sits at its first value forever while real coverage drifts above
    it, and the gap silently becomes the amount of regression the gate will tolerate."""
    before = coverage_doc({"a.py": 40.0, "b.py": 60.0})
    after = coverage_doc({"a.py": 60.0, "b.py": 60.0})
    assert stamp_then_check(before, after) == 1
    assert "--stamp" in capsys.readouterr().out


def test_a_small_rise_inside_the_slack_does_not_fail(sandbox):
    """Adding one test should not be a chore. The slack is what keeps the ratchet from being one."""
    before = coverage_doc({"a.py": 40.0, "b.py": 60.0})
    after = coverage_doc({"a.py": 40.5, "b.py": 60.0})
    assert stamp_then_check(before, after) == 0


# --- the boundary -------------------------------------------------------------------------

def test_a_tracked_file_that_is_neither_measured_nor_exempt_fails(sandbox, capsys, monkeypatch):
    """The failure mode that makes a percentage meaningless: a file leaves the measurement and
    the number goes UP, because it is an average over whatever remained."""
    cov = coverage_doc({"a.py": 40.0, "b.py": 60.0})
    gate.stamp(cov)
    monkeypatch.setattr(gate, "tracked_python", lambda: ["a.py", "b.py", "c.py"])
    assert gate.check(cov) == 1
    assert "c.py: tracked, not exempt, and not measured" in capsys.readouterr().out


def test_a_surface_that_enumerates_to_nothing_fails(sandbox, capsys, monkeypatch):
    """Zero failures over zero files is not a green gate — it is a gate that did not run."""
    cov = coverage_doc({"a.py": 40.0, "b.py": 60.0})
    gate.stamp(cov)
    monkeypatch.setattr(gate, "tracked_python", lambda: [])
    assert gate.check(cov) == 1
    assert "UNDETECTABLE" in capsys.readouterr().out


def test_a_missing_baseline_fails_with_the_command_that_creates_one(sandbox, capsys):
    """Not "no baseline, nothing to compare, pass"."""
    assert gate.check(coverage_doc({"a.py": 40.0})) == 1
    assert "--stamp" in capsys.readouterr().out


# --- the exemption list ---------------------------------------------------------------------

def test_every_exemption_names_a_real_file_and_a_reason():
    """An exemption glob that matches nothing is either a typo or a file that came back into
    the measurement. Either way the list is describing a repo that no longer exists."""
    exempt = gate.exempt_paths()
    assert exempt, "the exemption list matched no files — has the layout moved?"
    for path, reason in exempt.items():
        assert (REPO / path).is_file(), f"{path} is exempted but does not exist"
        assert len(reason) > 80, f"{path}: exemption reason is too thin to review"


def test_the_exemption_reason_is_checked_against_the_file_not_taken_on_trust():
    """The feed_fetch wrappers are exempt because importing one raises ModuleNotFoundError
    before any of its statements run. That claim is verified per-file, so an exemption cannot
    quietly outlive the fact that justified it."""
    assert gate.verify_exemptions(gate.exempt_paths()) == []
    # A file that no longer matches the claimed shape is reported, not silently kept.
    assert gate.verify_exemptions({"scripts/coverage_gate.py": "wrong reason"}) != []


def test_without_git_the_surface_is_undetectable_rather_than_empty(monkeypatch, capsys):
    """The CI failure this was written for: `git` was absent from the coverage job's image, so
    `git ls-files` raised, the enumeration came back empty, and the runner reported "no
    measurable files". It failed closed, which is right, but it named the wrong cause — and an
    empty surface is one refactor away from being read as "nothing to measure, pass"."""
    def no_git(*args, **kwargs):
        raise FileNotFoundError(2, "No such file or directory", "git")
    monkeypatch.setattr(gate.subprocess, "run", no_git)
    with pytest.raises(SystemExit) as exc:
        gate.tracked_python()
    assert "UNDETECTABLE" in str(exc.value)


def test_the_measured_surface_excludes_tests_and_exemptions_and_is_not_empty():
    """The live wiring: what coverage-run.sh will actually hand to `coverage json`."""
    surface = gate.measurable()
    assert surface, "nothing to measure"
    assert not any("/tests/" in f"/{p}" or p.startswith("tests/") for p in surface)
    assert not any("/conformance/" in f"/{p}" for p in surface)
    assert not any(p.endswith("_feed_fetch.py") for p in surface)


def test_the_committed_baseline_matches_the_surface_the_gate_will_measure():
    """A baseline listing files the gate no longer measures (or missing ones it does) makes the
    per-file check silently partial — it only compares the intersection."""
    baseline = json.loads((REPO / "coverage-baseline.json").read_text(encoding="utf-8"))
    assert set(baseline["files"]) == set(gate.measurable()), (
        "coverage-baseline.json and the measurable surface have diverged — re-stamp")
