#!/usr/bin/env python3
"""Coverage floor + ratchet for the pack library (okengine#601).

The suites here ran against no floor and no baseline: 151 tests passed, and nothing measured
or bounded what they touched. That matters more than usual because pack cron scripts are not
inert configuration — they are `no_agent` lanes that write to the vault directly, bypassing the
enforced write SERVER while remaining bound by the corpus INVARIANTS. Every recent defect in
them (an undeclared `source_kind`, hand-rolled YAML quoting that stopped six captures parsing,
two modules six importers imported that were not in the repo) was caught by reading the code or
by a live vault, never by a test.

A 100% floor imposed at an unknown baseline fails on day one and gets waived, which is worse
than no floor. So this measures, publishes, floors at the measurement, and ratchets.

Three checks, in the order they can go wrong:

**Boundary.** Every tracked non-test .py is measured or carries a written exemption. Without
this a whole tree can drop out of measurement and the percentage goes UP. Exemptions are
verified live: one that no longer applies fails, so the list cannot rot into a permission slip.

**Total floor.** Aggregate line coverage may not fall below the baseline.

**Per-file no-regression.** No file may fall below its own baseline. A total-only floor lets a
well-covered new file pay for gutting an existing one.

The ratchet is the other direction: coverage that rises past the baseline by more than a point
fails too, asking you to re-stamp. That is what makes the floor move rather than sit at its
2026 value forever.

One structural fact worth knowing before anyone plans the climb: `packs/*/validate.py` is the
same ~395-statement validator copied into eleven packs, byte-identical once the pack name is
normalised, and it is 0% covered. That is roughly 45% of this repo's measured statements. The
ratchet will not move meaningfully until those eleven copies become one shared module -- which
validate-all.sh's own comment says was the intent ("The shared validator lib
(scripts/pack_validate_lib.py) is vendored into each pack as", a sentence that stops mid-clause
and refers to a file that does not exist). Writing the same tests eleven times is the wrong
answer to that; deduplicating is, and it is a separate change.
"""
from __future__ import annotations

import argparse
import ast
import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
BASELINE = ROOT / "coverage-baseline.json"
COVERAGE_JSON = ROOT / "coverage.json"

# How far coverage may rise above the baseline before the gate asks for a re-stamp. Small enough
# that the floor actually tracks reality; large enough that adding one test is not a chore.
RATCHET_SLACK = 1.0

# The one vendored validator that IS measured. Every pack ships a byte-identical copy (they must
# validate standalone and offline, so the file cannot live in scripts/); measuring all of them
# would count the same ~390 statements ten times and make the denominator a duplication artefact
# rather than a size. The other nine are exempted below, and the exemption is only sound because
# check_vendored_validators.py proves they are the same bytes as this one (okengine#606).
CANONICAL_VALIDATOR = "packs/okpack-example/validate.py"

# Files that CANNOT be measured here, each with the reason. Checked against reality on every run
# (see `verify_exemptions`), so a reason that stops being true fails the gate.
EXEMPT: dict[str, str] = {
    "packs/*/crons/scripts/*_feed_fetch.py":
        "thin wrapper over the engine's generic feed_fetch.py, which is co-deployed to "
        "/opt/data/scripts at runtime and is not in this repo. The module body is "
        "`raise SystemExit(feed_fetch.main([...]))`, so importing it here raises "
        "ModuleNotFoundError before a single statement of the wrapper runs. Measurable only "
        "in a deployment, which is not what this gate measures.",
}

VENDORED_VALIDATOR_REASON = (
    f"byte-identical vendored copy of {CANONICAL_VALIDATOR}, which IS measured. Packs vendor "
    "this file because they must validate standalone and offline; counting all ten copies would "
    "multiply one file's statements by ten and turn the denominator into a duplication artefact. "
    "check_vendored_validators.py fails the build if any copy stops matching, so this exemption "
    "cannot outlive the identity it rests on."
)


def tracked_python() -> list[str]:
    """Every tracked .py that is not itself a test. `git ls-files` rather than a walk: an
    untracked scratch file is not part of the surface, and a file deleted from git but left on
    disk must not keep counting."""
    try:
        proc = subprocess.run(["git", "ls-files", "*.py"], cwd=ROOT, capture_output=True,
                              text=True, check=True)
    except FileNotFoundError:
        # Not "no files, therefore nothing to measure". Without git the surface is unknowable,
        # and an unknowable surface must not resolve to an empty one — that is the difference
        # between "the gate found nothing wrong" and "the gate could not look".
        sys.exit("coverage-gate: git is not available, so the measured surface is UNDETECTABLE "
                 "(install git in this job — the gate enumerates from `git ls-files`)")
    except subprocess.CalledProcessError as exc:
        sys.exit(f"coverage-gate: `git ls-files` failed ({exc.returncode}), so the measured "
                 f"surface is UNDETECTABLE:\n{exc.stderr.strip()}")
    out = proc.stdout.split()
    return sorted(
        p for p in out
        if "/tests/" not in f"/{p}" and "/conformance/" not in f"/{p}"
        and not pathlib.PurePosixPath(p).name.startswith("test_")
        and not p.startswith("tests/")
    )


def _is_bundle(pack: pathlib.Path) -> bool:
    """A bundle owns no types and ships no schema.yaml, so its `validate.py` checks a RECIPE and
    is legitimately a different program — not a duplicate, and so not exempt. Line-scanned rather
    than parsed so this stays dependency-free."""
    meta = pack / "pack.yaml"
    if not meta.is_file():
        return False
    return any(line.strip().replace('"', "").replace("'", "") == "kind: bundle"
               for line in meta.read_text(encoding="utf-8", errors="replace").splitlines())


def exempt_paths() -> dict[str, str]:
    """Expand the EXEMPT globs against the tracked surface, keeping each file's reason, and add
    the duplicate vendored validators (a rule a glob cannot express: every copy EXCEPT one)."""
    tracked = tracked_python()
    out: dict[str, str] = {}
    for pattern, reason in EXEMPT.items():
        for path in tracked:
            if pathlib.PurePosixPath(path).match(pattern):
                out[path] = reason
    for path in tracked:
        if (pathlib.PurePosixPath(path).match("packs/*/validate.py")
                and path != CANONICAL_VALIDATOR
                and not _is_bundle(ROOT / path.rsplit("/", 1)[0])):
            out[path] = VENDORED_VALIDATOR_REASON
    return out


def verify_exemptions(paths: dict[str, str]) -> list[str]:
    """An exemption claims something about the world. Check it, so the list cannot become a
    place to file inconvenient files.

    Parsed rather than grepped: a substring search for "import feed_fetch" is satisfied by any
    file that merely MENTIONS it — a comment, a docstring, this module's own exemption text —
    so it would wave through exactly the files it exists to catch. The claim is structural
    (a module-level import of feed_fetch, and a module-level raise), so check the structure."""
    problems = []
    canonical = ROOT / CANONICAL_VALIDATOR
    for path in sorted(paths):
        target = ROOT / path
        if paths[path] is VENDORED_VALIDATOR_REASON:
            # The claim is byte-identity to a file that IS measured. Anything else — a drifted
            # copy, or a canonical file that vanished — means these statements are going
            # unmeasured rather than being measured once.
            if not canonical.is_file():
                problems.append(f"{path}: exempted as a copy of {CANONICAL_VALIDATOR}, which "
                                "does not exist — nothing is measuring this code")
            elif target.read_bytes() != canonical.read_bytes():
                problems.append(f"{path}: exempted as byte-identical to {CANONICAL_VALIDATOR} "
                                "but differs — it is now unmeasured code, not a duplicate")
            continue
        try:
            tree = ast.parse(target.read_text(encoding="utf-8"))
        except (OSError, SyntaxError) as exc:
            problems.append(f"{path}: exempted but unreadable ({exc})")
            continue
        imports_it = any(
            isinstance(node, ast.Import) and any(a.name == "feed_fetch" for a in node.names)
            for node in tree.body)
        raises = any(isinstance(node, ast.Raise) for node in tree.body)
        if not (imports_it and raises):
            problems.append(
                f"{path}: exempted as a wrapper that raises before its own statements run, but "
                "its module body no longer imports feed_fetch and raises — measure it, or "
                "correct the reason")
    return problems


def measurable() -> list[str]:
    return [p for p in tracked_python() if p not in exempt_paths()]


def load_coverage() -> dict:
    if not COVERAGE_JSON.is_file():
        sys.exit(f"no {COVERAGE_JSON.name} — run scripts/coverage-run.sh first")
    return json.loads(COVERAGE_JSON.read_text(encoding="utf-8"))


def file_pct(entry: dict) -> float:
    return round(float(entry["summary"]["percent_covered"]), 2)


def stamp(cov: dict) -> None:
    files = {path: file_pct(entry) for path, entry in sorted(cov["files"].items())}
    totals = cov["totals"]
    BASELINE.write_text(json.dumps({
        "_": "Generated by scripts/coverage_gate.py --stamp. The floor is the measurement, and "
             "it only moves up: see the module docstring for why a floor set above the baseline "
             "gets waived instead of met.",
        "total_percent": round(float(totals["percent_covered"]), 2),
        "num_statements": totals["num_statements"],
        "covered_lines": totals["covered_lines"],
        "num_branches": totals["num_branches"],
        "files": files,
    }, indent=2) + "\n", encoding="utf-8")
    print(f"stamped {BASELINE.name}: {totals['percent_covered']:.2f}% over "
          f"{totals['num_statements']} statements in {len(files)} file(s)")


def check(cov: dict) -> int:
    if not BASELINE.is_file():
        print(f"FAIL — no {BASELINE.name}. Run: scripts/coverage-run.sh && "
              "python3 scripts/coverage_gate.py --stamp")
        return 1
    base = json.loads(BASELINE.read_text(encoding="utf-8"))
    failures: list[str] = []

    # --- boundary ---------------------------------------------------------------------------
    exempt = exempt_paths()
    failures.extend(verify_exemptions(exempt))
    measured = set(cov["files"])
    expected = set(measurable())
    if not expected:
        print("FAIL — the tracked surface enumerated to nothing. UNDETECTABLE, not a pass.")
        return 1
    for path in sorted(expected - measured):
        failures.append(f"{path}: tracked, not exempt, and not measured — add it to the "
                        "coverage run or give it an exemption with a reason")
    for path in sorted(measured - expected):
        failures.append(f"{path}: measured but not on the tracked surface (stale coverage.json?)")

    # --- total floor ------------------------------------------------------------------------
    total = round(float(cov["totals"]["percent_covered"]), 2)
    floor = float(base["total_percent"])
    if total < floor:
        failures.append(f"TOTAL {total:.2f}% is below the {floor:.2f}% floor")

    # --- per-file no-regression -------------------------------------------------------------
    for path, was in sorted(base.get("files", {}).items()):
        if path not in cov["files"]:
            continue                      # deleted or newly exempt; the boundary check owns that
        now = file_pct(cov["files"][path])
        if now < float(was) - 0.005:      # tolerate float formatting, not a real drop
            failures.append(f"{path}: {now:.2f}% is below its own {float(was):.2f}% baseline")

    print(f"coverage: {total:.2f}% over {cov['totals']['num_statements']} statements in "
          f"{len(measured)} measured file(s); floor {floor:.2f}%; "
          f"{len(exempt)} file(s) exempt with a reason")

    if failures:
        print("\n  FAIL:")
        for f in failures:
            print(f"    ✗ {f}")
        print(f"\n{len(failures)} coverage gate failure(s)")
        return 1

    # --- ratchet ----------------------------------------------------------------------------
    if total > floor + RATCHET_SLACK:
        print(f"\n  FAIL: coverage rose to {total:.2f}%, more than {RATCHET_SLACK} point(s) above "
              f"the {floor:.2f}% floor — re-stamp so the floor keeps it:\n"
              "    scripts/coverage-run.sh && python3 scripts/coverage_gate.py --stamp")
        return 1

    print("coverage-gate: PASS")
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--stamp", action="store_true", help="rewrite the baseline from coverage.json")
    ap.add_argument("--list-surface", action="store_true",
                    help="print the measurable file list, one per line (used by coverage-run.sh)")
    args = ap.parse_args(argv)

    if args.list_surface:
        for path in measurable():
            print(path)
        return 0
    cov = load_coverage()
    if args.stamp:
        stamp(cov)
        return 0
    return check(cov)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
