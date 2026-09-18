#!/usr/bin/env bash
# Run every assertion-bearing test lane under coverage and emit coverage.json (okengine#601).
#
# Two lanes, two shapes: packs/*/tests + tests/ are pytest; each pack's conformance suite is a
# standalone script run from inside the pack dir (see conformance-all.sh). Both are measured,
# combined, and reported against an EXPLICIT file list -- see the note in .coveragerc for why
# `source =` cannot be used here.
#
# What is NOT measured: scripts/validate-all.sh. Those validators are executed by the validate
# lane, so running them here would raise the number without a single new assertion behind it.
# Coverage should reflect what the tests exercise.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
PY="${PYTHON:-python3}"

# The measurement must be reproducible from any checkout, so it is taken WITHOUT an engine.
# tests/test_prompt_bindings.py asserts against a real engine when ENGINE_DIR is set and skips
# visibly when it is not; leaving that to the ambient environment would make the baseline depend
# on whether the person running it happens to have an engine checkout exported, and the per-file
# floor would then fail for whoever does not.
unset ENGINE_DIR OKENGINE_DIR

export COVERAGE_FILE="$ROOT/.coverage"
rm -f "$ROOT"/.coverage "$ROOT"/.coverage.*

fail=0
echo "==> pytest lanes"
"$PY" -m coverage run -m pytest -q -o addopts= --strict-markers packs/*/tests tests || fail=1

echo "==> conformance lanes"
shopt -s nullglob
ran=0
for d in "$ROOT"/packs/*/; do
  [ -d "${d}conformance" ] || continue
  for s in "${d}conformance"/run_*.py "${d}conformance"/test_*.py; do
    ran=1
    ( cd "$d" && COVERAGE_RCFILE="$ROOT/.coveragerc" "$PY" -m coverage run \
        "conformance/$(basename "$s")" >/dev/null 2>&1 ) || {
      echo "   FAIL: $(basename "$(dirname "${s%/*}")")/$(basename "$s")"; fail=1; }
  done
done
[ "$ran" = 1 ] || { echo "no conformance suite ran -- UNDETECTABLE, not a pass"; exit 1; }

echo "==> combine + report"
"$PY" -m coverage combine -q || fail=1

# The measured surface, enumerated rather than discovered. An empty list is a failure: it means
# the layout moved and the gate is about to measure nothing.
mapfile -t FILES < <("$PY" "$ROOT/scripts/coverage_gate.py" --list-surface)
[ "${#FILES[@]}" -gt 0 ] || { echo "no measurable files enumerated -- UNDETECTABLE, not a pass"; exit 1; }

"$PY" -m coverage json -q -o "$ROOT/coverage.json" "${FILES[@]}" || fail=1
"$PY" -m coverage report "${FILES[@]}" | tail -3

exit "$fail"
