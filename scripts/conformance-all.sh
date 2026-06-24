#!/usr/bin/env bash
# Run each pack's conformance suite, if it ships one.
#
# A pack opts in by shipping a conformance/ dir with runnable entrypoints
# (run_*.py / test_*.py) that exit nonzero on failure — e.g. the okpack-sec standard's
# STIX 2.1 + OCSF projector proofs, validated against the standards' official libraries
# (stix2, py-ocsf-models). Those libs are optional: a suite degrades to structural +
# golden checks when they're absent, and runs the full official validation when present
# (CI installs them). Run locally or in CI; exits 1 if any suite fails.
#
# Degraded mode (okpacks-library#19): without the official validators the suites still run
# structural+golden, but that is NOT full conformance. By default this prints an unmistakable
# degraded banner; pass --strict (or set OKPACK_STRICT_CONFORMANCE=1) to FAIL instead — CI uses
# --strict so a missing validator can never silently pass.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fail=0
ran=0
strict=0
if [ "${1:-}" = "--strict" ] || [ "${OKPACK_STRICT_CONFORMANCE:-0}" = "1" ]; then strict=1; fi
have_stix2=1; python3 -c "import stix2" 2>/dev/null || have_stix2=0
have_ocsf=1;  python3 -c "import py_ocsf_models" 2>/dev/null || have_ocsf=0
shopt -s nullglob
for d in "$ROOT"/packs/*/; do
  name="$(basename "$d")"
  [ -d "${d}conformance" ] || continue
  entries=("${d}conformance"/run_*.py "${d}conformance"/test_*.py)
  if [ ${#entries[@]} -eq 0 ]; then
    echo "WARN: $name has conformance/ but no run_*/test_* entrypoints — skipping"
    continue
  fi
  echo "==> $name conformance"
  for s in "${entries[@]}"; do
    ran=1
    echo "   - $(basename "$s")"
    # run from the pack root so the suite's `sys.path` (pack root) resolves its imports
    ( cd "$d" && python3 "conformance/$(basename "$s")" ) || fail=1
  done
done
if [ "$ran" = 0 ]; then
  echo "no pack ships a conformance/ suite — nothing to run"
  exit 0
fi
if [ "$fail" != 0 ]; then
  echo "one or more conformance suites failed"
  exit 1
fi

# Suites passed — but distinguish full-strength from degraded (okpacks-library#19).
if [ "$have_stix2" = 0 ] || [ "$have_ocsf" = 0 ]; then
  echo
  echo "⚠️  DEGRADED CONFORMANCE — suites passed structural + golden only (official validators missing):"
  [ "$have_stix2" = 0 ] && echo "      • stix2 (official STIX 2.1 validation) not installed"
  [ "$have_ocsf" = 0 ]  && echo "      • py-ocsf-models (official OCSF validation) not installed"
  echo "      Run full-strength:  pip install -r requirements-dev.txt"
  if [ "$strict" = 1 ]; then
    echo "      (--strict / OKPACK_STRICT_CONFORMANCE=1) → FAILING."
    exit 1
  fi
  echo "      Pass --strict to fail on this. CI installs the validators and runs full-strength."
  exit 0
fi
echo "all conformance suites pass (official validators present — full-strength)"
