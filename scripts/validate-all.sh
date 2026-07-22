#!/usr/bin/env bash
# Validate every pack definition in packs/ with its own offline validate.py.
# Run locally or in CI. Exit 1 if any pack fails.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fail=0
# The shared validator lib (scripts/pack_validate_lib.py) is vendored into each pack as
shopt -s nullglob
for d in "$ROOT"/packs/*/; do
  name="$(basename "$d")"
  if [ ! -f "$d/validate.py" ]; then
    echo "WARN: $name has no validate.py — skipping"
    continue
  fi
  echo "==> $name"
  ( cd "$d" && python3 validate.py ) || fail=1
done
echo "==> library (catalog + cross-pack invariants)"
python3 "$ROOT/scripts/validate-library.py" || fail=1
echo "==> pack quality / readiness (fixture coverage)"
python3 "$ROOT/scripts/pack_quality.py" || fail=1
echo "==> versioning convention (schema changes require a bump + changelog — okpacks#29)"
python3 "$ROOT/scripts/check_version_bumps.py" || fail=1
if [ "$fail" = 0 ]; then
  echo "all packs valid"
else
  echo "one or more packs failed validation"
  exit 1
fi
