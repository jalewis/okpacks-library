#!/usr/bin/env bash
# Validate every pack definition in packs/ with its own offline validate.py.
# Run locally or in CI. Exit 1 if any pack fails.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fail=0
# Each pack vendors its own validate.py because a pack must validate STANDALONE and OFFLINE — it
# is a distributable artifact and cannot import a repo-level module that will not travel with it.
# The copies are therefore byte-identical to the engine skeleton, which is name-agnostic
# (PACK_NAME = ROOT.name, no {{PACK}} substitution); check_vendored_validators.py below enforces
# that identity, because the VALIDATE_VERSION stamp did not (okengine#606: four distinct contents
# shipped under one stamp). Bundle packs are exempt — they ship a recipe validator instead.
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
echo "==> engine-template prompt contract (action directive; echo-class reported)"
python3 "$ROOT/scripts/lint_prompts.py" "$ROOT/packs" || fail=1
# Needs the engine: a prompt is keyed by a job name this repo cannot see (okengine#562).
# Without ENGINE_DIR the script SAYS it could not check rather than reporting a pass.
echo "==> prompt bindings (keys resolve to a live lane; writer names match what it binds)"
python3 "$ROOT/scripts/check_prompt_bindings.py" "$ROOT/packs" || fail=1
echo "==> vendored validators are byte-identical (to each other, and to the engine skeleton)"
python3 "$ROOT/scripts/check_vendored_validators.py" "$ROOT/packs" || fail=1
if [ "$fail" = 0 ]; then
  echo "all packs valid"
else
  echo "one or more packs failed validation"
  exit 1
fi
