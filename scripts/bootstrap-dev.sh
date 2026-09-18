#!/usr/bin/env bash
# One-command dev setup + full check (okpacks-library#21).
#
# Creates a local virtualenv (.venv), installs the declared dev dependencies (requirements-dev.txt —
# PyYAML + the official standards validators stix2/py-ocsf-models), and runs the SAME path CI runs:
# per-pack validation + the library gate (validate-all) and FULL conformance (conformance-all
# --strict). --strict means a missing official validator fails here instead of silently degrading,
# so a green run locally == a green run in CI.
#
# A virtualenv (not a system install) keeps this working on PEP-668 externally-managed Pythons.
# Usage: scripts/bootstrap-dev.sh   (or: okpacks bootstrap)
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV="$ROOT/.venv"

echo "==> dev virtualenv ($VENV)"
if [ ! -x "$VENV/bin/python3" ]; then
  python3 -m venv "$VENV" || { echo "ERROR: could not create virtualenv (need python3-venv)."; exit 1; }
fi
# shellcheck disable=SC1091
. "$VENV/bin/activate"

echo "==> installing dev dependencies (requirements-dev.txt)"
python3 -m pip install -q --upgrade pip >/dev/null 2>&1 || true
if ! python3 -m pip install -q -r "$ROOT/requirements-dev.txt"; then
  echo "ERROR: pip install failed — see above."
  exit 1
fi

# Run validation + conformance with the venv active, so conformance finds stix2/py-ocsf-models.
echo "==> validate-all (per-pack + library gate)"
bash "$ROOT/scripts/validate-all.sh" || { echo "ERROR: validation failed."; exit 1; }

echo "==> conformance (full-strength — --strict)"
bash "$ROOT/scripts/conformance-all.sh" --strict || { echo "ERROR: conformance failed."; exit 1; }

echo
echo "✅ bootstrap complete — full validation + full conformance passed (same as CI)."
echo "   Re-activate later with:  . $VENV/bin/activate"
