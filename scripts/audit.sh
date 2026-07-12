#!/usr/bin/env bash
# Security audit (okpacks-library#44): dependency CVE scan + Python SAST.
#
# Two gates, mirroring the okengine pre-publish standard:
#   1) pip-audit — audits the declared dependencies against the PyPA advisory DB (known CVEs).
#   2) bandit    — static analysis for common Python security issues (shell=True, weak crypto,
#                  unsafe yaml/pickle, etc.) across this repo's own Python (scripts/ + packs/).
#
# Exits nonzero if either gate finds something, so CI's `audit` job fails on a real issue.
# Run locally or via `okpacks audit`. Needs requirements-dev.txt installed (pip-audit, bandit) —
# `okpacks bootstrap` installs them; in a bare checkout: pip install -r requirements-dev.txt.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
fail=0

echo "==> pip-audit (dependency CVE scan)"
if command -v pip-audit >/dev/null 2>&1; then
  # Audit both requirement sets; requirements-dev.txt pulls in requirements.txt via -r.
  #
  # Tracked ignore — GHSA-537c-gmf6-5ccf (cryptography <48.0.1 wheels bundle a vulnerable OpenSSL):
  #   * dev/conformance-ONLY transitive dep (pulled by py-ocsf-models/stix2); NOT in any pack's
  #     runtime (requirements.txt = PyYAML only) and NOT in the published snapshot.
  #   * The 48.0.1 fix is unreachable: py-ocsf-models (latest 0.9.0) hard-caps cryptography<47, so
  #     pinning the fix makes the dev env unresolvable. Drop this ignore once py-ocsf-models lifts
  #     the cap (re-check: `pip index versions py-ocsf-models`).
  pip-audit -r requirements.txt -r requirements-dev.txt \
    --ignore-vuln GHSA-537c-gmf6-5ccf || fail=1
else
  echo "ERROR: pip-audit not installed — run 'pip install -r requirements-dev.txt'."; fail=1
fi

echo
echo "==> bandit (Python SAST — medium+ severity)"
if command -v bandit >/dev/null 2>&1; then
  # Scan our own Python only; exclude the virtualenv and bytecode caches.
  bandit -ll -r scripts packs -x '.venv,*/__pycache__/*' || fail=1
else
  echo "ERROR: bandit not installed — run 'pip install -r requirements-dev.txt'."; fail=1
fi

echo
if [ "$fail" -ne 0 ]; then
  echo "❌ audit found issues — see above."; exit 1
fi
echo "✅ audit clean — no known-vulnerable deps, no medium+ SAST findings."
