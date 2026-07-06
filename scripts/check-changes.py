#!/usr/bin/env python3
"""Changelog drift check (okpacks-library#28).

Flags a pack whose DEFINITION/contract changed vs a base ref without a matching `CHANGELOG.md`
update — the missing-changelog-entry gap that today relies on reviewer discipline. "Definition" means
the contract a consumer depends on: `schema.yaml`, `pack.yaml`, `CLAUDE.md` (persona), `projectors/`,
and any `*-SPEC.md`. Tooling (importers/conformance/README) is intentionally NOT gated.

Advisory by default; `--strict` fails. Run via `okpacks changes [--base REF] [--strict]`
(default base: origin/main). Most useful on a feature branch / pre-merge; a no-op on an unchanged
tree.
"""
import argparse
import re
import subprocess
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFN = re.compile(r"^packs/([^/]+)/(schema\.yaml|pack\.yaml|CLAUDE\.md|projectors/|[A-Z0-9]+-SPEC\.md)")
CHANGELOG = re.compile(r"^packs/([^/]+)/CHANGELOG\.md$")


def changed_files(base: str) -> list[str] | None:
    try:
        out = subprocess.run(["git", "-C", str(ROOT), "diff", "--name-only", base, "--"],
                             capture_output=True, text=True, check=True).stdout
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None
    return [ln for ln in out.splitlines() if ln.strip()]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Flag pack contract changes missing a CHANGELOG update (#28).")
    ap.add_argument("--base", default="origin/main", help="git ref to diff against (default origin/main)")
    ap.add_argument("--strict", action="store_true", help="exit nonzero on drift")
    args = ap.parse_args(argv)

    files = changed_files(args.base)
    if files is None:
        print(f"changes: base ref '{args.base}' not available — skipping (fetch it to run the check).")
        return 0

    defn_by_pack: dict[str, set[str]] = defaultdict(set)
    changelog_touched: set[str] = set()
    for f in files:
        m = DEFN.match(f)
        if m:
            defn_by_pack[m.group(1)].add(m.group(2).rstrip("/"))
        cm = CHANGELOG.match(f)
        if cm:
            changelog_touched.add(cm.group(1))

    drift = [(pk, sorted(ch)) for pk, ch in sorted(defn_by_pack.items()) if pk not in changelog_touched]
    for pk, ch in drift:
        print(f"WARN  {pk}: contract changed ({', '.join(ch)}) but CHANGELOG.md was not updated")

    if not drift:
        print(f"changes: no changelog drift vs {args.base} "
              f"({len(defn_by_pack)} pack(s) with contract changes, all have CHANGELOG updates).")
        return 0
    if args.strict:
        print(f"\n{len(drift)} pack(s) with changelog drift (--strict).")
        return 1
    print(f"\n{len(drift)} pack(s) changed their contract without a CHANGELOG entry (advisory — "
          f"add an [Unreleased] note, or pass --base if comparing the wrong ref).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
