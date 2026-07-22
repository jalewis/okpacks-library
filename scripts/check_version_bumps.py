#!/usr/bin/env python3
"""okpacks#29 — schema changes require a pack version bump + changelog entry.

The schema CONTRACT of a pack is what installed vaults and composed bundles depend on:
`schema.yaml` and (for composable packs) `subdomain/host-schema-additions.yaml`. A change to
either without a version bump ships silently — operators can't tell an update carries migration
impact. This gate makes the convention (VERSIONING.md) machine-checked:

  R1  schema-contract files must be UNCHANGED since the commit that introduced the pack's
      current `version:` — schema churn after a release requires a new bump.
  R2  the current version must appear as a heading in the pack's CHANGELOG.md.
  R3  when the current version's own bump commit touched schema-contract files, its CHANGELOG
      section must state the migration impact (a line containing "igration" — "Migration
      impact: none" is fine for additive changes).
  R4  the topmost numeric version heading in CHANGELOG.md must equal pack.yaml's version —
      a changelog documenting a release the pack.yaml never shipped (or vice versa) is drift
      (this caught okpack-cti: CHANGELOG at 0.3.1, pack.yaml still 0.3.0).

Needs real git history (the bump commit may be old): CI sets GIT_DEPTH: "0" on the job. When
history is truncated the affected rule WARNs "undetectable" (never a vacuous pass) but does not
fail — a fresh full clone will enforce it.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONTRACT = ("schema.yaml", "subdomain/host-schema-additions.yaml")


def git(*args: str) -> str:
    return subprocess.run(["git", "-C", str(ROOT), *args],
                          capture_output=True, text=True, check=False).stdout.strip()


def pack_version(pack: Path) -> str | None:
    m = re.search(r"^version:\s*[\"']?([0-9][^\s\"']*)", (pack / "pack.yaml").read_text(), re.M)
    return m.group(1) if m else None


def changelog_section(pack: Path, version: str) -> str | None:
    """The CHANGELOG body under the current version's heading, or None if the heading is absent."""
    p = pack / "CHANGELOG.md"
    if not p.is_file():
        return None
    text = p.read_text(encoding="utf-8")
    m = re.search(rf"^##[^\n]*{re.escape(version)}[^\n]*\n(.*?)(?=^## |\Z)", text, re.M | re.S)
    return m.group(1) if m else None


def top_changelog_version(pack: Path) -> str | None:
    p = pack / "CHANGELOG.md"
    if not p.is_file():
        return None
    for line in p.read_text(encoding="utf-8").splitlines():
        m = re.match(r"^##\s*\[?v?([0-9]+\.[0-9]+[^\s\]—-]*)", line)
        if m:
            return m.group(1)
    return None


def main() -> int:
    fails: list[str] = []
    warns: list[str] = []
    for pack in sorted(ROOT.glob("packs/*")):
        if not (pack / "pack.yaml").is_file():
            continue
        name, rel = pack.name, pack.relative_to(ROOT)
        ver = pack_version(pack)
        if not ver:
            fails.append(f"{name}: pack.yaml has no parseable `version:`")
            continue

        # the commit that introduced the CURRENT version string in pack.yaml
        bump = git("log", "-1", "--format=%H", "-S", f"version: {ver}", "--", f"{rel}/pack.yaml")
        contract = [f"{rel}/{c}" for c in CONTRACT if (pack / c).is_file()]

        if not bump:
            warns.append(f"{name}: cannot locate the commit introducing version {ver} "
                         f"(shallow clone?) — R1/R3 UNDETECTABLE, not a pass")
        elif contract:
            # R1 — no schema-contract drift since the bump
            drift = git("diff", "--name-only", f"{bump}..HEAD", "--", *contract)
            if drift:
                fails.append(f"{name}: schema contract changed since version {ver} was set "
                             f"({', '.join(drift.split())}) — bump `version:` in pack.yaml "
                             f"(see VERSIONING.md) and document it in CHANGELOG.md")

        # R4 — the changelog's newest release is the shipped version
        top = top_changelog_version(pack)
        if top is not None and top != ver:
            fails.append(f"{name}: CHANGELOG's newest version heading is {top} but pack.yaml "
                         f"ships {ver} — reconcile them (bump pack.yaml or fix the heading)")

        # R2 — the version is documented
        section = changelog_section(pack, ver)
        if section is None:
            fails.append(f"{name}: CHANGELOG.md has no `## {ver}` section — every released "
                         f"version documents its changes (VERSIONING.md)")
        elif bump and contract:
            # R3 — a schema-touching bump states its migration impact
            parent = git("rev-parse", "--quiet", "--verify", f"{bump}^")
            if parent:
                in_bump = git("diff", "--name-only", f"{parent}..{bump}", "--", *contract)
                if in_bump and "igration" not in section:
                    fails.append(f"{name}: version {ver} changed the schema contract but its "
                                 f"CHANGELOG section has no migration-impact line "
                                 f"(add e.g. `Migration impact: none — additive only`)")

    for w in warns:
        print(f"  WARN  {w}")
    if fails:
        print("version-bump-check: FAIL — schema/versioning convention violations (okpacks#29):")
        for f in fails:
            print(f"  - {f}")
        return 1
    print(f"version-bump-check: PASS ({sum(1 for _ in ROOT.glob('packs/*/pack.yaml'))} packs)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
