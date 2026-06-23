#!/usr/bin/env python3
"""Vendor scripts/pack_validate_lib.py into each pack as _pack_validate_lib.py (okpacks-library#17).

Packs deploy STANDALONE (just packs/<name>/), so each carries a copy of the shared validator lib.
scripts/pack_validate_lib.py is the single source of truth; run this after editing it to re-vendor.
`--check` (wired into scripts/validate-all.sh and CI) verifies every pack's copy matches the
canonical and exits nonzero on drift, instead of writing — so a stale copy can never ship.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CANON = ROOT / "scripts" / "pack_validate_lib.py"
VENDORED = "_pack_validate_lib.py"


def pack_dirs() -> list[Path]:
    return [d for d in sorted((ROOT / "packs").iterdir())
            if d.is_dir() and (d / "validate.py").exists()]


def main() -> int:
    check = "--check" in sys.argv
    canon = CANON.read_text(encoding="utf-8")
    packs = pack_dirs()
    drift: list[str] = []
    for d in packs:
        dst = d / VENDORED
        if check:
            if not dst.exists():
                drift.append(f"{d.name}: {VENDORED} missing")
            elif dst.read_text(encoding="utf-8") != canon:
                drift.append(f"{d.name}: {VENDORED} out of sync with scripts/pack_validate_lib.py")
        else:
            dst.write_text(canon, encoding="utf-8")
            print(f"synced {d.name}/{VENDORED}")
    if check:
        if drift:
            print("validator-lib sync FAILED:")
            for x in drift:
                print(f"  - {x}")
            print("  fix: python3 scripts/sync-validate-lib.py")
            return 1
        print(f"validator lib in sync across {len(packs)} pack(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
