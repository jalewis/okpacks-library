#!/usr/bin/env python3
"""Every vendored validate.py is byte-identical to the engine skeleton (okengine#606).

A pack ships its own `validate.py` because it must validate standalone and offline — the pack is
a distributable artifact and cannot import a repo-level module that will not travel with it. That
is a good reason for vendoring and a bad situation to leave unchecked: the copies drift, and the
only thing watching them was a hand-maintained `VALIDATE_VERSION` stamp.

The stamp did not work, in the way hand-maintained stamps do not. Four distinct contents shipped
under `2026.07.3` across the engine skeleton and the pack repos, each carrying a fix the others
lacked:

  - the okengine#178 `@jitter` supported-base check: present in six copies, missing from four, so
    an unsupported `@jitter:3h` would pass validation in those four and then silently never fire;
  - https-only feed probing: in the pack copies, absent from the skeleton;
  - string-form `schedule` handling and `@jitter:<base>@<suffix>` stripping: only in the skeleton.

All four claimed the same vintage, so a stamp comparison said they agreed.

The fix was to make the file name-agnostic — the two `{{PACK}}` literals became `PACK_NAME =
ROOT.name` — so one byte-identical file serves every pack and the skeleton, and identity becomes
checkable. This is that check. It is the reason the coverage gate may exempt nine of the ten
copies: they are provably the same bytes as the one it measures.

Bundle packs are exempt: a bundle owns no types and ships no schema.yaml, so it carries a recipe
validator that is legitimately a different file (okengine#181).
"""
from __future__ import annotations

import hashlib
import os
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent


def digest(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()[:12]


def is_bundle(pack: pathlib.Path) -> bool:
    meta = pack / "pack.yaml"
    if not meta.is_file():
        return False
    for line in meta.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.strip().replace('"', "").replace("'", "") == "kind: bundle":
            return True
    return False


def vendored(packs_root: pathlib.Path) -> list[pathlib.Path]:
    return sorted(p / "validate.py" for p in packs_root.iterdir()
                  if p.is_dir() and (p / "validate.py").is_file() and not is_bundle(p))


def check(packs_root: pathlib.Path, skeleton: pathlib.Path | None) -> tuple[list[str], int]:
    copies = vendored(packs_root)
    if not copies:
        return ([f"no vendored validate.py found under {packs_root} — the layout moved, so "
                 "drift is UNDETECTABLE, not absent"], 0)

    failures: list[str] = []
    # Mutual identity first: it holds with or without an engine checkout, so a developer without
    # one still gets the half of the check this repo can answer alone.
    by_digest: dict[str, list[str]] = {}
    for path in copies:
        by_digest.setdefault(digest(path), []).append(str(path.relative_to(ROOT)))
    if len(by_digest) > 1:
        failures.append("vendored validators are not identical to each other:")
        for d, paths in sorted(by_digest.items()):
            failures.append(f"    {d}  {', '.join(paths)}")

    if skeleton is None:
        print("vendored-validators: engine skeleton not available — identity vs the SKELETON is "
              "UNDETECTABLE (set ENGINE_DIR=<engine checkout>)")
        if os.environ.get("CI"):
            failures.append("this is a required check in CI and half of it could not run")
    else:
        skel = digest(skeleton)
        off = sorted(str(p.relative_to(ROOT)) for p in copies if digest(p) != skel)
        if off:
            failures.append(
                f"vendored validators differ from the engine skeleton ({skel}) — re-copy "
                f"{skeleton} verbatim (it is name-agnostic by design):")
            failures.extend(f"    {p}" for p in off)

    return failures, len(copies)


def main(argv: list[str]) -> int:
    packs_root = pathlib.Path(argv[0]) if argv else ROOT / "packs"
    engine = os.environ.get("ENGINE_DIR") or os.environ.get("OKENGINE_DIR")
    skeleton = None
    if engine:
        candidate = pathlib.Path(engine) / "templates" / "pack" / "skeleton" / "validate.py"
        if candidate.is_file():
            skeleton = candidate

    failures, count = check(packs_root, skeleton)
    print(f"vendored-validators: {count} vendored validate.py checked"
          + (f" against {skeleton}" if skeleton else ""))
    if failures:
        print("\n  FAIL:")
        for f in failures:
            print(f"    ✗ {f}" if not f.startswith("    ") else f)
        return 1
    print("vendored-validators: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
