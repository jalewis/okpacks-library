#!/usr/bin/env python3
"""Offline validator for the okpack-sec BUNDLE (okengine#181).

A bundle owns no types and ships no schema.yaml — so it can't run the standard per-pack schema
validator. Instead it validates its RECIPE: owns-nothing, a `host`, a non-empty `compose` list that
excludes the host, and every recipe member declared in `requires`. Mirrors the engine's
scripts/pack_meta.validate_bundle_recipe + framework_validate bundle path. No network; stdlib+PyYAML.

Exit: 0 = valid · 1 = a recipe error.
"""
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent


def main() -> int:
    meta = yaml.safe_load((ROOT / "pack.yaml").read_text(encoding="utf-8")) or {}
    errs: list[str] = []
    if meta.get("kind") != "bundle":
        errs.append("pack.yaml `kind` must be `bundle`")
    owns = meta.get("owns") or {}
    if owns.get("types") or owns.get("namespaces"):
        errs.append("a bundle must own nothing (owns.types/namespaces must be empty)")
    recipe = meta.get("bundle") or {}
    host = recipe.get("host")
    compose = recipe.get("compose") or []
    if not host:
        errs.append("bundle.host is missing")
    if not compose:
        errs.append("bundle.compose is empty")
    if host and host in compose:
        errs.append(f"bundle.compose must not contain the host {host!r}")
    if len(set(compose)) != len(compose):
        errs.append("bundle.compose has duplicate entries")
    reqs = {str(r).split("@", 1)[0] for r in (meta.get("requires") or [])}
    for m in ([host] if host else []) + list(compose):
        if m not in reqs:
            errs.append(f"recipe member {m!r} is not declared in `requires`")

    name = meta.get("name", "okpack-sec")
    if errs:
        for e in errs:
            print(f"FAIL  {name}: {e}")
        print(f"\n{name} bundle recipe INVALID — {len(errs)} error(s).")
        return 1
    print(f"OK — {name} bundle valid: host {host} + composes {len(compose)} pack(s) "
          f"({', '.join(compose)}).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
