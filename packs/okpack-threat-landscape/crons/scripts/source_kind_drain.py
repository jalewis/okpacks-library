#!/usr/bin/env python3
"""Normalize legacy source-kind aliases to the core cross-pack vocabulary (#238)."""
from __future__ import annotations

import argparse
import os
import sys
import tempfile
from pathlib import Path

import yaml


ALIASES = {
    "annual-report": "report",
    "blog-post": "post",
    "security_news": "news",
    "news-article": "news",
}


def drain_page(path: Path, *, dry_run: bool = False) -> tuple[str, str]:
    text = path.read_text(encoding="utf-8")
    end = text.find("\n---", 3) if text.startswith("---") else -1
    if end < 0:
        return "skip", "no-frontmatter"
    fm = yaml.safe_load(text[3:end]) or {}
    if not isinstance(fm, dict):
        return "skip", "invalid-frontmatter"
    raw = str(fm.get("source_kind") or "").strip()
    replacement = ALIASES.get(raw)
    if replacement is None:
        return "skip", "canonical-or-unmanaged"
    fm["source_kind"] = replacement
    if not dry_run:
        head = yaml.safe_dump(fm, sort_keys=False, allow_unicode=True,
                              default_flow_style=False).rstrip()
        descriptor, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent, text=True)
        temp = Path(temp_name)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(f"---\n{head}\n---\n\n{text[end + 4:].lstrip(chr(10)).rstrip()}\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp, path)
        finally:
            temp.unlink(missing_ok=True)
    return "change", f"{raw}->{replacement}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vault", type=Path,
                        default=Path(os.environ.get("WIKI_PATH", "/opt/vault")))
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    root = args.vault / "wiki" / "sources"
    changed = 0
    for path in sorted(root.rglob("*.md")) if root.is_dir() else []:
        state, _ = drain_page(path, dry_run=args.dry_run)
        changed += state == "change"
    mode = "would change" if args.dry_run else "changed"
    print(f"source-kind-drain: {mode} {changed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
