#!/usr/bin/env python3
"""Conservatively normalize legacy free-text attribution_confidence values (#238).

The field is a categorical epistemic label, not a place for rationale. Exact legacy patterns are
collapsed to the lower defensible band; the original text moves to attribution_notes and every
changed page remains review-flagged. Non-attribution page types lose the inapplicable field.
Unknown values fail closed into the reject report instead of being guessed.
"""
from __future__ import annotations

import argparse
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

import yaml


CANONICAL = ("confirmed", "high", "moderate", "low", "suspected", "unverified")
EXACT_ALIASES = {
    "unconfirmed": "unverified",
    "very-high": "high",
    "medium-high": "moderate",
    "medium-high-professional-tracking-frameworks": "moderate",
    "low-moderate": "low",
    "suspected low_to_medium_range": "suspected",
}
NON_ATTRIBUTION_TYPES = frozenset({"vulnerability", "vulnerability_discovery", "cve"})


def normalize(value: Any, page_type: Any) -> tuple[str | None, str] | None:
    """Return (replacement-or-None, reason), or None when human mapping is required."""
    raw = str(value or "").strip()
    folded = raw.casefold()
    if folded in CANONICAL:
        return CANONICAL[CANONICAL.index(folded)], "canonical"
    if str(page_type or "").casefold() in NON_ATTRIBUTION_TYPES:
        return None, "remove-inapplicable"
    if folded in EXACT_ALIASES:
        return EXACT_ALIASES[folded], "legacy-alias"
    if folded.startswith("suspected —"):
        return "suspected", "rationale-split"
    if folded.startswith("low-medium —"):
        return "low", "lower-bound-and-rationale-split"
    return None


def _read(path: Path) -> tuple[dict[str, Any], str] | None:
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---"):
        return None
    end = text.find("\n---", 3)
    if end < 0:
        return None
    fm = yaml.safe_load(text[3:end]) or {}
    return (fm, text[end + 4:].lstrip("\n")) if isinstance(fm, dict) else None


def _write_atomic(path: Path, fm: dict[str, Any], body: str) -> None:
    head = yaml.safe_dump(fm, sort_keys=False, allow_unicode=True,
                          default_flow_style=False).rstrip()
    descriptor, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent, text=True)
    temp = Path(temp_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(f"---\n{head}\n---\n\n{body.rstrip()}\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)


def drain_page(path: Path, *, dry_run: bool = False) -> tuple[str, str]:
    parsed = _read(path)
    if parsed is None:
        return "skip", "no-frontmatter"
    fm, body = parsed
    if "attribution_confidence" not in fm:
        return "skip", "absent"
    raw = str(fm["attribution_confidence"]).strip()
    result = normalize(raw, fm.get("type"))
    if result is None:
        return "reject", raw
    replacement, reason = result
    if reason == "canonical":
        return "skip", "canonical"
    if replacement is None:
        fm.pop("attribution_confidence", None)
    else:
        fm["attribution_confidence"] = replacement
        prior = str(fm.get("attribution_notes") or "").strip()
        audit_note = f"Legacy attribution label normalized from: {raw}"
        fm["attribution_notes"] = f"{prior} {audit_note}".strip()
    fm["needs_review"] = True
    if not dry_run:
        _write_atomic(path, fm, body)
    return "change", reason


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vault", type=Path,
                        default=Path(os.environ.get("WIKI_PATH", "/opt/vault")))
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    root = args.vault / "wiki" / "entities"
    changed = rejected = 0
    for path in sorted(root.rglob("*.md")) if root.is_dir() else []:
        state, detail = drain_page(path, dry_run=args.dry_run)
        if state == "change":
            changed += 1
        elif state == "reject":
            rejected += 1
            print(f"REJECT {path.relative_to(args.vault)}: {detail}", file=sys.stderr)
    mode = "would change" if args.dry_run else "changed"
    print(f"attribution-confidence-drain: {mode} {changed}; rejected {rejected}")
    return 1 if rejected else 0


if __name__ == "__main__":
    raise SystemExit(main())
