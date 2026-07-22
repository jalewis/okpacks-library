#!/usr/bin/env python3
"""okpack-vuln — severity vocabulary normalizer (no_agent, ZERO LLM tokens).

Agent-authored `severity` values sometimes carry descriptive free-text — e.g. a compile agent writes
`critical (unauthenticated RCE exploit)` instead of the canonical CVSS band `critical`. Making the
enum strict would REJECT the whole page write (dropping the source); instead this lane SELF-HEALS on
scan: for any page whose `severity` sits outside the governing schema's `enums.severity` but
unambiguously contains exactly ONE canonical band token, it coerces the value to that band. Values
with zero or >1 band tokens are left untouched for corpus_audit to flag — the lane never GUESSES.

Reads the sanctioned band list from the vault's own schema.yaml (`enums.severity`), so it can't drift
from the contract. SET semantics, idempotent, MERGE-safe (body + all other frontmatter preserved).

Env: WIKI_PATH (/opt/vault)
Usage: severity_normalize.py [--vault DIR] [--dry-run]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

import yaml

_FM_RE = re.compile(r"\A---[ \t]*\n(.*?\n)---[ \t]*\n?(.*)\Z", re.S)
_DEFAULT_BANDS = ["critical", "high", "medium", "low", "none"]


def _content_root(vault: Path) -> Path:
    return vault / "wiki" if (vault / "wiki").is_dir() else vault


def _split(p: Path) -> tuple[dict, str]:
    try:
        txt = p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {}, ""
    m = _FM_RE.match(txt)
    if not m:
        return {}, ""
    try:
        fm = yaml.safe_load(m.group(1))
    except yaml.YAMLError:
        fm = None
    return (fm if isinstance(fm, dict) else {}), (m.group(2) or "")


def _bands(vault: Path) -> list[str]:
    """Canonical severity vocabulary from the vault's schema.yaml (else the CVSS default)."""
    sp = vault / "schema.yaml"
    try:
        sch = yaml.safe_load(sp.read_text(encoding="utf-8")) or {}
        vals = ((sch.get("enums") or {}).get("severity"))
        if isinstance(vals, list) and vals:
            return [str(v) for v in vals]
    except (OSError, yaml.YAMLError):
        pass
    return _DEFAULT_BANDS


def coerce(value, bands) -> "str | None":
    """The canonical band for a free-text severity, or None to leave it alone (already canonical, or
    zero/ambiguous band tokens — never guessed). Pure; unit-testable."""
    v = str(value).strip()
    lower = {b.lower(): b for b in bands}
    if v.lower() in lower:
        return None                                    # already canonical
    toks = set(re.findall(r"[a-z]+", v.lower()))       # word tokens, so "critical" matches but
    hits = [lower[b] for b in lower if b in toks]      # "critically" (not a token) does not
    return hits[0] if len(hits) == 1 else None


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--vault", default=os.environ.get("WIKI_PATH", "/opt/vault"))
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)
    vault = Path(args.vault)
    wiki = _content_root(vault)
    bands = _bands(vault)

    fixed = skipped = 0
    for p in wiki.rglob("*.md"):
        if p.stem.startswith(("INDEX", "_")):
            continue
        fm, body = _split(p)
        if not fm or "severity" not in fm or fm["severity"] is None:
            continue
        band = coerce(fm["severity"], bands)
        if band is None:
            if str(fm["severity"]).strip().lower() not in {b.lower() for b in bands}:
                skipped += 1                            # off-enum but not safely coercible
            continue
        rel = p.relative_to(wiki)
        if args.dry_run:
            print(f"  WOULD coerce {rel}: {fm['severity']!r} -> {band!r}")
            fixed += 1
            continue
        fm["severity"] = band
        head = yaml.safe_dump(fm, sort_keys=False, allow_unicode=True).rstrip()
        try:
            p.write_text(f"---\n{head}\n---\n\n{body.strip()}\n", encoding="utf-8")
            fixed += 1
        except OSError as e:
            print(f"WARN: {rel}: {e}", file=sys.stderr)

    print(f"severity-normalize: {fixed} value(s) coerced to a canonical band, "
          f"{skipped} off-enum value(s) left for corpus_audit (not safely coercible)"
          f"{' [dry-run]' if args.dry_run else ''}")
    print(json.dumps({"wakeAgent": False}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
