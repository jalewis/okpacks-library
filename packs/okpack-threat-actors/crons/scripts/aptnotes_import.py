#!/usr/bin/env python3
"""okpack-threat-actors — APTnotes historical report seed (no_agent, ZERO LLM tokens).

RSS is forward-only; this backfills HISTORY. APTnotes (github.com/aptnotes/data) is a curated JSON
index of ~689 public vendor APT reports going back to 2006 — the CTI-native historical corpus. This
lane writes one `source` page per report (title, vendor, date, link) and — the value-add — matches
each report TITLE against the vault's known actor aliases, wiring `[[actor]]` links so the historical
corpus connects to the ATT&CK/MISP-seeded actor graph immediately (still zero tokens).

It seeds METADATA + the PDF link, not the PDF text (APTnotes links rot and are heavy). Idempotent /
MERGE-safe: a mostly-static corpus, so re-runs are cheap no-ops; disable the cron after first seed if
you like. License: APTnotes index is CC0/public — pages stamp `sources: [APTnotes]` + the vendor.

Env: WIKI_PATH (/opt/vault) · APTNOTES_URL (default the raw APTnotes.json) · APTNOTES_LIMIT (0=all) ·
     APTNOTES_MIN_ALIAS (6 = only match actor aliases this long in titles, to avoid false hits)
Usage: aptnotes_import.py [--vault DIR] [--limit N] [--dry-run]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.request
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _okf_write import content_root, clean, slug, write_page  # noqa: E402
from misp_galaxy_import import index_actors      # reuse the alias index  # noqa: E402

APTNOTES_URL = os.environ.get(
    "APTNOTES_URL", "https://raw.githubusercontent.com/aptnotes/data/master/APTnotes.json")
MIN_ALIAS = int(os.environ.get("APTNOTES_MIN_ALIAS", "6"))


def _fetch(url: str) -> list:
    req = urllib.request.Request(url, headers={"User-Agent": "okpack-threat-actors/aptnotes"})
    with urllib.request.urlopen(req, timeout=90) as r:  # noqa: S310  # nosec B310 (fixed https upstream)
        return json.loads(r.read().decode("utf-8"))


def _date(rec: dict) -> str:
    """APTnotes Date is MM/DD/YYYY; fall back to Year-01-01, then a fixed floor."""
    for fmt in ("%m/%d/%Y", "%Y-%m-%d"):
        try:
            return datetime.strptime((rec.get("Date") or "").strip(), fmt).strftime("%Y-%m-%d")
        except (ValueError, TypeError):
            pass
    y = str(rec.get("Year") or "").strip()
    return f"{y}-01-01" if re.fullmatch(r"\d{4}", y) else "1970-01-01"


def _actor_matcher(idx: dict):
    """Compile ONE word-boundary regex over actor aliases (>= MIN_ALIAS chars) -> alias->page-stem map."""
    stems = {}
    aliases = []
    for alias, rel in idx.items():
        if len(alias) >= MIN_ALIAS:
            stems[alias] = Path(rel).stem
            aliases.append(re.escape(alias))
    if not aliases:
        return None, {}
    aliases.sort(key=len, reverse=True)
    return re.compile(r"\b(" + "|".join(aliases) + r")\b", re.I), stems


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--vault", default=os.environ.get("WIKI_PATH", "/opt/vault"))
    ap.add_argument("--limit", type=int, default=int(os.environ.get("APTNOTES_LIMIT", "0")))
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)
    vault = content_root(Path(args.vault))

    try:
        notes = _fetch(APTNOTES_URL)
    except Exception as e:                            # noqa: BLE001
        print(f"ERROR: APTnotes fetch failed: {e}", file=sys.stderr)
        return 1

    rx, stems = _actor_matcher(index_actors(vault))
    if args.limit:
        notes = notes[:args.limit]

    written = linked = errs = 0
    for rec in notes:
        title = (rec.get("Title") or "").strip()
        if not title:
            continue
        pub = _date(rec)
        vendor = (rec.get("Source") or "").strip()
        rel_path = f"sources/{pub}-{slug(title)}.md"
        fm = {"type": "source", "source_kind": "threat-report", "source_channel": "aptnotes",
              "source_feed": "APTnotes", "publisher": vendor or None, "title": title,
              "url": rec.get("Link") or None, "published": pub, "sources": ["APTnotes"],
              "sha1": rec.get("SHA-1") or None}
        # match the title against known actor aliases -> wikilinks (zero-token graph wiring)
        mentions = sorted({stems[m.lower()] for m in rx.findall(title)}) if rx else []
        if mentions:
            fm["mentions_actors"] = mentions
        body = [f"# {title}", "", f"Historical vendor APT report ({vendor or 'unknown source'}, {pub}), "
                "indexed by APTnotes. PDF at the source link (not fetched).", ""]
        if mentions:
            body += ["## Actors named in the title", ""] + [f"- [[{s}]]" for s in mentions] + [""]
            linked += 1
        try:
            write_page(vault, rel_path, fm, "\n".join(body), dry_run=args.dry_run)
            written += 1
        except OSError as e:
            errs += 1
            print(f"WARN: {rel_path}: {e}", file=sys.stderr)

    print(f"aptnotes-seed: {written} historical report(s) -> sources/, {linked} title-linked to actors"
          f"{f', {errs} error(s)' if errs else ''}")
    print(json.dumps({"wakeAgent": False}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
