#!/usr/bin/env python3
"""okpack-indicators — URLhaus (abuse.ch) IOC seed (no_agent, ZERO LLM tokens).

Seeds `indicator` pages (type: indicator, indicator_type: url) from abuse.ch URLhaus — a public
feed of malicious URLs (malware distribution / C2). BOUNDED to the recent feed (not the full
archive). Each page carries the URL, the associated threat/malware tag, and the host, cross-linked
to the malware family it distributes ([[<family>]], resolves to a composed malware pack's page) and
to the host's `infrastructure` page. no_agent, deterministic CSV -> markdown, MERGE-safe.

License: URLhaus data is CC0 (public domain) — pages stamp `sources: [URLhaus]`.

Env: WIKI_PATH (/opt/vault) · URLHAUS_URL (default the recent-URLs CSV) · URLHAUS_LIMIT (default 500)
Usage: urlhaus_import.py [--limit N] [--vault DIR] [--dry-run]
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import os
import re
import sys
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _okf_write import content_root, slug, write_page   # noqa: E402

URLHAUS_URL = os.environ.get("URLHAUS_URL", "https://urlhaus.abuse.ch/downloads/csv_recent/")
_HOST_RE = re.compile(r"^[a-z0-9.\-]+$")
# URLhaus tags mix the malware family with file-format / architecture descriptors — skip the latter
# so we don't fabricate a family (e.g. tags "32-bit,elf,mips,Mozi" → family Mozi, not "32-bit").
_NONFAMILY = {"32-bit", "64-bit", "elf", "exe", "dll", "mips", "arm", "arm7", "x86", "x64", "js",
              "doc", "xls", "pdf", "apk", "sh", "bin", "zip", "rar", "php", "html", "vbs", "ps1",
              "macos", "linux", "windows", "android", "iot", "opendir"}


def _family(tags: list[str]) -> str | None:
    for t in tags:
        if t.lower() not in _NONFAMILY and t.replace("-", "").isalpha() and len(t) >= 3:
            return t
    return None


# URLhaus csv_recent has a FIXED column order and prefixes EVERY line (incl. the header row) with
# `#`, so we can't rely on DictReader's header detection — declare the columns explicitly.
_COLS = ["id", "dateadded", "url", "url_status", "last_online", "threat", "tags",
         "urlhaus_link", "reporter"]


def _fetch_csv(url: str) -> list[dict]:
    req = urllib.request.Request(url, headers={"User-Agent": "okpack-indicators/urlhaus_import"})
    with urllib.request.urlopen(req, timeout=90) as r:   # noqa: S310 (fixed https host)  # nosec B310 (fixed https upstream)
        raw = r.read().decode("utf-8", errors="replace")
    data = [ln for ln in raw.splitlines() if ln and not ln.lstrip().startswith("#")]
    return list(csv.DictReader(io.StringIO("\n".join(data)), fieldnames=_COLS))


def _host_of(url: str) -> str:
    try:
        return (urllib.parse.urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--vault", default=os.environ.get("WIKI_PATH", "/opt/vault"))
    ap.add_argument("--limit", type=int, default=int(os.environ.get("URLHAUS_LIMIT", "500")))
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)
    vault = content_root(Path(args.vault))

    try:
        rows = _fetch_csv(URLHAUS_URL)
    except Exception as e:                               # noqa: BLE001 — best-effort seed lane
        print(f"ERROR: URLhaus fetch failed: {e}", file=sys.stderr)
        return 1

    written = hosts = errs = 0
    seen_hosts: set[str] = set()
    for row in rows[: max(1, args.limit)]:
        url = (row.get("url") or "").strip()
        uid = (row.get("id") or "").strip()
        if not url or not uid:
            continue
        threat = (row.get("threat") or "").strip() or None
        tags = [t for t in (row.get("tags") or "").split(",") if t.strip()]
        added = (row.get("dateadded") or "")[:10] or None
        host = _host_of(url)
        family = _family(tags)                           # best-effort family tag (skips format/arch)
        body = [f"# URLhaus indicator {uid}", "",
                f"Malicious URL reported to abuse.ch URLhaus: `{url}`", ""]
        if threat:
            body.append(f"- **Threat:** {threat}")
        if host:
            body.append(f"- **Host:** [[{slug(host)}]]")   # resolves to the infrastructure page below
        if family:
            body.append(f"- **Distributes:** [[{slug(family)}]]")  # resolves to a composed malware pack
        body += ["", "> Seeded no_agent from the abuse.ch URLhaus recent feed (CC0)."]
        fm = {"type": "indicator", "id": f"urlhaus-{uid}", "indicator_type": "url",
              "value": url, "title": f"URL {host or uid}", "threat": threat,
              "malware_family": family, "first_seen": added, "last_seen": added,
              "tags": tags or None, "sources": ["URLhaus"],
              "url": f"https://urlhaus.abuse.ch/url/{uid}/"}
        try:
            if write_page(vault, f"indicators/{(added or '0000-00')[:7]}/urlhaus-{uid}.md",
                          {k: v for k, v in fm.items() if v not in (None, "", [])},
                          "\n".join(body), dry_run=args.dry_run) != "dry":
                written += 1
            # one infrastructure page per distinct host, cross-linked from its indicators
            if host and _HOST_RE.match(host) and host not in seen_hosts:
                seen_hosts.add(host)
                if not args.dry_run:
                    write_page(vault, f"entities/{slug(host)[:1] or '_'}/{slug(host)}.md",
                               {"type": "infrastructure", "id": slug(host), "title": host,
                                "infra_type": "hosting-provider", "sources": ["URLhaus"]},
                               f"# {host}\n\nAdversary infrastructure observed hosting malicious URLs "
                               f"(abuse.ch URLhaus).")
                    hosts += 1
        except OSError as e:
            errs += 1
            print(f"WARN: write {uid}: {e}", file=sys.stderr)

    print(f"urlhaus-import: {written} indicator(s) + {hosts} infrastructure page(s) -> indicators/,entities/"
          f"{f', {errs} error(s)' if errs else ''}")
    print(json.dumps({"wakeAgent": False}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
