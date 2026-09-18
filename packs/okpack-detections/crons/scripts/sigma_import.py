#!/usr/bin/env python3
"""okpack-detections — SigmaHQ rule seed (no_agent, ZERO LLM tokens).

Seeds `detection` pages from the open SigmaHQ ruleset (github.com/SigmaHQ/sigma). BOUNDED: fetches
the repo tree once (1 GitHub API call), takes the first N rule files, and pulls each via the raw CDN
(not rate-limited). Each page carries the rule's title/level/logsource and — the point — the ATT&CK
technique(s) it covers, as `[[technique]]` links (the detection-coverage seam: resolves to a composed
actor pack's technique pages, so the vault can answer "which techniques do we detect"). no_agent,
deterministic YAML -> markdown, MERGE-safe. Links, does not paste, the full rule.

License: SigmaHQ rules are DRL-1.1 (permissive) — pages stamp `sources: [SigmaHQ]` + the rule id/url.

Env: WIKI_PATH (/opt/vault) · SIGMA_LIMIT (default 60) · GITHUB_TOKEN (optional, lifts the API limit)
Usage: sigma_import.py [--limit N] [--vault DIR] [--dry-run]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.request
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _okf_write import content_root, slug, write_page   # noqa: E402

_TREE = "https://api.github.com/repos/SigmaHQ/sigma/git/trees/master?recursive=1"
_RAW = "https://raw.githubusercontent.com/SigmaHQ/sigma/master/"
_TECH_RE = re.compile(r"attack[.\-]t(\d{4})(?:\.(\d{3}))?", re.I)   # attack.t1059.001 -> T1059.001


def _get(url: str, token: str | None) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "okpack-detections/sigma_import"})
    if token and "api.github.com" in url:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=90) as r:   # noqa: S310 (fixed https hosts)  # nosec B310 (fixed https upstream)
        return r.read()


def _techniques(tags: list[str]) -> list[str]:
    out = []
    for t in tags or []:
        m = _TECH_RE.search(str(t))
        if m:
            tid = "T" + m.group(1) + (f".{m.group(2)}" if m.group(2) else "")
            if tid not in out:
                out.append(tid)
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--vault", default=os.environ.get("WIKI_PATH", "/opt/vault"))
    ap.add_argument("--limit", type=int, default=int(os.environ.get("SIGMA_LIMIT", "60")))
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)
    vault = content_root(Path(args.vault))
    token = os.environ.get("GITHUB_TOKEN") or None

    try:
        tree = json.loads(_get(_TREE, token))
    except Exception as e:                               # noqa: BLE001 — best-effort seed lane
        print(f"ERROR: SigmaHQ tree fetch failed: {e}", file=sys.stderr)
        return 1
    paths = [n["path"] for n in (tree.get("tree") or [])
             if n.get("type") == "blob" and n["path"].startswith("rules/")
             and n["path"].endswith(".yml")]
    paths.sort()

    written = errs = 0
    for rel in paths[: max(1, args.limit)]:
        try:
            doc = yaml.safe_load(_get(_RAW + rel, token))
        except Exception as e:                           # noqa: BLE001
            errs += 1
            print(f"WARN: fetch {rel}: {e}", file=sys.stderr)
            continue
        if not isinstance(doc, dict) or not doc.get("title"):
            continue
        title = str(doc["title"]).strip()
        rid = str(doc.get("id") or slug(title))
        techs = _techniques(doc.get("tags") or [])
        ls = doc.get("logsource") or {}
        logsource = " / ".join(str(ls.get(k)) for k in ("product", "category", "service") if ls.get(k))
        body = [f"# {title}", "", str(doc.get("description") or "").strip(), ""]
        if logsource:
            body.append(f"- **Log source:** {logsource}")
        if doc.get("level"):
            body.append(f"- **Level:** {doc['level']}")
        if techs:
            body.append("- **Covers:** " + ", ".join(f"[[{t}]]" for t in techs))
        fps = doc.get("falsepositives")
        if fps:
            body += ["", "## False positives", ""] + [f"- {x}" for x in (fps if isinstance(fps, list) else [fps])]
        body += ["", f"> Seeded no_agent from SigmaHQ (`{rel}`). Full rule lives in the ruleset."]
        fm = {"type": "detection", "id": f"sigma-{rid}", "title": title,
              "detection_format": "sigma", "rule_level": doc.get("level"),
              "rule_status": doc.get("status"), "logsource": logsource or None,
              "covers_techniques": techs or None, "author": doc.get("author"),
              "tags": [t for t in (doc.get("tags") or []) if not str(t).lower().startswith("attack.")] or None,
              "sources": ["SigmaHQ"], "url": f"https://github.com/SigmaHQ/sigma/blob/master/{rel}"}
        try:
            if write_page(vault, f"detections/{slug(title)[:1] or '_'}/sigma-{rid}.md",
                          {k: v for k, v in fm.items() if v not in (None, "", [])},
                          "\n".join(body), dry_run=args.dry_run) != "dry":
                written += 1
        except OSError as e:
            errs += 1
            print(f"WARN: write {rid}: {e}", file=sys.stderr)

    print(f"sigma-import: {written} detection(s) -> detections/ (of {len(paths)} rules, cap {args.limit})"
          f"{f', {errs} error(s)' if errs else ''}")
    print(json.dumps({"wakeAgent": False}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
