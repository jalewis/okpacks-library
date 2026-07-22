#!/usr/bin/env python3
"""Enrich existing CVE pages from OSV.dev without creating or merging pages.

The CVE record and its one-hop advisory aliases are fetched.  Every distinct raw
revision is archived outside wiki/, while the current normalized projection is
MERGE-stamped onto the canonical CVE page.  Ambiguous multi-CVE aliases are
flagged for review and never cause an automatic identity merge.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

import yaml

API = os.environ.get("OSV_API", "https://api.osv.dev/v1/vulns")
_FM = re.compile(r"\A---[ \t]*\n(.*?\n)---[ \t]*\n?(.*)\Z", re.S)
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)
_ALIAS = re.compile(r"^(?:GHSA|GO|PYSEC|RUSTSEC|OSV|MAL|UBUNTU|DEBIAN|ALPINE)-", re.I)


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def runtime_dir(vault: Path) -> Path:
    for candidate in (vault / ".hermes-data", vault / ".okengine"):
        if candidate.is_dir():
            return candidate
    candidate = vault / ".okengine"
    candidate.mkdir(parents=True, exist_ok=True)
    return candidate


def read_page(path: Path) -> tuple[dict, str, str] | None:
    text = path.read_text(encoding="utf-8", errors="replace")
    match = _FM.match(text)
    if not match:
        return None
    try:
        meta = yaml.safe_load(match.group(1)) or {}
    except yaml.YAMLError:
        return None
    return (meta, match.group(2), text) if isinstance(meta, dict) else None


def stamp_page(text: str, fields: dict) -> str | None:
    match = _FM.match(text)
    if not match:
        return None
    try:
        meta = yaml.safe_load(match.group(1)) or {}
    except yaml.YAMLError:
        return None
    if not isinstance(meta, dict):
        return None
    if all(meta.get(key) == value for key, value in fields.items()):
        return None
    meta.update(fields)
    head = yaml.safe_dump(meta, sort_keys=False, allow_unicode=True).rstrip()
    return f"---\n{head}\n---\n{match.group(2)}"


def fetch_record(record_id: str, *, retries: int = 3, delay: float = 0.1) -> dict | None:
    url = f"{API.rstrip('/')}/{urllib.parse.quote(record_id, safe='-')}"
    request = urllib.request.Request(url, headers={"User-Agent": "okpack-vuln/osv-import"})
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(request, timeout=45) as response:  # noqa: S310  # nosec B310
                data = json.load(response)
            return data if isinstance(data, dict) else None
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None
            if exc.code not in (429, 500, 502, 503, 504) or attempt + 1 == retries:
                raise
        except (OSError, ValueError):
            if attempt + 1 == retries:
                raise
        time.sleep(delay * (2 ** attempt))
    return None


def records_for_cve(cve: str, *, delay: float = 0.1) -> list[dict]:
    first = fetch_record(cve, delay=delay)
    if not first:
        return []
    records = [first]
    aliases = sorted({str(a) for a in first.get("aliases", []) if _ALIAS.match(str(a))})
    for alias in aliases[:25]:
        if delay:
            time.sleep(delay)
        record = fetch_record(alias, delay=delay)
        if record and record.get("id") not in {r.get("id") for r in records}:
            records.append(record)
    return records


def fetch_all(pages: list[tuple], *, workers: int, delay: float) -> dict:
    """Fetch page identities concurrently; results remain keyed for ordered writes."""
    results = {}
    with ThreadPoolExecutor(max_workers=max(1, min(workers, 32))) as pool:
        futures = {pool.submit(records_for_cve, cve, delay=delay): cve
                   for _path, cve, _text in pages}
        for future in as_completed(futures):
            cve = futures[future]
            try:
                results[cve] = future.result()
            except Exception as exc:  # noqa: BLE001 -- preserve other independent lookups
                results[cve] = exc
    return results


def normalize(records: list[dict], retrieved_at: str) -> dict:
    ids, aliases, packages, affected, fixed, introduced, fixed_commits = set(), set(), set(), set(), set(), set(), set()
    modified, withdrawn = [], []
    cve_aliases = set()
    for record in records:
        rid = str(record.get("id") or "")
        if rid:
            ids.add(rid)
            (_CVE.match(rid) and cve_aliases.add(rid.upper()))
        for alias in record.get("aliases") or []:
            aliases.add(str(alias))
            if _CVE.match(str(alias)):
                cve_aliases.add(str(alias).upper())
        if record.get("modified"):
            modified.append(str(record["modified"]))
        if record.get("withdrawn"):
            withdrawn.append(str(record["withdrawn"]))
        for item in record.get("affected") or []:
            package = item.get("package") or {}
            eco, name, purl = (str(package.get(k) or "") for k in ("ecosystem", "name", "purl"))
            coordinate = purl or f"{eco or 'unknown'}:{name or 'unknown'}"
            if eco or name or purl:
                packages.add(" | ".join((eco or "unknown", name or "unknown", purl or "no-purl")))
            ranges = item.get("ranges") or []
            # Prefer compact exact range events. Enumerated affected versions can
            # contain thousands of releases and remain available in the raw archive.
            if not ranges:
                for version in (item.get("versions") or [])[:200]:
                    affected.add(f"{coordinate}@{version}")
            for range_ in ranges:
                kind = str(range_.get("type") or "unknown")
                repo = str(range_.get("repo") or "")
                scope = repo if kind == "GIT" and repo else coordinate
                for event in range_.get("events") or []:
                    for key, value in event.items():
                        token = f"{scope} | {kind}:{key}:{value}"
                        if key == "fixed":
                            (fixed_commits if kind == "GIT" else fixed).add(token)
                        elif key == "introduced":
                            introduced.add(token)
                        elif key in ("last_affected", "limit"):
                            affected.add(token)
    return {
        "osv_ids": sorted(ids),
        "osv_aliases": sorted(aliases),
        "osv_packages": sorted(packages),
        "osv_affected_versions": sorted(affected),
        "osv_fixed_versions": sorted(fixed),
        "osv_introduced": sorted(introduced),
        "osv_fixed_commits": sorted(fixed_commits),
        "osv_modified": max(modified) if modified else None,
        "osv_withdrawn": bool(withdrawn),
        "osv_withdrawn_at": max(withdrawn) if withdrawn else None,
        "osv_alias_ambiguity": len(cve_aliases) > 1,
        "osv_retrieved_at": retrieved_at,
    }


def archive_records(root: Path, records: list[dict]) -> tuple[int, dict[str, str]]:
    added, hashes = 0, {}
    for record in records:
        rid = str(record.get("id") or "unknown")
        raw = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        digest = hashlib.sha256(raw.encode()).hexdigest()
        hashes[rid] = digest
        directory = root / re.sub(r"[^A-Za-z0-9_.-]", "_", rid)
        target = directory / f"{digest}.json"
        if not target.exists():
            directory.mkdir(parents=True, exist_ok=True)
            target.write_text(json.dumps(record, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
            added += 1
    return added, hashes


def _telemetry(root: Path, started: str, outcome: str, fetched: int, accepted: int,
               checkpoint_in, checkpoint_out, error: str | None = None) -> None:
    try:
        import collection_ledger as ledger
        sid = ledger.source_id("okpack.vuln.osv", "osv.dev", "OSV.dev")
        ledger.register_sources(root, [{"source_id": sid, "connector_id": "okpack.vuln.osv",
            "label": "OSV.dev", "source_kind": "secondary", "independent_origin": None}],
            connector_id="okpack.vuln.osv")
        ledger.append_attempt(root, {"connector_id": "okpack.vuln.osv", "source_id": sid,
            "started_at": started, "finished_at": utcnow(), "outcome": outcome,
            "fetched": fetched, "extracted": fetched, "accepted": accepted,
            "rejected": max(0, fetched - accepted), "deduped": 0, "dead_letter": 0,
            "error_category": error, "checkpoint_in": ledger.checkpoint_digest(checkpoint_in),
            "checkpoint_out": ledger.checkpoint_digest(checkpoint_out)})
    except (ImportError, OSError, ValueError):
        pass


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--vault", default=os.environ.get("WIKI_PATH", "/opt/vault"))
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--limit", type=int, default=0, help="bounded CVE count; 0 processes all")
    parser.add_argument("--delay", type=float, default=float(os.environ.get("OSV_REQUEST_DELAY", "0.1")))
    parser.add_argument("--workers", type=int, default=int(os.environ.get("OSV_WORKERS", "12")),
                        help="bounded concurrent CVE lookups (default 12)")
    args = parser.parse_args(argv)
    started = utcnow()
    # OSV is a daily enrichment lane. Day-granular observation makes same-day
    # retries idempotent while still advancing freshness on every scheduled run.
    retrieved = datetime.now(timezone.utc).date().isoformat()
    vault = Path(args.vault)
    state_root = runtime_dir(vault)
    state_path = state_root / "osv-state.json"
    try:
        previous = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        previous = {}
    pages = []
    for path in sorted((vault / "wiki" / "cves").rglob("*.md")):
        parsed = read_page(path)
        if parsed and _CVE.match(str(parsed[0].get("cve_id") or path.stem)):
            pages.append((path, str(parsed[0].get("cve_id") or path.stem).upper(), parsed[2]))
    if args.limit:
        cursor = int(previous.get("cursor", 0)) % max(1, len(pages))
        pages = (pages[cursor:] + pages[:cursor])[:args.limit]
    fetched = stamped = revisions = failures = 0
    hashes = dict(previous.get("records") or {})
    results = fetch_all(pages, workers=args.workers, delay=max(0, args.delay))
    for path, cve, text in pages:
        try:
            records = results.get(cve, [])
            if isinstance(records, Exception):
                raise records
            fetched += len(records)
            if not records:
                continue
            fields = normalize(records, retrieved)
            if not args.dry_run:
                added, current = archive_records(state_root / "osv-archive", records)
                revisions += added
                hashes.update(current)
            fields["osv_revision_count"] = sum(
                len(list((state_root / "osv-archive" / re.sub(r"[^A-Za-z0-9_.-]", "_", rid)).glob("*.json")))
                for rid in fields["osv_ids"])
            updated = stamp_page(text, fields)
            if updated is not None:
                stamped += 1
                if not args.dry_run:
                    path.write_text(updated, encoding="utf-8")
        except Exception as exc:  # noqa: BLE001 -- one advisory must not abort the corpus
            failures += 1
            print(f"WARN: {cve}: {exc}", file=sys.stderr)
    checkpoint = {"retrieved_at": retrieved, "records": hashes,
                  "cursor": (int(previous.get("cursor", 0)) + len(pages)) % max(1, len(pages))}
    if not args.dry_run:
        state_path.write_text(json.dumps(checkpoint, indent=2) + "\n", encoding="utf-8")
    outcome = "success" if failures == 0 else ("partial" if fetched else "failure")
    _telemetry(state_root / "collection", started, outcome, fetched, stamped,
               previous, checkpoint, "upstream-or-parse" if failures else None)
    print(f"osv-import: {len(pages)} CVEs ({max(1, min(args.workers, 32))} workers) · "
          f"{fetched} records · {stamped} stamped · "
          f"{revisions} new immutable revisions · {failures} failures")
    print(json.dumps({"wakeAgent": False}))
    return 0 if outcome != "failure" else 1


if __name__ == "__main__":
    sys.exit(main())
