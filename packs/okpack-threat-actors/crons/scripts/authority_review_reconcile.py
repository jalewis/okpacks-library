#!/usr/bin/env python3
"""Reconcile review state for claim-matched primary-authority actor records.

This lane is intentionally narrow. It does not infer authority from a publisher label, article
count, or secondary reporting. It requires a locally stored source page, an exact approved HTTPS
origin, a government-alert kind, an explicit actor-name match in that source, a source reference
already associated with the actor, confirmed attribution, and no conflicts. Everything else stays
in human review. Default mode is a dry run.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _okf_write import _split_frontmatter, content_root, slug, write_page  # noqa: E402


CISA_ACTOR_POLICY = {
    "id": "cisa-direct-actor-attribution-v1",
    "authority": "CISA multi-agency advisory",
    "eligible_types": ["actor"],
    "source_names": ["CISA Cybersecurity Advisories"],
    "url_hosts": ["www.cisa.gov"],
    "url_path_pattern": r"/news-events/cybersecurity-advisories/[a-z0-9-]+/?",
    "id_field": "authority_claim_id",
    "id_pattern": r"actor-attribution:[a-z0-9-]+",
    "verified_fields": ["title", "attribution_confidence", "body:actor-attribution"],
    "required_values": {"authority_import": "direct-government-advisory"},
}


def _utc_second(value: object) -> str:
    text = str(value or "").strip()
    try:
        parsed = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        parsed = dt.datetime.now(dt.timezone.utc)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _names(fm: dict) -> list[str]:
    values = [fm.get("title"), *(fm.get("aliases") or [])]
    return [str(value).strip() for value in values if len(str(value or "").strip()) >= 5]


def _mentions_actor(source_text: str, names: list[str]) -> bool:
    folded = source_text.casefold()
    return any(re.search(rf"(?<![\w]){re.escape(name.casefold())}(?![\w])", folded)
               for name in names)


def _source_path(wiki: Path, ref: str) -> Path:
    rel = ref.strip().removesuffix(".md") + ".md"
    return wiki / rel


def qualifying_source(wiki: Path, actor_fm: dict) -> tuple[str, dict, str] | None:
    if actor_fm.get("attribution_confidence") != "confirmed" or actor_fm.get("conflicts"):
        return None
    refs = actor_fm.get("np_source_refs") or []
    canonical = actor_fm.get("sources") or []
    refs = [*refs, *[v for v in canonical if str(v).startswith("sources/")]]
    seen: set[str] = set()
    for ref in refs:
        ref = str(ref).strip().removesuffix(".md")
        if not ref or ref in seen:
            continue
        seen.add(ref)
        path = _source_path(wiki, ref)
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        sfm, _ = _split_frontmatter(text)
        if (sfm.get("publisher") != "CISA Cybersecurity Advisories"
                or sfm.get("kind") != "government-alert"
                or not _mentions_actor(text, _names(actor_fm))):
            continue
        url = str(sfm.get("url") or "")
        record = {
            "type": "actor",
            "sources": ["CISA Cybersecurity Advisories"],
            "url": url,
            "authority_claim_id": f"actor-attribution:{slug(str(actor_fm.get('title') or ''))}",
            "authority_import": "direct-government-advisory",
        }
        return ref, record, _utc_second(sfm.get("published") or sfm.get("last_updated"))
    return None


def reconcile(vault: Path, *, apply: bool = False, actor: str = "") -> dict:
    wiki = content_root(vault)
    result = {"eligible": 0, "updated": 0, "skipped": 0, "errors": 0}
    for path in sorted((wiki / "entities").rglob("*.md")):
        text = path.read_text(encoding="utf-8")
        fm, body = _split_frontmatter(text)
        if fm.get("type") != "actor" or (actor and path.stem != actor):
            continue
        match = qualifying_source(wiki, fm)
        if not match:
            result["skipped"] += 1
            continue
        ref, authority_record, reviewed_at = match
        result["eligible"] += 1
        refs = list(fm.get("sources") or [])
        if ref not in refs:
            refs.append(ref)
        incoming = {"type": "actor", "sources": refs,
                    "authority_import": "direct-government-advisory"}
        body = re.sub(r"sources/\d{4}//nsa-cisa-fsb-center-16-router-hardening", ref, body)
        try:
            write_page(wiki, path.relative_to(wiki).as_posix(), incoming, body,
                       dry_run=not apply, authority_policy=CISA_ACTOR_POLICY,
                       authority_record=authority_record, reviewed_at=reviewed_at)
        except (OSError, RuntimeError, ValueError) as exc:
            result["errors"] += 1
            print(f"WARN: {path.relative_to(wiki)}: {exc}", file=sys.stderr)
            continue
        if apply:
            result["updated"] += 1
    return result


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--vault", default="/opt/vault")
    ap.add_argument("--actor", default="")
    ap.add_argument("--apply", action="store_true")
    args = ap.parse_args(argv)
    apply = args.apply or os.environ.get("AUTHORITY_RECONCILE_APPLY") == "1"
    result = reconcile(Path(args.vault), apply=apply, actor=args.actor)
    print("authority-review-reconcile: " + json.dumps(result, sort_keys=True))
    print(json.dumps({"wakeAgent": False}))
    return 1 if result["errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
