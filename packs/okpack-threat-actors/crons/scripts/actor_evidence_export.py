#!/usr/bin/env python3
"""Export a public, allowlisted actor-evidence snapshot for a private analysis consumer.

Only structured actor fields are projected. Bodies, prompts, configuration, private findings, and
unsourced actor records never cross the boundary. The exporter makes no network calls.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

import yaml


CONTRACT = "okengine-evidence-snapshot/v2"
EXPORT_FIELDS = (
    "id", "title", "aliases", "attack_id", "origin_country", "attribution_confidence",
    "campaigns", "malware", "tools", "techniques", "observations", "sources", "updated",
    "source_records", "attribution_claims",
)
LIST_FIELDS = ("aliases", "campaigns", "malware", "tools", "techniques", "observations")
SOURCE_KEYS = frozenset({"id", "url", "title", "publisher", "published", "source_kind"})
FRONTMATTER_RE = re.compile(r"\A---\s*\n(.*?\n)---\s*(?:\n|\Z)", re.DOTALL)
WIKILINK_RE = re.compile(r"^\[\[([^]|#]+)(?:#[^]|]+)?(?:\|[^]]+)?]]$")
KNOWN_SOURCES = {
    "MITRE ATT&CK": {
        "publisher": "MITRE", "source_kind": "knowledge-base",
        "url": "https://attack.mitre.org/", "publisher_key": "mitre-attack",
    },
    "MISP galaxy": {
        "publisher": "MISP Project", "source_kind": "dataset",
        "url": "https://github.com/MISP/misp-galaxy", "publisher_key": "misp-galaxy",
    },
    "Microsoft": {
        "publisher": "Microsoft", "source_kind": "vendor-reporting",
        "url": "https://www.microsoft.com/en-us/security/security-insider/",
        "publisher_key": "microsoft",
    },
}
ATTACK_GROUP_URL_RE = re.compile(r"^https://attack\.mitre\.org/groups/G[0-9]{4}/?$", re.IGNORECASE)


class ExportError(ValueError):
    """The public corpus cannot be exported without weakening the boundary."""


def _json_value(value: Any) -> Any:
    if isinstance(value, (date, datetime)):
        return value.isoformat()
    if isinstance(value, dict):
        return {str(key): _json_value(child) for key, child in value.items()}
    if isinstance(value, list):
        return [_json_value(child) for child in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def _frontmatter(path: Path) -> dict[str, Any] | None:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return None
    match = FRONTMATTER_RE.match(text)
    if not match:
        return None
    try:
        value = yaml.safe_load(match.group(1))
    except yaml.YAMLError:
        return None
    return value if isinstance(value, dict) else None


def _nonempty_strings(value: Any) -> list[str]:
    values = value if isinstance(value, list) else ([value] if value is not None else [])
    return [item.strip() for item in values if isinstance(item, str) and item.strip()]


def _sources(value: Any) -> list[Any]:
    values = value if isinstance(value, list) else ([value] if value is not None else [])
    result: list[Any] = []
    for item in values:
        if isinstance(item, str) and item.strip():
            result.append(item.strip())
        elif isinstance(item, dict):
            safe = {key: _json_value(item[key]) for key in SOURCE_KEYS if item.get(key) not in (None, "")}
            if any(isinstance(safe.get(key), str) and safe[key].strip() for key in ("id", "url")):
                result.append(safe)
    return result


def _source_path(reference: str, vault: Path) -> Path | None:
    match = WIKILINK_RE.match(reference.strip())
    target = match.group(1) if match else reference.strip()
    if target.endswith(".md"):
        target = target[:-3]
    if not target.startswith("sources/") or ".." in Path(target).parts:
        return None
    candidate = vault / "wiki" / f"{target}.md"
    return candidate if candidate.is_file() else None


def source_record(reference: Any, vault: Path) -> dict[str, Any]:
    if isinstance(reference, dict):
        reference_text = str(reference.get("id") or reference.get("url") or "source")
        record = {"source_ref": reference_text, "title": str(reference.get("title") or reference_text)}
        record.update({key: _json_value(reference[key]) for key in SOURCE_KEYS
                       if key != "id" and key in reference})
    else:
        reference_text = str(reference)
        record = {"source_ref": reference_text, "title": reference_text}
        path = _source_path(reference_text, vault)
        if path:
            fm = _frontmatter(path) or {}
            for key in ("title", "url", "publisher", "published", "source_kind", "reliability"):
                if fm.get(key) not in (None, ""):
                    record[key] = _json_value(fm[key])
        elif reference_text in KNOWN_SOURCES:
            record.update(KNOWN_SOURCES[reference_text])
    record.setdefault("source_kind", "reference-label")
    record["independence_status"] = "not-assessed"
    record.setdefault("publisher_key", str(record.get("publisher") or record["source_ref"]).casefold())
    url = record.get("url")
    # Entity provenance is context until a claim explicitly selects it below. A URL alone does not
    # prove that the page was retrieved or that its contents support this particular claim.
    record["retrieval_status"] = "publisher-or-dataset-root"
    origin_basis = f"{record['publisher_key']}\0{url or record['source_ref']}"
    record["evidence_origin_id"] = "origin:" + hashlib.sha256(origin_basis.encode()).hexdigest()[:24]
    record["citation_scope"] = "entity-provenance"
    return record


def attribution_source_records(record: dict[str, Any], fm: dict[str, Any], vault: Path) -> list[dict[str, Any]]:
    explicit = _sources(fm.get("attribution_sources"))
    citations = [source_record(item, vault) for item in explicit]
    actor_url = fm.get("url")
    if not citations and isinstance(actor_url, str) and ATTACK_GROUP_URL_RE.fullmatch(actor_url.strip()):
        citations = [source_record({
            "id": actor_url.strip(),
            "url": actor_url.strip(),
            "title": f"MITRE ATT&CK: {record['title']}",
            "publisher": "MITRE",
            "source_kind": "knowledge-base",
        }, vault)]
        citations[0]["publisher_key"] = "mitre-attack"
        origin_basis = f"mitre-attack\0{actor_url.strip()}"
        citations[0]["evidence_origin_id"] = "origin:" + hashlib.sha256(origin_basis.encode()).hexdigest()[:24]
    for citation in citations:
        citation["citation_scope"] = "reported-country-nexus"
        citation["retrieval_status"] = "exact-page"
    return citations


def attribution_claim(record: dict[str, Any], fm: dict[str, Any],
                      claim_sources: list[dict[str, Any]]) -> dict[str, Any] | None:
    country = record.get("origin_country")
    if not isinstance(country, str) or not country:
        return None
    note = fm.get("attribution_notes")
    if isinstance(note, str) and note.strip():
        statement = note.strip()[:4000]
        statement_kind = "corpus-attribution-note"
    else:
        statement = f"The public actor corpus reports a country nexus of {country} for {record['title']}."
        statement_kind = "structured-field-rendering"
    source_refs = [source["source_ref"] for source in claim_sources]
    context_refs = [source["source_ref"] for source in record["source_records"]
                    if source["source_ref"] not in source_refs]
    basis = f"{record['id']}\0reported-country-nexus\0{country}\0" + "\0".join(source_refs)
    return {
        "claim_id": "claim:" + hashlib.sha256(basis.encode("utf-8")).hexdigest()[:24],
        "claim_kind": "reported-country-nexus",
        "subject_ref": record["id"],
        "predicate": "reported-country-nexus",
        "object": country,
        "statement": statement,
        "statement_kind": statement_kind,
        "verbatim": False,
        "source_refs": source_refs,
        "context_source_refs": context_refs,
        "citation_status": "claim-specific" if source_refs else "publisher-only",
        "lineage_status": "not-assessed",
        "public_confidence_label": record.get("attribution_confidence") or "not-supplied",
        "derivation": "origin_country",
        "independence_status": "not-assessed",
    }


def project_actor(path: Path, entities_root: Path) -> tuple[dict[str, Any] | None, str | None]:
    fm = _frontmatter(path)
    if not fm or fm.get("type") != "actor":
        return None, None
    sources = _sources(fm.get("sources"))
    if not sources:
        return None, "missing source provenance"

    actor_id = fm.get("id") or fm.get("attack_id")
    if not isinstance(actor_id, str) or not actor_id.strip():
        actor_id = f"okf:{path.relative_to(entities_root).with_suffix('').as_posix()}"
    title = fm.get("title") or fm.get("name")
    if not isinstance(title, str) or not title.strip():
        return None, "missing title"

    record: dict[str, Any] = {"id": actor_id.strip(), "title": title.strip(), "sources": sources}
    for field in LIST_FIELDS:
        values = _nonempty_strings(fm.get(field))
        if values:
            record[field] = values
    for field in ("attack_id", "origin_country", "attribution_confidence"):
        value = fm.get(field)
        if isinstance(value, str) and value.strip():
            record[field] = value.strip()
    updated = fm.get("updated") or fm.get("last_updated")
    if updated not in (None, ""):
        record["updated"] = _json_value(updated)
    vault = entities_root.parents[1]
    record["source_records"] = [source_record(source, vault) for source in sources]
    claim_sources = attribution_source_records(record, fm, vault)
    by_ref = {source["source_ref"]: source for source in record["source_records"]}
    for source in claim_sources:
        if source["source_ref"] in by_ref:
            by_ref[source["source_ref"]].update(source)
        else:
            record["source_records"].append(source)
            by_ref[source["source_ref"]] = source
    claim = attribution_claim(record, fm, claim_sources)
    if claim:
        record["attribution_claims"] = [claim]
    return record, None


def build_records(vault: Path) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    entities = vault.resolve() / "wiki" / "entities"
    if not entities.is_dir():
        raise ExportError(f"actor entity tree not found: {entities}")
    records: list[dict[str, Any]] = []
    skipped: list[dict[str, str]] = []
    seen: dict[str, Path] = {}
    for path in sorted(entities.rglob("*.md")):
        record, reason = project_actor(path, entities)
        if reason:
            skipped.append({"path": str(path.relative_to(vault)), "reason": reason})
            continue
        if record is None:
            continue
        actor_id = record["id"]
        if actor_id in seen:
            raise ExportError(f"duplicate actor id {actor_id!r}: {seen[actor_id]} and {path}")
        seen[actor_id] = path
        records.append(record)
    records.sort(key=lambda item: (item["id"].casefold(), item["title"].casefold()))
    return records, skipped


def _version(vault: Path) -> tuple[str, str]:
    try:
        pack = yaml.safe_load((vault / "pack.yaml").read_text())
        pack_version = str(pack["version"])
    except (OSError, KeyError, TypeError, yaml.YAMLError) as exc:
        raise ExportError("cannot read pack version from pack.yaml") from exc
    try:
        engine_pin = yaml.safe_load((vault / "engine.version").read_text())
        engine_version = engine_pin.get("version") if isinstance(engine_pin, dict) else engine_pin
    except (OSError, yaml.YAMLError) as exc:
        raise ExportError("cannot read engine.version") from exc
    if not pack_version or not isinstance(engine_version, str) or not engine_version.strip():
        raise ExportError("pack and engine versions must be non-empty")
    return pack_version, engine_version.strip()


def export_snapshot(vault: Path, output: Path, generated_at: str | None = None) -> dict[str, Any]:
    vault = vault.resolve()
    output = output.resolve()
    if output.exists():
        raise ExportError(f"output already exists: {output}")
    records, skipped = build_records(vault)
    payload = b"".join(
        json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8") + b"\n"
        for record in records
    )
    digest = hashlib.sha256(payload).hexdigest()
    pack_version, engine_version = _version(vault)
    manifest = {
        "contract": CONTRACT,
        "generated_at": generated_at or datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "producer": {"pack": "okpack-threat-actors", "version": pack_version,
                     "engine_version": engine_version},
        "producer_trust": "public", "classification": "public", "max_tlp": "CLEAR",
        "records_file": "actors.ndjson", "record_count": len(records), "content_sha256": digest,
        "field_allowlist": list(EXPORT_FIELDS),
    }

    output.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=f".{output.name}.", dir=output.parent))
    try:
        (stage / "actors.ndjson").write_bytes(payload)
        (stage / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        (stage / "export-report.json").write_text(
            json.dumps({"exported": len(records), "skipped": skipped}, indent=2, sort_keys=True) + "\n"
        )
        os.replace(stage, output)
    finally:
        if stage.exists():
            shutil.rmtree(stage)
    return {"manifest": manifest, "skipped": skipped}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="new snapshot directory to create")
    parser.add_argument("--vault", type=Path,
                        default=Path(os.environ.get("WIKI_PATH", Path(__file__).resolve().parents[2])))
    parser.add_argument("--fail-on-skipped", action="store_true")
    args = parser.parse_args(argv)
    try:
        result = export_snapshot(args.vault, args.output)
        if args.fail_on_skipped and result["skipped"]:
            shutil.rmtree(args.output)
            raise ExportError(f"{len(result['skipped'])} actor record(s) were skipped")
    except (OSError, ExportError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    manifest = result["manifest"]
    print(f"EXPORTED: {manifest['record_count']} actor record(s), {len(result['skipped'])} skipped; "
          f"sha256={manifest['content_sha256']}; output={args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
