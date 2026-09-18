#!/usr/bin/env python3
"""Deterministically remove obvious non-actors from the actor corpus.

The entity synthesis lane is probabilistic.  This daily backstop re-evaluates every live
``type: actor`` page and applies only high-precision dispositions:

* generic/template/common-role labels are tombstoned;
* pages whose own prose explicitly defines the subject as malicious software, a backdoor,
  ransomware, or a phishing toolkit are retyped to ``malware``;
* authority-backed actors are never changed by lexical heuristics.

Ambiguous pages are reported and left alone.  Use ``--apply`` (or
``ACTOR_IDENTITY_AUDIT_APPLY=1``) to write; dry-run is the safe default.
"""
from __future__ import annotations

import argparse
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _okf_write import content_root  # noqa: E402

_FM = re.compile(r"^---\s*\n(.*?)\n---\s*\n(.*)", re.S)
_NORMALIZE = re.compile(r"[^a-z0-9]+")

# Exact labels observed in production plus class/template labels. Whole-title matching is
# intentional: real names such as "Comment Crew" and "Scattered Spider" remain valid.
GENERIC_ACTOR_LABELS = frozenset(
    """
actor|actors|adversary|ai agent|ai agents|ai attacker|ai attackers|attack group|attacker|attackers
autonomous llm agent|criminal group|cyber criminals|cybercriminal|cybercriminal group|cybercriminals
hacker|hacker group|hackers|initial access broker|initial access brokers|intruder|intruders|llm agent
llm agents|malware campaign|outsider|placeholder|ransomware campaign|ransomware gang|ransomware gangs
ransomware group|threat actor|threat actor name|threat actors|threat group|unknown|unknown actor
unknown threat actor|unsafe
""".strip().replace("\n", "|").split("|")
)

_VAGUE = frozenset({"generic", "placeholder", "someone", "unknown", "unnamed", "unidentified"})
_CATEGORY_END = frozenset({"actor", "actors", "adversary", "adversaries", "attacker", "attackers"})
_SOFTWARE_KIND = (
    r"(?:backdoor|malware|implant|loader|ransomware|stealer|trojan|"
    r"phishing[- ]as[- ]a[- ]service|phishing (?:service|toolkit)|toolkit)"
)
_SOFTWARE_TITLE = re.compile(r"\b(?:backdoor|malware|ransomware|stealer|trojan|rat|toolkit)\b", re.I)
_ACTOR_ACTIVITY_FIELDS = frozenset(
    {
        "actor_type", "activity_tier", "attribution_confidence", "consensus",
        "news_last_seen", "recent_news", "recent_news_refs", "recent_reports",
        "review_checked_at", "review_status", "sheet_origin_group", "total_mentions",
    }
)


def _split(path: Path) -> tuple[dict, str]:
    try:
        match = _FM.match(path.read_text(encoding="utf-8", errors="replace"))
    except OSError:
        return {}, ""
    if not match:
        return {}, ""
    try:
        fm = yaml.safe_load(match.group(1)) or {}
    except yaml.YAMLError:
        return {}, ""
    return (fm if isinstance(fm, dict) else {}), match.group(2)


def _label(fm: dict, path: Path) -> str:
    return str(fm.get("title") or fm.get("name") or path.stem).strip()


def _normalized(value: str) -> str:
    return _NORMALIZE.sub(" ", value.casefold()).strip()


def _authority_backed(fm: dict) -> bool:
    attack_id = str(fm.get("attack_id") or "").upper()
    reviewed = str(fm.get("review_status") or "") == "auto-verified"
    return bool(
        re.fullmatch(r"G\d{4,}", attack_id)
        or fm.get("authority_ids")
        or (reviewed and int(fm.get("consensus") or 0) >= 2)
    )


def _defines_software(title: str, body: str) -> bool:
    """Require the software noun to be grammatically tied to THIS page's title."""
    plain = re.sub(r"[`*_#]+", " ", body[:4000])
    plain = re.sub(r"\s+", " ", plain).strip()
    named = re.escape(title)
    direct = re.search(
        rf"\b{named}\b\s+(?:is|was)\s+(?P<prefix>[^.;:]{{0,80}}?)\b{_SOFTWARE_KIND}\b",
        plain,
        re.I,
    )
    if direct:
        prefix_words = re.findall(r"[a-z]+", direct.group("prefix").lower())
        safe_descriptors = {
            "a", "an", "the", "commercial", "custom", "malicious", "modular", "new",
            "newly", "previously", "python", "remote", "sophisticated", "unreported", "windows",
        }
        suffix_words = re.findall(r"[a-z]+", plain[direct.end():direct.end() + 70].lower())[:6]
        category_suffix = {
            "actor", "actors", "affiliate", "affiliates", "cartel", "cluster", "gang", "group",
            "operation", "operator", "operators", "team", "threat",
        }
        if set(prefix_words) <= safe_descriptors and not category_suffix.intersection(suffix_words):
            return True
    return bool(
        re.search(
            rf"\b{_SOFTWARE_KIND}\b\s*,?\s*(?:dubbed|named|called)\s+{named}\b",
            plain,
            re.I,
        )
    )


def _reserved_actor_titles(vault: Path) -> frozenset[str]:
    """Load the admission vocabulary from the governing pack schema."""
    for candidate in (vault / "schema.yaml", vault / "wiki" / "schema.yaml"):
        try:
            schema = yaml.safe_load(candidate.read_text(encoding="utf-8")) or {}
            configured = (
                (schema.get("identity_admission") or {})
                .get("actor", {})
                .get("excluded_exact_titles", ())
            )
        except (AttributeError, OSError, TypeError, yaml.YAMLError):
            continue
        values = configured.values() if isinstance(configured, dict) else configured
        if isinstance(values, (str, bytes)) or not hasattr(values, "__iter__"):
            return frozenset()
        return frozenset(_normalized(str(value)) for value in values if str(value).strip())
    return frozenset()


def classify(
    fm: dict, body: str, path: Path, reserved_titles: frozenset[str] = frozenset()
) -> tuple[str, str]:
    """Return ``(keep|tombstone|malware, reason)`` using high-precision evidence."""
    if str(fm.get("type") or "") != "actor" or str(fm.get("status") or "").lower() == "tombstoned":
        return "keep", "not a live actor"
    if _authority_backed(fm):
        return "keep", "authority-backed actor identity"
    title = _label(fm, path)
    normalized = _normalized(title)
    words = normalized.split()
    if normalized in reserved_titles:
        return "tombstone", f"geopolitical entity is an attribution value, not an actor: {title}"
    if normalized in GENERIC_ACTOR_LABELS:
        return "tombstone", f"generic actor label: {title}"
    if (len(words) <= 4 and words and words[-1] in _CATEGORY_END) or _VAGUE.intersection(words):
        return "tombstone", f"descriptive/template actor label: {title}"
    title_words = set(_normalized(title).split())
    actor_categories = {"actor", "cartel", "crew", "gang", "group", "operation", "operator", "team"}
    if _defines_software(title, body) or (
        _SOFTWARE_TITLE.search(title)
        and not actor_categories.intersection(title_words)
        and re.search(r"\b(?:this|the) ransomware\b", body, re.I)
    ):
        return "malware", f"page evidence defines {title} as software/tooling"
    return "keep", "no deterministic error evidence"


def _apply(path: Path, wiki: Path, fm: dict, body: str, action: str, reason: str, dry_run: bool) -> None:
    updated = dict(fm)
    if action == "tombstone":
        updated.update({
            "status": "tombstoned",
            "tombstone_reason": f"actor-identity-audit: {reason}",
            "last_updated": datetime.now(timezone.utc).date().isoformat(),
        })
    else:
        updated["type"] = "malware"
        updated["malware_type"] = "ransomware" if "ransomware" in f"{_label(fm, path)} {body}".lower() else "malware"
        updated["last_updated"] = datetime.now(timezone.utc).date().isoformat()
        updated["identity_audit_note"] = reason
        for field in _ACTOR_ACTIVITY_FIELDS:
            updated.pop(field, None)
    if dry_run:
        return
    # This is a type migration, not an enrichment merge: actor-only fields must be removed rather
    # than preserved by _okf_write's normal merge semantics. Replace the same canonical file
    # atomically, retaining the complete body and every non-actor field.
    head = yaml.safe_dump(updated, sort_keys=False, allow_unicode=True).rstrip()
    rendered = f"---\n{head}\n---\n\n{body.rstrip()}\n"
    temp = path.with_suffix(path.suffix + ".actor-audit.tmp")
    temp.write_text(rendered, encoding="utf-8")
    os.replace(temp, path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--vault", default=os.environ.get("WIKI_PATH", "/opt/vault"))
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args(argv)
    dry_run = not (args.apply or os.environ.get("ACTOR_IDENTITY_AUDIT_APPLY") == "1")
    wiki = content_root(Path(args.vault))
    reserved_titles = _reserved_actor_titles(Path(args.vault))
    counts = {"tombstone": 0, "malware": 0, "keep": 0}
    for path in sorted((wiki / "entities").rglob("*.md")) if (wiki / "entities").exists() else []:
        fm, body = _split(path)
        action, reason = classify(fm, body, path, reserved_titles)
        counts[action] += 1
        if action != "keep":
            print(f"{'DRY ' if dry_run else ''}{action}: {path.relative_to(wiki)} — {reason}")
            _apply(path, wiki, fm, body, action, reason, dry_run)
    print(
        "actor-identity-audit | "
        f"tombstoned {counts['tombstone']}, retyped malware {counts['malware']}, "
        f"kept {counts['keep']}, mode={'dry-run' if dry_run else 'apply'}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
