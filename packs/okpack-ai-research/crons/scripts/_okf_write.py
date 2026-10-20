#!/usr/bin/env python3
"""Shared OKF page-write helpers for the okpack-threat-actors no_agent importers.

Co-located with the importer scripts (staged together into /opt/data/scripts by
deploy-cron-scripts.sh), so `from _okf_write import ...` resolves at runtime — the same
pattern the other packs use for their shared cron libs. stdlib + PyYAML only.

The importers are AUTHORITATIVE for the fields THEY source (attack_id, aliases, tactic,
the relationship link block) but must NOT clobber fields OWNED BY OTHER LANES —
`attribution_confidence` (entity-backfill), `related_actors` (actor_correlation),
`needs_review`, curated `tags`. `write_page` therefore MERGES: it preserves every existing
frontmatter key, overlays the importer's fields, and UNIONS list fields like aliases/tags.
"""
from __future__ import annotations

import hashlib
import os
import re
from urllib.parse import urlsplit
import sys
from pathlib import Path

import yaml

# okf_migrate is the engine cron lib, staged alongside pack scripts in /opt/data/scripts. Import it
# DEFENSIVELY: if it isn't on the path (e.g. a pack-only test env, or a deploy that staged pack
# scripts but not engine scripts), write_page falls back to its legacy flat behavior rather than
# crashing every importer (okengine#54).
try:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import okf_migrate
except Exception:  # noqa: BLE001
    okf_migrate = None

# importer_guard is the engine-owned boundary for deterministic direct writers (#237). It is
# staged beside pack scripts in production. Keep pack-only tooling usable when the engine checkout
# is absent, matching the okf_migrate compatibility behavior above.
try:
    from importer_guard import guard as _importer_guard
except Exception:  # noqa: BLE001
    _importer_guard = None

try:
    import authority_lib
except Exception:  # noqa: BLE001
    authority_lib = None

# id_lib is the GOVERNED identity library -- the same one cron-plus's slug_identity_guard loads to
# decide what counts as a separator-equivalent page. Importing it here rather than re-deriving the
# rule is the point: a writer that computed identity its own way would disagree with the guard, and
# the disagreement would only surface as a quarantined page and a failed run (okengine#647).
try:
    import id_lib
except Exception:  # noqa: BLE001
    id_lib = None

# schema_lib resolves the governing type's `id_authority` binding and id_index answers "is this id
# already held by a live page?". Both are engine cron libs staged beside id_lib. A page is only
# CREATED when all of them are importable: without them the helper cannot mint the id the engine
# would, and an id-less page is one the enforced write path can never update or tombstone
# (okpacks-library#105). Updates of an existing page do not need them.
try:
    import schema_lib
except Exception:  # noqa: BLE001
    schema_lib = None

try:
    import id_index
except Exception:  # noqa: BLE001
    id_index = None

# namespace -> {slug_identity: rel}. Built once per process and updated on write, so an importer
# that mints hundreds of pages does not re-walk the namespace per page, and cannot create two
# spellings of the SAME new entity within a single run.
_IDENTITY_INDEX: dict = {}


def _identity_index(vault: "Path", namespace: str) -> dict:
    cached = _IDENTITY_INDEX.get(namespace)
    if cached is not None:
        return cached
    index: dict = {}
    root = vault / namespace
    if id_lib is not None and root.is_dir():
        for page in root.rglob("*.md"):
            if page.name.startswith(("_", ".")):
                continue
            key = id_lib.slug_identity(page.stem)
            if key:
                index.setdefault(key, str(page.relative_to(vault))[:-3])
    _IDENTITY_INDEX[namespace] = index
    return index


# vault -> {id: wiki-relative path without ".md"}. Seeded once per process from the engine id-index
# (the persisted artifact when present, else a scan) and extended by every page this process
# creates, so two records in one run cannot both claim an id either.
_ID_CLAIMS: dict = {}

_REAL_URL = re.compile(r"^https?://[^\s/]+", re.I)
# A bare service endpoint (okengine#901): every record read from it shares the URL, so it identifies a
# service, not a document. A copy of the engine's `state._SERVICE_ENDPOINT_PATH` /
# `_is_service_endpoint_url`, pinned by tests/test_okf_write_page_id.py.
_SERVICE_ENDPOINT_PATH = re.compile(
    r"(?:/(?:Map|Feature)Server(?:/\d+)?"
    r"|/query"
    r"|/resource/[a-z0-9]{4}-[a-z0-9]{4}\.(?:json|csv|geojson|xml))"
    r"/?$",
    re.I,
)


def _is_service_endpoint_url(value) -> bool:
    """Whether `value` is a bare service endpoint: an address, but of a service, not a record."""
    text = str(value or "").strip()
    if not _REAL_URL.match(text):
        return False
    try:
        parts = urlsplit(text)
    except ValueError:
        return False
    return not parts.query and bool(_SERVICE_ENDPOINT_PATH.search(parts.path))


def _source_url_id(url) -> str:
    """The URL identity of a `source` page: `sources:url-<sha256(url)[:20]>` (okengine#515/#862).

    A faithful copy of the engine's `source_url_id` (write path + reid_sources_by_url): whitespace
    and ONE trailing slash normalized, no case folding, and a non-http placeholder or a bare service
    endpoint (okengine#901) is no identity.
    It is copied rather than imported because the engine's copy lives in the baked write-path
    package, which is not staged beside pack scripts. tests/test_okf_write_page_id.py pins it to the
    engine function."""
    text = str(url or "").strip()
    if not text or not _REAL_URL.match(text) or _is_service_endpoint_url(text):
        return ""
    text = text[:-1] if text.endswith("/") and len(text) > 1 else text
    return "sources:url-" + hashlib.sha256(text.encode("utf-8")).hexdigest()[:20]


def missing_identity_libs() -> list:
    """Engine libs a page CREATE needs; empty when an id can be derived and checked."""
    return [n for n, m in (("id_lib", id_lib), ("schema_lib", schema_lib), ("id_index", id_index))
            if m is None]


def derive_page_id(vault: "Path", rel: str, fm: dict) -> tuple:
    """(id, kind) the engine assigns a new page at wiki-relative `rel` with frontmatter `fm`.

    A caller-supplied `id` is the caller's identity decision and is kept as given. Otherwise the
    derivation is OKEngine `backfill_ids.derive_for_page`'s (and the write path's
    `_page_id_and_kind`'s): the governing type's `id_authority` binding gives an authority id
    (`mitre:t1059`); else a slug minted in the page's namespace from its natural key
    (`entities:acme-corp`). The one addition is the engine's URL identity for a `source` page with
    a real url, which converge_source, raw-compile and reid_sources_by_url all assign -- a slug
    there would fork the page raw-compile mints for the same URL (okengine#886). Requires
    `missing_identity_libs()` to be empty."""
    rel = rel[:-3] if rel.endswith(".md") else rel
    explicit = fm.get("id")
    if explicit is not None and str(explicit).strip():
        return str(explicit).strip(), "explicit"
    namespace = rel.split("/", 1)[0]
    if str(fm.get("type") or "").strip() == "source" and namespace == "sources":
        url_id = _source_url_id(fm.get("url"))
        if url_id:
            return url_id, "authority"
    schema = schema_lib.merged_schema(vault.parent, namespace)
    authority, id_field = schema_lib.type_id_authority(schema, str(fm.get("type") or "").strip())
    return id_lib.derive_id(authority=authority,
                            local_id=fm.get(id_field) if authority else None,
                            minted_scope=namespace,
                            slug_source=id_lib.natural_key(fm, fallback=Path(rel).name))


def _id_claims(vault: "Path") -> dict:
    key = str(vault)
    claims = _ID_CLAIMS.get(key)
    if claims is None:
        idx = id_index.load() or id_index.build(vault.parent, force=True)
        claims = {}
        for pid, holder in idx.by_id.items():       # live AND tombstoned holders
            claims[pid] = holder[:-3] if holder.endswith(".md") else holder
        _ID_CLAIMS[key] = claims
    return claims


def _claim_new_id(vault: "Path", rel: str, fm: dict):
    """The id a NEW page at `rel` gets, or None when it must not be created.

    A derived id already held by a different page -- live or tombstoned -- is never claimed twice:
    an authority id is a genuine duplicate of an existing record (a merge, which an importer may
    not decide), so the create is refused; a minted slug collides by design and is disambiguated
    with a path-stable hash exactly as `backfill_ids` does. Both are reported."""
    pid, kind = derive_page_id(vault, rel, fm)
    holder = _id_claims(vault).get(pid)
    if holder is None or holder == rel:
        return pid
    if kind != "slug":
        print(f"WARN: id collision: not creating {rel}.md — its {kind} id {pid!r} is already held "
              f"by {holder}.md. Two pages for one record need a merge, not a second claimant "
              f"(okpacks-library#105).", file=sys.stderr)
        return None
    scope = id_lib.parse_id(pid)[0]
    disambiguated = id_lib.make_id(scope, f"{Path(rel).name}-{id_lib._short_hash(rel + '.md', 6)}")
    print(f"WARN: slug id {pid!r} is held by {holder}.md; {rel}.md gets {disambiguated!r} "
          f"(disambiguated as backfill_ids does).", file=sys.stderr)
    return disambiguated


_SLUG = re.compile(r"[^a-z0-9]+")
# list-valued fields that should be UNIONED (not replaced) on re-import, so enrichment survives
_UNION_FIELDS = frozenset({"aliases", "tags", "related", "sources", "platforms"})
# fields an importer must never overwrite if another lane already set them. (related_actors is NOT
# here: no importer emits it, so it's preserved automatically; and the correlation lane must REPLACE
# it wholesale each run — a fresh computation, not an ever-growing union.)
_PRESERVE_IF_SET = frozenset({"attribution_confidence", "needs_review", "confidence"})


def slug(s: str) -> str:
    return _SLUG.sub("-", (s or "").lower()).strip("-")[:80] or "untitled"


def clean(text: str, cap: int = 4000) -> str:
    t = re.sub(r"<[^>]+>", "", text or "").strip()
    return re.sub(r"[ \t]+\n", "\n", t)[:cap]


def _split_frontmatter(md: str) -> tuple[dict, str]:
    """Return (frontmatter dict, body) from an existing page; ({}, whole) if none."""
    if md.startswith("---"):
        end = md.find("\n---", 3)
        if end != -1:
            try:
                fm = yaml.safe_load(md[3:end]) or {}
            except yaml.YAMLError:
                fm = {}
            body = md[end + 4:].lstrip("\n")
            return (fm if isinstance(fm, dict) else {}), body
    return {}, md


def _merge_fm(existing: dict, incoming: dict) -> dict:
    """existing (on disk) UNDER incoming (importer), preserving other-lane fields + unioning lists."""
    out = dict(existing)
    for k, v in incoming.items():
        if k in _PRESERVE_IF_SET and existing.get(k) not in (None, "", []):
            continue                                   # another lane owns it — leave it
        if k in _UNION_FIELDS and isinstance(v, list):
            seen, merged = set(), []
            for item in (existing.get(k) or []) + v:   # preserve existing order, append new
                key = str(item).lower()
                if key not in seen:
                    seen.add(key)
                    merged.append(item)
            out[k] = merged
        else:
            out[k] = v
    return out



def _actor_source_error(vault: Path, fm: dict) -> str | None:
    """Use existing confined source bodies; missing/unreadable references remain unknown."""
    try:
        from okengine.actor_identity import actor_source_identity_error
    except ImportError as exc:
        raise RuntimeError("actor source validation requires the installed OKEngine actor identity guard") from exc
    title = str(fm.get("title") or fm.get("name") or "")
    bodies = []
    sources = fm.get("sources")
    if sources is None:
        sources = fm.get("source")
    sources = sources or []
    if isinstance(sources, str):
        sources = [sources]
    for source in sources:
        if not isinstance(source, str):
            continue
        ref = source.strip().strip("[]").removeprefix("wiki/").removesuffix(".md")
        parts = Path(ref).parts
        if not parts or Path(ref).is_absolute() or ".." in parts or "\\" in ref:
            continue
        # Match the existing engine schema walk-up convention for subdomains.
        i = 0
        while i < len(parts) - 1 and (vault.joinpath(*parts[:i + 1]) / "schema.yaml").is_file():
            i += 1
        if parts[i] != "sources":
            continue
        page = vault / (ref + ".md")
        try:
            page.resolve().relative_to(vault.resolve())
            source_fm, body = _split_frontmatter(page.read_text(encoding="utf-8"))
            heading, separator, remainder = body.lstrip().partition("\n")
            source_title = str(source_fm.get("title") or "").strip()
            if source_title and separator and re.fullmatch(r"#\s+" + re.escape(source_title) + r"\s*", heading, re.I):
                body = remainder
            bodies.append(body)
        except (OSError, ValueError, UnicodeError, yaml.YAMLError):
            continue
    return actor_source_identity_error(title, bodies)

def write_page(vault: Path, rel_path: str, fm: dict, body: str, *, dry_run: bool = False,
               authority_policy: dict | None = None, authority_record: dict | None = None,
               reviewed_at: str | None = None, require_actor: bool = False) -> str:
    """Create-or-MERGE an OKF page. Returns 'created' | 'updated' | 'dry'. Frontmatter keys with
    empty/None values are dropped. `body` replaces the importer-owned body section wholesale.

    Partitioned namespaces are routed to the seat a WRITER must use -- `write_key`, which updates an
    existing page wherever it sits (the flat root OR a wrong-shaped shard) and gives a NEW page the
    `reshard_by` segment straight away. It is deliberately not `canonical_key`: that is the drain's
    BASE bucket, one level above where reshard_oversized keeps a split bucket, so minting there
    re-creates one-level strays every run for the nightly sweep to push back down -- 448 of them on
    one live vault between two sweeps, with every stored page path stale in between (okengine#818,
    #243). Merging against the existing copy keeps a partition-unaware rel_path from creating a
    duplicate the drain then re-shards (okengine#54). Flat namespaces keep rel_path verbatim; if
    the engine lib is unavailable, so does everything.

    A CREATED page always carries an `id` (okpacks-library#105): the caller's id, else the one the
    engine derives (`derive_page_id`). An existing page keeps its id -- a caller's id
    never replaces it. A create is refused -- 'collision' when the id belongs to another page,
    'unverifiable' when the engine identity libs are missing -- rather than land a page the write
    path could never update. Returns 'created' | 'updated' | 'dry' | 'collision' | 'unverifiable'."""
    rel = rel_path[:-3] if rel_path.endswith(".md") else rel_path
    existing = None
    if okf_migrate is not None:
        ns, slug_ = rel.split("/", 1)[0], rel.rsplit("/", 1)[-1]
        root = vault.parent                       # vault == WIKI_PATH/wiki; okf_migrate wants root
        if okf_migrate.is_partitioned(root, ns):
            existing = okf_migrate.find_page(root, ns, slug_)
            rel = okf_migrate.write_key(root, ns, slug_, fm)
    path = vault / (rel + ".md")
    src = existing if (existing and existing.exists()) else (path if path.exists() else None)
    # Creating a page whose slug differs from a live one only by separators is what cron-plus's
    # slug_identity_guard quarantines and FAILS the run over. Refuse it here instead, for two
    # reasons: the run then dispositions the record instead of dying on it, and the engine's rule
    # -- "weak spelling identity never auto-merges" (write_services/deduplication) -- is preserved,
    # because `check-point` and `checkpoint` may genuinely be different things. Reconciling the two
    # names is an identity decision, not something an importer may take silently.
    if src is None and id_lib is not None:
        ns_ = rel.split("/", 1)[0]
        ident = id_lib.slug_identity(rel.rsplit("/", 1)[-1])
        clash = _identity_index(vault, ns_).get(ident) if ident else None
        if clash and clash != rel:
            print(f"WARN: weak-identity collision: not creating {rel}.md — live page {clash}.md "
                  f"has the same separator-insensitive identity ({ident!r}). Not merged: spelling "
                  f"alone is weak identity evidence (okengine#647). Reconcile the names, then "
                  f"re-import.", file=sys.stderr)
            return "collision"
    action = "updated" if src is not None else "created"
    if src is not None:
        prev_fm, _ = _split_frontmatter(src.read_text(encoding="utf-8"))
        if require_actor and (prev_fm.get("type") != "actor" or str(prev_fm.get("status") or "").casefold() == "tombstoned" or prev_fm.get("redirect_to")):
            return "ineligible"
        fm = _merge_fm(prev_fm, fm)
        if prev_fm.get("id") not in (None, ""):
            fm["id"] = prev_fm["id"]               # identity is immutable (okpacks-library#105)
    else:
        if require_actor:
            return "ineligible"
        # Every created page carries the id the engine would mint, or is not created: the enforced
        # write path cannot update or tombstone an id-less page (okpacks-library#105).
        missing = missing_identity_libs()
        if missing:
            print(f"WARN: not creating {rel}.md — engine identity lib(s) {', '.join(missing)} not "
                  f"importable, so its id cannot be derived (okpacks-library#105).",
                  file=sys.stderr)
            return "unverifiable"
        pid = _claim_new_id(vault, rel, fm)
        if pid is None:
            return "collision"
        fm = {"id": pid, **{k: v for k, v in fm.items() if k != "id"}}
    if authority_policy is not None:
        # This is the sole exception to sticky review state: a direct-authority importer may clear
        # it only after the engine verifies the exact source, URL, identifier, type, provenance
        # marker, and absence of conflicts. Never silently degrade to an unreviewed write when the
        # policy engine is missing or refuses the record.
        if authority_lib is None:
            raise RuntimeError("authority policy requested but engine authority_lib is unavailable")
        fm.update(authority_lib.disposition(authority_record or fm, authority_policy,
                                            reviewed_at=reviewed_at))
    if _importer_guard is not None:
        namespace = rel.split("/", 1)[0]
        problems = _importer_guard(fm, vault=vault.parent, namespace=namespace)
        if problems:
            # Importers must not silently discard a source record. Land it visibly review-flagged
            # and name every boundary violation in the lane log; corpus_audit provides the standing
            # fleet view. A governed repair can then make the semantic mapping explicitly.
            fm["needs_review"] = True
            for problem in problems:
                print(f"WARN: importer guard {rel}: {problem}", file=sys.stderr)
    if str(fm.get("type") or "").strip().casefold() == "actor":
        try:
            from okengine.actor_identity import actor_identity_error
        except ImportError as exc:
            raise RuntimeError("actor validation requires the installed OKEngine actor identity guard") from exc
        if src is not None and str(prev_fm.get("status") or "").casefold() == "tombstoned" and str(fm.get("status") or "").casefold() != "tombstoned":
            raise ValueError("a tombstoned actor identity cannot be restored by an importer")
        if str(fm.get("status") or "").casefold() != "tombstoned":
            contradiction = actor_identity_error(str(fm.get("title") or fm.get("name") or path.stem), body)
            contradiction = contradiction or _actor_source_error(vault, fm)
            if contradiction:
                raise ValueError(f"actor write refused: source subject is {contradiction}")
    fm = {k: v for k, v in fm.items() if v not in (None, "", [], {})}
    if dry_run:
        return "dry"
    head = yaml.safe_dump(fm, sort_keys=False, allow_unicode=True, default_flow_style=False).rstrip()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"---\n{head}\n---\n\n{body.rstrip()}\n", encoding="utf-8")
    if id_lib is not None:
        ident = id_lib.slug_identity(rel.rsplit("/", 1)[-1])
        if ident:
            _identity_index(vault, rel.split("/", 1)[0]).setdefault(ident, rel)
    if action == "created":
        _id_claims(vault).setdefault(fm["id"], rel)
    if existing and existing.resolve() != path.resolve():   # collapse a stale flat/wrong-shard copy
        try:
            existing.unlink()
        except OSError:
            pass
    return action


def content_root(vault) -> "Path":
    """The OKF content root = <vault>/wiki. `WIKI_PATH` holds the VAULT ROOT (a misnomer); every engine
    component derives `WIKI = VAULT / "wiki"` (write_server.py:69, build_index_tree.py:36,
    backlinks_refresh.py:49), so match it EXACTLY — always append wiki/. Callers pass the vault root
    (== WIKI_PATH), NEVER the wiki dir. write_page creates wiki/ if absent (writer lanes); reader
    helpers see it empty (they guard on .exists())."""
    return Path(vault) / "wiki"
