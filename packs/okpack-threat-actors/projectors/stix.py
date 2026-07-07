"""Project okf-sec pages → STIX 2.1.

Pure stdlib for the core projection (PyYAML is imported lazily only to read a vault). Emits
JSON-able dicts in STIX 2.1 shape. IDs and timestamps are DERIVED deterministically from page
content (UUIDv5 + page dates), so the same page always yields the same bundle — which makes golden
conformance fixtures possible. Fields STIX 2.1 has no native home for ride an `x_okfsec_*` custom
property and are recorded as *documented loss* (§7 of the spec).

This is the reference projector for the conformance suite; at the v0.1 extraction it moves to the
`okf` repo. It proves the design on the well-specified types; remaining types fall through a generic
SDO path (common props + everything else as documented loss).

Link resolution: `rels`/wikilink targets resolve to a target page's *true* STIX id (its type +
identity field) via a whole-vault index (`build_vault_index`); without an index, a single page falls
back to the `[[entities/<type>/<slug>]]` path-shape heuristic.

API:  project_page(frontmatter, slug, resolver=None) -> {bundle, loss}   # one page → a STIX 2.1 bundle
      build_vault_index(vault_dir) -> {key: stix_id}        # index a vault for cross-link resolution
      project_vault(vault_dir) -> {slug: {bundle, loss}}    # project every page, links resolved
"""
from __future__ import annotations

import re
import uuid

# Fixed namespace for okf-sec deterministic id derivation (not a STIX-mandated value).
NS = uuid.UUID("6f9b9af4-0000-5e00-8a01-a1b2c3d4e5f6")
SPEC_VERSION = "2.1"

# okf-sec canonical type → default STIX SDO type. `source`→`report`; types with no SDO
# (software, detection, concept, finding, prediction, dashboard) get the generic x_okfsec path.
SDO_TYPE = {
    "vulnerability": "vulnerability", "attack-pattern": "attack-pattern",
    "threat-actor": "threat-actor", "intrusion-set": "intrusion-set", "malware": "malware",
    "tool": "tool", "campaign": "campaign", "indicator": "indicator",
    "infrastructure": "infrastructure", "identity": "identity",
    "course-of-action": "course-of-action", "source": "report",
}

ALIASES = {
    # The composable-pack canonical (friendly) names map onto their STIX SDO. `actor` is the
    # ATT&CK-group sense (G####) → intrusion-set; `publisher` (report authors) → identity.
    "actor": "intrusion-set", "publisher": "identity",
    "cve": "vulnerability", "technique": "attack-pattern", "ioc": "indicator",
    "host": "infrastructure", "product": "software", "group": "intrusion-set",
    "apt-group": "intrusion-set", "mitigation": "course-of-action", "ransomware": "malware",
    "ransomware-family": "malware", "vendor": "identity", "organization": "identity",
    "company": "identity", "person": "identity", "agency": "identity",
    "government-agency": "identity", "government-entity": "identity", "team": "identity",
}

# Well-known STIX TLP marking-definition ids (TLP 1.0 set; amber+strict maps to amber for v0.1).
TLP_MARKING = {
    "clear": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
    "green": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
    "amber": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
    "amber+strict": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
    "red": "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
}

# refs[].std → STIX external_references.source_name
REF_SOURCE_NAME = {
    "cve": "cve", "cwe": "cwe", "capec": "capec", "mitre-attack": "mitre-attack",
    "mitre-d3fend": "mitre-d3fend", "nvd": "nvd", "ghsa": "ghsa", "cpe": "cpe",
    "cisa-kev": "cisa-kev", "epss": "epss", "misp": "misp", "stix": "stix",
    "vendor-advisory": "vendor-advisory", "url": "url",
}

# rels predicate → (stix relationship_type, reversed?). Reverse aliases flip subject/object.
REL = {
    "uses": ("uses", False), "uses-technique": ("uses", False), "uses-malware": ("uses", False),
    "uses-tool": ("uses", False), "targets": ("targets", False),
    "attributed-to": ("attributed-to", False), "authored-by": ("authored-by", False),
    "owns": ("owns", False), "compromises": ("compromises", False), "exploits": ("exploits", False),
    "delivers": ("delivers", False), "downloads": ("downloads", False), "drops": ("drops", False),
    "variant-of": ("variant-of", False), "communicates-with": ("communicates-with", False),
    "beacons-to": ("beacons-to", False), "exfiltrates-to": ("exfiltrates-to", False),
    "controls": ("controls", False), "consists-of": ("consists-of", False), "hosts": ("hosts", False),
    "resolves-to": ("resolves-to", False), "indicates": ("indicates", False),
    "mitigates": ("mitigates", False), "subtechnique-of": ("subtechnique-of", False),
    "originates-from": ("originates-from", False), "located-at": ("located-at", False),
    "related-to": ("related-to", False),
    # reverse aliases (flip):
    "used-by": ("uses", True), "exploited-by": ("exploits", True), "mitigated-by": ("mitigates", True),
    "detected-by": ("x_okfsec_detects", True), "owned-by": ("owns", True), "hosted-by": ("hosts", True),
    "affected-by": ("x_okfsec_affects", True), "attributed-campaigns": ("attributed-to", True),
    # okf-native (no STIX SRO) → custom relationship_type string (valid: it's open-vocab):
    "detects": ("x_okfsec_detects", False), "affects": ("x_okfsec_affects", False),
}

# Envelope/handled keys that are NEVER documented loss (consumed by common-props or intentional).
_ENVELOPE = {
    "type", "name", "aliases", "description", "created", "updated", "first_seen", "last_seen",
    "confidence", "tlp", "sources", "tags", "refs", "rels", "stix", "related", "title",
    "cve_id", "mitre_id",
}


def normalize_type(t: str) -> str:
    return ALIASES.get(t, t)


def _did(stix_type: str, identity: str) -> str:
    return f"{stix_type}--{uuid.uuid5(NS, f'{stix_type}:{identity}')}"


def _ts(date) -> str | None:
    """A 'YYYY-MM-DD' page date → a STIX timestamp. None passes through."""
    if not date:
        return None
    s = str(date)
    return s if "T" in s else f"{s}T00:00:00.000Z"


def _confidence_num(conf) -> int | None:
    if conf is None:
        return None
    if isinstance(conf, (int, float)):
        return max(0, min(100, round(float(conf) * 100)))
    return {"low": 15, "medium": 50, "high": 85}.get(str(conf).lower())


def _undefang(value: str) -> str:
    return (str(value).replace("[.]", ".").replace("[:]", ":").replace("(.)", ".")
            .replace("hxxps", "https").replace("hxxp", "http").replace("[at]", "@"))


def _slugify(s) -> str:
    return re.sub(r"[^a-z0-9]+", "-", str(s).lower()).strip("-")


def _target_id(wikilink: str, resolver: dict | None = None) -> str | None:
    """Resolve a `[[...]]` link to a STIX id. With a vault `resolver` (from build_vault_index),
    resolve by the link's slug/name against the real page graph — the target page's true type +
    identity. Falls back to the `[[entities/<type>/<slug>]]` path-shape heuristic (single-page /
    dangling link)."""
    inner = wikilink.strip().strip("[]").strip()
    if not inner:
        return None
    parts = [p for p in inner.split("/") if p]
    if resolver:
        stem = parts[-1] if parts else inner
        for key in (stem.lower(), _slugify(stem), _slugify(inner)):
            if key in resolver:
                return resolver[key]
    if len(parts) >= 3 and parts[0] == "entities":
        stype = SDO_TYPE.get(normalize_type(parts[1]))
        if stype:
            return _did(stype, parts[-1])
    return None


def _pattern(ioc_type: str, value: str) -> str:
    v = _undefang(value)
    if ioc_type == "ip":
        kind = "ipv6-addr" if ":" in v else "ipv4-addr"
        return f"[{kind}:value = '{v}']"
    if ioc_type == "domain":
        return f"[domain-name:value = '{v}']"
    if ioc_type == "url":
        return f"[url:value = '{v}']"
    if ioc_type == "email":
        return f"[email-addr:value = '{v}']"
    if ioc_type == "hash":
        algo = "SHA-256" if len(v) == 64 else "MD5" if len(v) == 32 else "SHA-1"
        return f"[file:hashes.'{algo}' = '{v}']"
    return f"[x-okfsec:value = '{v}']"


def page_stix_id(page: dict, slug: str) -> str:
    """The STIX id a page projects to (its SDO type + identity field). Used for the page's own
    object id AND to resolve inbound links — so a link resolves to the SAME id the target emits,
    whatever the link's path shape."""
    okf_type = normalize_type(page.get("type"))
    stix_hint = page.get("stix") or {}
    stix_type = stix_hint.get("type") or SDO_TYPE.get(okf_type) or f"x-okfsec-{okf_type}"
    name = page.get("name") or page.get("title") or slug.replace("-", " ")
    ident = page.get("cve_id") or page.get("mitre_id") or page.get("value") or name
    return stix_hint.get("id") or _did(stix_type, ident)


def project_page(page: dict, slug: str, resolver: dict | None = None) -> dict:
    """Project one okf-sec page (its frontmatter dict) to a STIX 2.1 bundle. `resolver` (from
    build_vault_index) resolves cross-page links against the whole vault; None → single-page."""
    okf_type = normalize_type(page.get("type"))
    stix_hint = page.get("stix") or {}
    stix_type = stix_hint.get("type") or SDO_TYPE.get(okf_type)
    name = page.get("name") or page.get("title") or slug.replace("-", " ")
    consumed = set(_ENVELOPE)
    loss: dict = {}

    objects: list = []

    if stix_type is None:
        # No STIX SDO for this okf-sec type: emit a custom object carrying everything as loss.
        stix_type = f"x-okfsec-{okf_type}"

    ident = page.get("cve_id") or page.get("mitre_id") or page.get("value") or name
    obj = {
        "type": stix_type,
        "spec_version": SPEC_VERSION,
        "id": page_stix_id(page, slug),
        "created": _ts(page.get("created")) or "2026-01-01T00:00:00.000Z",
        "modified": _ts(page.get("updated") or page.get("created")) or "2026-01-01T00:00:00.000Z",
    }
    if page.get("description"):
        obj["description"] = page["description"]
    if page.get("aliases"):
        obj["aliases"] = page["aliases"]
    if page.get("tags"):
        obj["labels"] = page["tags"]
    c = _confidence_num(page.get("confidence"))
    if c is not None:
        obj["confidence"] = c
    if page.get("tlp") in TLP_MARKING:
        obj["object_marking_refs"] = [TLP_MARKING[page["tlp"]]]

    # name (most SDOs require it; report/identity/etc. all take it)
    if stix_type != "indicator":
        obj["name"] = name

    # external_references from refs[]
    ext = []
    for r in (page.get("refs") or []):
        e = {"source_name": REF_SOURCE_NAME.get(r.get("std"), r.get("std") or "url")}
        if r.get("id"):
            e["external_id"] = r["id"]
        if r.get("url"):
            e["url"] = r["url"]
        ext.append(e)
    # cve_id / mitre_id convenience mirrors → external_references if not already present
    if page.get("cve_id") and not any(e.get("external_id") == page["cve_id"] for e in ext):
        ext.append({"source_name": "cve", "external_id": page["cve_id"]})
    if page.get("mitre_id") and not any(e.get("external_id") == page["mitre_id"] for e in ext):
        ext.append({"source_name": "mitre-attack", "external_id": page["mitre_id"]})
    if ext:
        obj["external_references"] = ext

    # --- type-specific native mappings ---
    def take(*keys):
        consumed.update(keys)

    if stix_type == "vulnerability":
        for k in ("cwe", "capec"):
            for v in (page.get(k) or []):
                obj.setdefault("external_references", []).append(
                    {"source_name": k, "external_id": v})
            take(k)
        # cvss/epss/exploitation/affected/patched/severity have no native STIX slot → loss
    elif stix_type == "attack-pattern":
        if page.get("tactics"):
            obj["kill_chain_phases"] = [{"kill_chain_name": "mitre-attack", "phase_name": p}
                                        for p in page["tactics"]]
            take("tactics")
        for k, sk in (("is_subtechnique", "x_mitre_is_subtechnique"), ("platforms", "x_mitre_platforms"),
                      ("detection", "x_mitre_detection"), ("data_sources", "x_mitre_data_sources"),
                      ("version", "x_mitre_version")):
            if page.get(k) is not None:
                obj[sk] = page[k]
                take(k)
    elif stix_type == "threat-actor":
        if page.get("actor_class"):
            obj["threat_actor_types"] = [page["actor_class"]]
            take("actor_class")
        _actor_common(page, obj, take)
    elif stix_type == "intrusion-set":
        _actor_common(page, obj, take)
        take("actor_class")  # not a native intrusion-set field → drop quietly (kind implied by SDO)
    elif stix_type == "malware":
        obj["is_family"] = bool(page.get("is_family", True))
        take("is_family")
        if page.get("category"):
            obj["malware_types"] = [page["category"]]
            take("category")
        for k in ("first_seen", "last_seen"):
            if page.get(k):
                obj[k] = _ts(page[k])
    elif stix_type == "tool":
        if page.get("category"):
            obj["tool_types"] = [page["category"]]
            take("category")
    elif stix_type == "campaign":
        for k in ("first_seen", "last_seen"):
            if page.get(k):
                obj[k] = _ts(page[k])
    elif stix_type == "indicator":
        ioc_type, value = page.get("ioc_type"), page.get("value")
        obj["pattern"] = _pattern(ioc_type, value)
        obj["pattern_type"] = "stix"
        obj["valid_from"] = _ts(page.get("first_seen") or page.get("created")) or obj["created"]
        take("ioc_type", "value")
    elif stix_type == "infrastructure":
        if page.get("infra_type"):
            obj["infrastructure_types"] = [page["infra_type"]]
            take("infra_type")
    elif stix_type == "identity":
        if page.get("identity_class"):
            obj["identity_class"] = page["identity_class"]
            take("identity_class")
        if page.get("sector"):
            obj["sectors"] = page["sector"]
            take("sector")
    elif stix_type == "report":
        obj["published"] = _ts(page.get("published")) or obj["created"]
        take("published")
        refs = []
        for pred in ("related-to",):
            for link in (page.get("rels") or {}).get(pred, []):
                tid = _target_id(link if isinstance(link, str) else link.get("target", ""), resolver)
                if tid:
                    refs.append(tid)
        obj["object_refs"] = refs or [obj["id"]]  # report requires non-empty object_refs
        # source provenance/Admiralty have no STIX slot → loss
        take("source_kind", "publisher", "url", "raw")

    # --- documented loss: any remaining non-envelope field → x_okfsec_<field> ---
    for k, v in page.items():
        if k in consumed or v is None:
            continue
        obj[f"x_okfsec_{k}"] = v
        loss[k] = v

    objects.append(obj)

    # --- relationships → SROs (rels) ---
    src_id = obj["id"]
    for pred, targets in (page.get("rels") or {}).items():
        if pred in ("related-to",) and stix_type == "report":
            continue  # already folded into object_refs
        rtype, reverse = REL.get(pred, (f"x_okfsec_{pred}", False))
        for t in (targets if isinstance(targets, list) else [targets]):
            link = t if isinstance(t, str) else t.get("target")
            tid = _target_id(link or "", resolver)
            if not tid:
                continue
            a, b = (tid, src_id) if reverse else (src_id, tid)
            sro = {
                "type": "relationship", "spec_version": SPEC_VERSION,
                "id": _did("relationship", f"{a}|{rtype}|{b}"),
                "created": obj["created"], "modified": obj["modified"],
                "relationship_type": rtype, "source_ref": a, "target_ref": b,
            }
            if not isinstance(t, str):
                if t.get("confidence") is not None:
                    cv = _confidence_num(t["confidence"])
                    if cv is not None:
                        sro["confidence"] = cv
                if t.get("first_seen"):
                    sro["start_time"] = _ts(t["first_seen"])
                if t.get("description"):
                    sro["description"] = t["description"]
            objects.append(sro)

    bundle = {"type": "bundle", "id": _did("bundle", ident), "objects": objects}
    return {"bundle": bundle, "loss": sorted(loss.keys())}


def _actor_common(page: dict, obj: dict, take) -> None:
    if page.get("motivation"):
        m = page["motivation"]
        if m.get("primary"):
            obj["primary_motivation"] = m["primary"]
        if m.get("secondary"):
            obj["secondary_motivations"] = m["secondary"]
        take("motivation")
    for k in ("sophistication", "resource_level", "goals", "roles"):
        if page.get(k) is not None:
            obj[k] = page[k]
            take(k)
    for k in ("first_seen", "last_seen"):
        if page.get(k):
            obj[k] = _ts(page[k])


# --- whole-vault link resolution -------------------------------------------------------------

def _read_frontmatter(path) -> dict | None:
    """Parse a page's YAML frontmatter (the block between the leading `---` fences). None if absent
    or unparseable. PyYAML is imported lazily so the core projection stays stdlib."""
    import yaml  # lazy
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---"):
        return None
    end = text.find("\n---", 3)
    if end == -1:
        return None
    try:
        fm = yaml.safe_load(text[3:end])
    except Exception:  # noqa: BLE001
        return None
    return fm if isinstance(fm, dict) else None


def _index_keys(stem: str, fm: dict):
    """Lookup keys a link might use to reference a page: its file stem + slugified name/title/aliases."""
    keys = {stem.lower(), _slugify(stem)}
    for k in ("name", "title"):
        if fm.get(k):
            keys.add(_slugify(fm[k]))
    for a in (fm.get("aliases") or []):
        keys.add(_slugify(a))
    return {k for k in keys if k}


def _vault_pages(vault_dir):
    """Yield (path, frontmatter) for every typed page in a vault (`wiki/` if present, else the dir)."""
    from pathlib import Path
    root = Path(vault_dir) / "wiki"
    root = root if root.is_dir() else Path(vault_dir)
    for p in sorted(root.rglob("*.md")):
        fm = _read_frontmatter(p)
        if fm and fm.get("type"):
            yield p, fm


def build_vault_index(vault_dir) -> dict:
    """Index a vault's pages → their STIX ids, so rels/wikilink targets resolve against the real
    page graph (true type + identity) rather than the link-path shape. Keys: file stem and
    slugified name/title/aliases. First writer wins on a key collision (deterministic via sort)."""
    index: dict = {}
    for p, fm in _vault_pages(vault_dir):
        sid = page_stix_id(fm, p.stem)
        for key in _index_keys(p.stem, fm):
            index.setdefault(key, sid)
    return index


def project_vault(vault_dir) -> dict:
    """Project every typed page in a vault, resolving cross-page links against the whole-vault index.
    Returns {slug: {bundle, loss}}."""
    resolver = build_vault_index(vault_dir)
    return {p.stem: project_page(fm, p.stem, resolver=resolver) for p, fm in _vault_pages(vault_dir)}
