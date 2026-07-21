#!/usr/bin/env python3
"""Library-wide validation for okpacks-library (okpacks-library#26).

The per-pack `validate.py` checks each pack in isolation; this validates the CATALOG and the
CROSS-PACK invariants those validators can't see, in one place:

  - catalog.json ↔ each pack's `pack.yaml` / `engine.version` consistency (subsumes #15);
  - **unique pack names** and **unique cron IDs** across the whole library (a duplicate cron id
    would collide in a composed deployment's jobs.json);
  - **engine-pin coherence** (all packs targeting one engine release; outliers flagged);
  - **dev dependency metadata** present (requirements*.txt that CI + contributors rely on).

Complements, does not replace, the per-pack validators. Run from the repo root; exit 1 on any FAIL
(warnings never fail). Wired into `scripts/validate-all.sh` and the `okpacks` CLI.
"""
import json
import os
import re
from collections import defaultdict
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
fails: list[str] = []
warns: list[str] = []
_SERIES = re.compile(r"v(\d+)\.(\d+)\.\d+")


def fail(msg: str) -> None:
    fails.append(msg)


def warn(msg: str) -> None:
    warns.append(msg)


def _engine_version(text: str) -> str | None:
    """The `version:` pin from a pack's engine.version (a small YAML file)."""
    try:
        d = yaml.safe_load(text)
    except yaml.YAMLError:
        return None
    return str(d["version"]).strip() if isinstance(d, dict) and d.get("version") else None


def pack_dirs() -> list[Path]:
    return [d for d in sorted((ROOT / "packs").iterdir())
            if d.is_dir() and (d / "pack.yaml").exists()]


def check_catalog_consistency(catalog: dict) -> None:
    """Each catalog entry agrees with the pack's own pack.yaml / engine.version (#15)."""
    listed = {p.get("name") for p in catalog.get("packs", [])}
    for p in catalog.get("packs", []):
        name = p.get("name")
        sub = p.get("subdir")
        d = (ROOT / sub) if sub else None
        if not sub or not d.is_dir():
            fail(f"catalog: {name}: subdir {sub!r} does not exist")
            continue
        py = d / "pack.yaml"
        if not py.exists():
            fail(f"catalog: {name}: {sub}/pack.yaml missing")
        else:
            meta = yaml.safe_load(py.read_text()) or {}
            if meta.get("name") != name:
                fail(f"catalog: {name}: catalog name != pack.yaml name {meta.get('name')!r}")
            if p.get("trust") != meta.get("trust"):
                fail(f"catalog: {name}: catalog trust {p.get('trust')!r} != pack.yaml "
                     f"trust {meta.get('trust')!r}")
        ev = d / "engine.version"
        if not ev.exists():
            fail(f"catalog: {name}: engine.version missing")
        else:
            pin = _engine_version(ev.read_text())
            if p.get("engine_version") and pin and p["engine_version"] != pin:
                fail(f"catalog: {name}: catalog engine_version {p.get('engine_version')!r} != "
                     f"engine.version {pin!r}")
        if not p.get("validated_against"):
            fail(f"catalog: {name}: catalog entry missing 'validated_against'")

    for pd in pack_dirs():
        if pd.name not in listed:
            fail(f"catalog: pack {pd.name!r} has pack.yaml but no catalog.json entry")


def check_unique_pack_names(catalog: dict) -> None:
    """Pack names must be unique across the library (catalog entries + pack.yaml)."""
    seen: dict[str, list[str]] = defaultdict(list)
    for p in catalog.get("packs", []):
        if p.get("name"):
            seen[p["name"]].append("catalog.json")
    for pd in pack_dirs():
        meta = yaml.safe_load((pd / "pack.yaml").read_text()) or {}
        if meta.get("name"):
            seen[meta["name"]].append(f"packs/{pd.name}/pack.yaml")
    # a name listed once per source is fine; flag a name that two different DIRS claim
    dir_names = [yaml.safe_load((pd / "pack.yaml").read_text()).get("name") for pd in pack_dirs()]
    for nm, count in {n: dir_names.count(n) for n in dir_names}.items():
        if nm and count > 1:
            fail(f"duplicate pack name {nm!r} declared by {count} pack dirs")


def check_unique_cron_ids() -> None:
    """Cron job IDs must be unique across ALL packs — a collision would clobber a job in a
    composed deployment's jobs.json."""
    owners: dict[str, list[str]] = defaultdict(list)
    for pd in pack_dirs():
        crons = pd / "crons" / "domain-crons.json"
        if not crons.exists():
            continue
        try:
            jobs = json.loads(crons.read_text())
        except json.JSONDecodeError as e:
            fail(f"{pd.name}: crons/domain-crons.json invalid JSON — {e}")
            continue
        for job in jobs:
            jid = job.get("id")
            if jid:
                owners[jid].append(f"{pd.name}:{job.get('name', '?')}")
    for jid, where in owners.items():
        if len(where) > 1:
            fail(f"duplicate cron id {jid!r} used by {len(where)} jobs: {', '.join(where)}")


def check_unique_port_offsets() -> None:
    """Host `port_offset` must be UNIQUE across deployable packs. On a multi-pack host several
    stacks run at once, so two packs with the same offset bind the same reader/mcp host ports and
    the second fails 'address already in use'. Offset 0 is the shared baseline for the example/demo
    pack; every other pack must claim its own (pack-library audit)."""
    seen: dict = defaultdict(list)
    for pd in pack_dirs():
        meta = yaml.safe_load((pd / "pack.yaml").read_text()) or {}
        off = meta.get("port_offset")
        if off is not None:
            seen[int(off)].append(pd.name)
    # offset 0 is the intentional baseline for exactly ONE demo/example pack; >1 at any offset collides
    for off, packs in sorted(seen.items()):
        if len(packs) > 1:
            fail(f"port_offset {off} shared by {len(packs)} packs: {', '.join(sorted(packs))} — "
                 "they bind identical host reader/mcp ports; give each deployable pack a unique offset")


def check_cron_scripts_exist() -> None:
    """Every cron lane's `script` must resolve to a real file — either in the pack's own
    crons/scripts/ or (for a shared lane) the engine's scripts/cron/ or an extension. A lane
    pointing at a missing script fails SILENTLY every tick (ingests nothing). Engine-aware: needs
    the engine checkout to know the shared inventory; SKIPS (cannot verify) when ENGINE_DIR is
    unresolvable, so it never false-fails on an engine-provided script (pack-library audit)."""
    eng = Path(os.environ.get("ENGINE_DIR") or (Path.home() / "MEGA" / "Source" / "okengine"))
    if not (eng / "scripts" / "cron").is_dir():
        print(f"  (skip cron-script existence: engine checkout not found at {eng} — set ENGINE_DIR)")
        return
    engine_scripts = {p.name for p in (eng / "scripts" / "cron").glob("*.py")}
    engine_scripts |= {p.name for p in (eng / "scripts").glob("*.py")}
    for ext in (eng / "extensions").glob("*/"):
        engine_scripts |= {p.name for p in ext.glob("*.py")}
    for pd in pack_dirs():
        crons = pd / "crons" / "domain-crons.json"
        if not crons.exists():
            continue
        try:
            jobs = json.loads(crons.read_text())
        except json.JSONDecodeError:
            continue   # check_unique_cron_ids already fails on invalid JSON
        pack_scripts = {p.name for p in (pd / "crons" / "scripts").glob("*.py")}
        for job in jobs:
            s = (job.get("script") or "").strip()
            if not s:
                continue
            base = s.split("/")[-1]
            if base not in pack_scripts and base not in engine_scripts:
                fail(f"{pd.name}: cron {job.get('name', '?')!r} references script {base!r} that "
                     "exists in neither the pack's crons/scripts/ nor the engine — dead lane (fails every tick)")


def check_engine_coherence() -> None:
    """All packs should target one engine release; flag outliers (a lagging pin is legal during
    migration, so WARN, not FAIL)."""
    pins: dict[str, str] = {}
    for pd in pack_dirs():
        ev = pd / "engine.version"
        if ev.exists():
            pin = _engine_version(ev.read_text())
            if pin:
                pins[pd.name] = pin
    distinct = set(pins.values())
    if len(distinct) > 1:
        warn(f"packs pin {len(distinct)} different engine versions "
             f"({', '.join(f'{k}={v}' for k, v in sorted(pins.items()))}) — confirm this is "
             f"intentional (a pack may lag mid-migration)")



def _engine_release() -> "str | None":
    """The `engine_release` of the engine this library is validated against — OKENGINE_DIR, else a
    sibling ../okengine checkout. None if not locatable (the check then WARNs, never a vacuous pass)."""
    for cand in (os.environ.get("OKENGINE_DIR"), str(ROOT.parent / "okengine")):
        mf = Path(cand) / "engine-manifest.yaml" if cand else None
        if mf and mf.is_file():
            try:
                d = yaml.safe_load(mf.read_text()) or {}
            except Exception:
                return None
            v = str(d.get("engine_release") or "").strip()
            return v if _SERIES.fullmatch(v) else None
    return None


def check_engine_currency() -> None:
    """Every pack's engine.version must be the SAME release series (vMAJOR.MINOR) as the engine this
    library is validated against. The engine's OWN `framework validate` (run at pull AND deploy)
    hard-FAILs on a cross-series pin, so a lagging pack is UNINSTALLABLE from a fresh pull. The gate
    used to check only that packs agreed with EACH OTHER (check_engine_coherence), so a whole library
    lagging one engine minor passed silently and every from-scratch install died at the version gate
    (the v0.10.8-vs-v0.11.3 drift). This is that missing currency check, at the earliest gate. If the
    engine isn't locatable, currency is undetectable -> WARN, never a vacuous pass (set OKENGINE_DIR)."""
    eng = _engine_release()
    if not eng:
        warn("engine-currency: engine-manifest.yaml not found (set OKENGINE_DIR) — pack "
             "engine.version currency vs the engine is undetectable")
        return
    e_series = _SERIES.match(eng).groups()
    for pd in pack_dirs():
        ev = pd / "engine.version"
        if not ev.exists():
            continue
        pin = _engine_version(ev.read_text())
        m = _SERIES.match(pin or "")
        if not m:
            continue                        # malformed/absent pin is check_catalog_consistency's job
        if m.groups() != e_series:
            fail(f"{pd.name}: engine.version {pin} is a different release series than the engine "
                 f"({eng}) — uninstallable (framework validate FAILs at pull/deploy). Re-validate "
                 f"against {eng} and bump engine.version.")



def check_conformance_standalone() -> None:
    """Conformance suites must be STANDALONE-runnable: conformance-all.sh executes them with plain
    python, and the public CI conformance env installs requirements-dev.txt only — NO pytest. A
    module-level `import pytest` passes every local gate (dev machines have pytest) and then crashes
    the whole suite in public CI (bit the v0.11.3/v0.11.4 snapshots via okpack-vuln's
    test_cve_mentions). Guarded/lazy imports inside a try block are fine; the module level is not."""
    for pd in pack_dirs():
        conf = pd / "conformance"
        if not conf.is_dir():
            continue
        for py in sorted(conf.glob("*.py")):
            for i, line in enumerate(py.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                s = line.strip()
                if s.startswith(("import pytest", "from pytest")):
                    fail(f"{pd.name}/conformance/{py.name}:{i}: module-level pytest import — "
                         f"conformance suites run WITHOUT pytest in public CI (standalone python); "
                         f"use tempfile + plain asserts (see sibling suites)")

def check_readme_engine_version(catalog: dict) -> None:
    """The top-level README's prose engine-version references must agree with the catalog's
    engine_version. Regression guard: the v0.10.1 re-pin bumped every pack + catalog.json but
    missed the README's 'OKEngine v0.10.0' line — a stale version shipped on the public mirror.
    Nothing enforced the README↔catalog agreement, so the earliest gate now does. If the README
    stops mentioning a version, that's undetectable here — WARN, never a vacuous pass."""
    readme = ROOT / "README.md"
    if not readme.exists():
        warn("README.md missing — engine-version consistency undetectable")
        return
    cat_vers = {p.get("engine_version") for p in catalog.get("packs", []) if p.get("engine_version")}
    if len(cat_vers) != 1:
        return  # engine-pin coherence is check_engine_coherence's job; nothing to compare against
    cat = next(iter(cat_vers))
    refs = re.findall(r"[Oo][Kk][Ee]ngine\s+(v\d+\.\d+\.\d+)", readme.read_text())
    if not refs:
        warn("README.md references no OKEngine version — consistency undetectable "
             "(fine if intentional; this check can't see a stale number that isn't there)")
        return
    stale = sorted({r for r in refs if r != cat})
    if stale:
        fail(f"README.md references OKEngine {', '.join(stale)} but the catalog pins {cat} — "
             f"update the README with the re-pin")


def check_dev_deps() -> None:
    """The dependency manifests CI + contributors install from must exist (#18)."""
    for req in ("requirements.txt", "requirements-dev.txt"):
        if not (ROOT / req).exists():
            fail(f"{req} missing — CI and contributors install dependencies from it (#18)")


def check_vendored_helpers() -> None:
    """Helpers vendored per pack (so a pulled pack is self-contained) must stay identical across
    their copies. Currently: okpack_run_report.py (the importer run-marker helper, #25)."""
    for helper in ("crons/scripts/okpack_run_report.py",):
        copies = sorted(p / helper for p in pack_dirs() if (p / helper).exists())
        if len(copies) < 2:
            continue
        base = copies[0].read_text()
        for c in copies[1:]:
            if c.read_text() != base:
                fail(f"vendored helper drift: {c.relative_to(ROOT)} differs from "
                     f"{copies[0].relative_to(ROOT)} — keep the copies identical")


def _base_scaffold() -> tuple[set[str], set[str]]:
    """The OKF base scaffold = what the okpack-example template owns. Co-ownership of these across
    packs is EXPECTED (one `source`/`concept`/`prediction` serves every domain in a composed vault);
    only DOMAIN types/namespaces must be disjoint. Derived from the template so it stays in sync."""
    ex = ROOT / "packs" / "okpack-example" / "pack.yaml"
    if ex.exists():
        owns = (yaml.safe_load(ex.read_text()) or {}).get("owns") or {}
        return set(owns.get("types") or []), set(owns.get("namespaces") or [])
    return ({"source", "concept", "prediction", "finding", "dashboard"},
            {"sources", "concepts", "predictions", "findings", "entities", "briefings"})


def _req_name(req: str) -> str:
    """Pack name from a `requires` entry like 'okpack-base@>=0.1.0'."""
    return str(req).split("@", 1)[0].strip()


def check_composition(catalog: dict) -> None:
    """Simulate composing the public packs into one vault and check the engine's composition rules
    (#22): `requires` resolve + are trust-compatible; DOMAIN types/namespaces are disjoint across the
    set (the OKF base scaffold is shared, not a conflict); and no pack's type ALIAS collides with a
    type another pack owns. The engine re-validates the full composed set at deploy; this is the
    offline, all-public-packs scenario."""
    metas = {pd.name: (yaml.safe_load((pd / "pack.yaml").read_text()) or {}) for pd in pack_dirs()}
    catalog_names = {p.get("name") for p in catalog.get("packs", [])}
    trust_of = {m.get("name"): m.get("trust") for m in metas.values()}
    base_types, base_ns = _base_scaffold()

    # requires must resolve to a catalog pack and stay within one trust level (applies to any pack)
    for m in metas.values():
        nm = m.get("name")
        for req in m.get("requires") or []:
            rn = _req_name(req)
            if rn not in catalog_names:
                fail(f"composition: {nm} requires {rn!r} — not in the catalog")
            elif trust_of.get(rn) and trust_of.get(nm) and trust_of[rn] != trust_of[nm]:
                fail(f"composition: {nm} ({trust_of[nm]}) requires {rn} ({trust_of[rn]}) — packs "
                     f"compose only within one trust level")

    # the all-public composition set: DOMAIN ownership must be disjoint (base scaffold is shared).
    # kind: bundle packs (okengine#181) own nothing and compose other packs — exclude them from
    # the ownership scan and validate their RECIPE separately below.
    public = [m for m in metas.values()
              if m.get("trust") == "public" and m.get("kind") != "bundle"]
    type_owners: dict[str, list[str]] = defaultdict(list)
    ns_owners: dict[str, list[str]] = defaultdict(list)
    for m in public:
        owns = m.get("owns") or {}
        for t in owns.get("types") or []:
            type_owners[t].append(m.get("name"))
        for n in owns.get("namespaces") or []:
            ns_owners[n].append(m.get("name"))
    for t, owners in sorted(type_owners.items()):
        if len(owners) > 1 and t not in base_types:
            fail(f"composition: domain type {t!r} owned by {len(owners)} public packs "
                 f"({', '.join(owners)}) — they can't share one vault")
    for n, owners in sorted(ns_owners.items()):
        if len(owners) > 1 and n not in base_ns:
            fail(f"composition: domain namespace {n!r} owned by {len(owners)} public packs "
                 f"({', '.join(owners)}) — they can't share one vault")

    # type ALIAS in one pack colliding with a type another pack OWNS is ambiguous on a shared write
    owned_by = {t: owners[0] for t, owners in type_owners.items()}
    for pd, m in metas.items():
        if m.get("trust") != "public":
            continue
        sch = ROOT / "packs" / pd / "schema.yaml"
        if not sch.exists():
            continue
        aliases = (yaml.safe_load(sch.read_text()) or {}).get("type_aliases") or {}
        for alias in aliases:
            owner = owned_by.get(alias)
            if owner and owner != m.get("name"):
                fail(f"composition: {m.get('name')} aliases type {alias!r} but {owner} OWNS it as a "
                     f"canonical type — remove/migrate the alias before these packs can compose")

    # kind: bundle recipe check (okengine#181), offline mirror of the engine's
    # validate_bundle_recipe — catch a malformed recipe at the library gate, not just at deploy.
    for m in metas.values():
        if m.get("kind") != "bundle":
            continue
        _check_bundle_recipe(m, catalog_names, metas)


def _check_bundle_recipe(m: dict, catalog_names: set, metas: dict) -> None:
    """A bundle owns nothing and composes real packs: a `host` base vault + a non-empty
    `compose` list (host excluded), every member catalogued and declared in `requires`, and
    no nesting. Mirrors scripts/pack_meta.validate_bundle_recipe in the engine."""
    nm = m.get("name")
    owns = m.get("owns") or {}
    if owns.get("types") or owns.get("namespaces"):
        fail(f"composition: bundle {nm!r} must own nothing (owns.types/namespaces must be empty)")
    recipe = m.get("bundle") or {}
    host = recipe.get("host")
    compose = recipe.get("compose") or []
    if not host:
        fail(f"composition: bundle {nm!r} has no bundle.host")
    if not compose:
        fail(f"composition: bundle {nm!r} has an empty bundle.compose")
    if host and host in compose:
        fail(f"composition: bundle {nm!r} lists its host {host!r} in bundle.compose")
    by_name = {mm.get("name"): mm for mm in metas.values()}
    reqs = {_req_name(r) for r in (m.get("requires") or [])}
    for mem in dict.fromkeys(([host] if host else []) + list(compose)):
        if mem not in catalog_names:
            fail(f"composition: bundle {nm!r} composes {mem!r} — not in the catalog")
        if mem not in reqs:
            fail(f"composition: bundle {nm!r} composes {mem!r} but does not list it in requires")
        if by_name.get(mem, {}).get("kind") == "bundle":
            fail(f"composition: bundle {nm!r} composes {mem!r} which is itself a bundle (no nesting)")


def main() -> int:
    try:
        catalog = json.loads((ROOT / "catalog.json").read_text())
    except (OSError, json.JSONDecodeError) as e:
        print(f"library validation FAILED: cannot read catalog.json — {e}")
        return 1

    check_catalog_consistency(catalog)
    check_unique_pack_names(catalog)
    check_unique_cron_ids()
    check_unique_port_offsets()
    check_cron_scripts_exist()
    check_engine_coherence()
    check_engine_currency()
    check_conformance_standalone()
    check_readme_engine_version(catalog)
    check_dev_deps()
    check_vendored_helpers()
    check_composition(catalog)

    for w in warns:
        print(f"WARN  {w}")
    for f in fails:
        print(f"FAIL  {f}")
    if fails:
        print(f"\nlibrary validation FAILED — {len(fails)} failure(s), {len(warns)} warning(s).")
        return 1
    n = len(catalog.get("packs", []))
    print(f"library valid — {n} packs, catalog + cross-pack invariants OK ({len(warns)} warning(s)).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
