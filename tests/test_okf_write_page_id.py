"""`_okf_write.write_page` creates every page with the id the engine would mint (okpacks-library#105).

The shared helper used to create pages with no `id`. OKEngine's enforced write path cannot update,
link or tombstone such a page -- every later model-lane, entity-link or dedup write is refused with
"missing required field(s): id" (116 unlinkable model pages on one vault, okengine#888). A no_agent
writer bypasses the write SERVER, never its invariants, and identity is one.

The contract, proven here against the REAL engine libs from ENGINE_DIR:
  - an id-less create gets exactly the id `backfill_ids` would stamp on the same page (authority id
    from the governing type's `id_authority`, else a namespace-scoped slug), and a URL-bearing
    `source` gets the engine's URL identity;
  - an existing page's id is never replaced, and a caller-supplied id is kept;
  - a derived id another page already holds is never claimed twice: an authority id is refused, a
    minted slug is disambiguated exactly as backfill_ids does;
  - without the engine identity libs a create is REFUSED instead of landing id-less.

The pack-only block at the bottom drives the same branches through the conformance stand-ins, so
the coverage lane (which runs without an engine) measures them too.
"""
from __future__ import annotations

import ast
import hashlib
import importlib.util
import inspect
import os
import re
import shutil
import sys
from urllib.parse import urlsplit
import types
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "packs" / "okpack-ai-research" / "crons" / "scripts" / "_okf_write.py"
DETECTIONS_SCHEMA = ROOT / "packs" / "okpack-detections" / "schema.yaml"
STANDINS = ROOT / "packs" / "okpack-threat-actors" / "conformance" / "_identity_standins.py"
ENGINE = os.environ.get("ENGINE_DIR") or os.environ.get("OKENGINE_DIR")
CRON = Path(ENGINE) / "scripts" / "cron" if ENGINE else None
HAVE_ENGINE = bool(CRON and (CRON / "id_lib.py").is_file()
                   and (Path(ENGINE) / "scripts" / "backfill_ids.py").is_file())
needs_engine = pytest.mark.skipif(
    not HAVE_ENGINE,
    reason="no ENGINE_DIR checkout with id_lib/backfill_ids — engine id parity UNDETECTABLE here")

_ENGINE_MODS = ("_okf_write", "id_lib", "schema_lib", "id_index", "okf_migrate", "importer_guard",
                "authority_lib", "backfill_ids", "reid_sources_by_url")


def _load_helper(name: str = "_okf_write", path: Path = HELPER):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def engine(monkeypatch, tmp_path):
    """The helper with the REAL engine libs, plus backfill_ids for parity, on a vault at tmp_path."""
    for m in _ENGINE_MODS:
        monkeypatch.delitem(sys.modules, m, raising=False)
    monkeypatch.setattr(sys, "path", [str(HELPER.parent), str(CRON), str(Path(ENGINE) / "scripts"),
                                      *sys.path])
    monkeypatch.setenv("WIKI_PATH", str(tmp_path))
    monkeypatch.setenv("HERMES_DATA", str(tmp_path / "data"))   # no persisted id-index: scan
    shutil.copy(DETECTIONS_SCHEMA, tmp_path / "schema.yaml")     # declares an id_authority type
    helper = _load_helper()
    import backfill_ids
    ns = types.SimpleNamespace(helper=helper, backfill=backfill_ids, root=tmp_path,
                               wiki=tmp_path / "wiki")
    yield ns
    for m in _ENGINE_MODS:
        sys.modules.pop(m, None)


def _fm(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8").split("---", 2)[1]) or {}


def _page(wiki: Path, rel: str, fm: dict) -> Path:
    p = wiki / f"{rel}.md"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("---\n" + yaml.safe_dump(fm, sort_keys=False) + "---\n\nBody\n", encoding="utf-8")
    return p


def _only_page(wiki: Path, namespace: str) -> Path:
    pages = sorted((wiki / namespace).rglob("*.md"))
    assert len(pages) == 1, f"expected exactly one page under {namespace}/, found {pages}"
    return pages[0]


def _backfilled_id(root: Path, rel_md: str, fm: dict) -> str:
    """What OKEngine backfill_ids stamps on an id-less page with `fm` at `rel_md`."""
    import backfill_ids
    twin = root / "twin"
    _page(twin / "wiki", rel_md[:-3], fm)
    shutil.copy(root / "schema.yaml", twin / "schema.yaml")
    backfill_ids.run(twin, apply=True)
    return _fm(twin / "wiki" / rel_md)["id"]


# ---------------------------------------------------------------- against the real engine libs

@needs_engine
@pytest.mark.parametrize("rel, fm, expected", [
    ("entities/acme-corp", {"type": "identity", "title": "Acme Corp"}, "entities:acme-corp"),
    ("entities/account-use-policies",
     {"type": "course-of-action", "title": "Account Use Policies", "attack_id": "M1036"},
     "attack:m1036"),
    ("dashboards/top-things", {"type": "dashboard", "title": "Top things — Zürich"},
     "dashboards:top-things-zurich"),
    ("entities/no-title", {"type": "identity"}, "entities:no-title"),
], ids=["minted-slug", "authority", "unicode-title", "stem-fallback"])
def test_an_idless_create_gets_the_id_backfill_ids_would_stamp(engine, rel, fm, expected):
    namespace = rel.split("/", 1)[0]
    assert engine.helper.write_page(engine.wiki, rel, dict(fm), "Body") == "created"
    page = _only_page(engine.wiki, namespace)
    got = _fm(page).get("id")
    assert got, f"{page} was created without an id — the okpacks-library#105 defect"
    rel_md = page.relative_to(engine.wiki).as_posix()
    assert got == _backfilled_id(engine.root, rel_md, fm) == expected


@needs_engine
def test_a_created_page_leaves_backfill_ids_nothing_to_stamp(engine):
    engine.helper.write_page(engine.wiki, "entities/acme-corp", {"type": "identity",
                                                                 "title": "Acme Corp"}, "Body")
    assert engine.backfill.run(engine.root, apply=False)["stamped"] == 0


@needs_engine
def test_an_existing_id_is_never_replaced(engine):
    page = _page(engine.wiki, "entities/acme-corp",
                 {"id": "entities:legacy", "type": "identity", "title": "Acme Corp"})
    result = engine.helper.write_page(engine.wiki, "entities/acme-corp",
                                      {"id": "entities:other", "type": "identity",
                                       "title": "Acme Corporation"}, "Body")
    assert result == "updated"
    assert _fm(page)["id"] == "entities:legacy" and _fm(page)["title"] == "Acme Corporation"


@needs_engine
def test_an_existing_idless_page_is_updated_but_not_reidentified(engine):
    """Repairing already-landed id-less pages is backfill_ids' lane, not this helper's
    (pack CHANGELOG 'Migration impact')."""
    page = _page(engine.wiki, "entities/acme-corp", {"type": "identity", "title": "Acme Corp"})
    assert engine.helper.write_page(engine.wiki, "entities/acme-corp",
                                    {"type": "identity", "sector": "x"}, "Body") == "updated"
    assert "id" not in _fm(page)


@needs_engine
def test_a_caller_supplied_id_is_kept_on_create(engine):
    engine.helper.write_page(engine.wiki, "security-incidents/2024/abc",
                             {"type": "incident", "id": "incident:abc", "title": "ABC"}, "Body")
    assert _fm(_only_page(engine.wiki, "security-incidents"))["id"] == "incident:abc"


def _write_path_source_url_id():
    """The write path's `source_url_id`, lifted from the engine source by AST: the package that
    holds it imports the whole web stack, which the pack test lane does not install."""
    src = Path(ENGINE) / "src" / "okengine" / "write_services"
    wanted = {"_norm_url", "source_url_id", "_REAL_URL", "_SERVICE_ENDPOINT_PATH",
              "_is_service_endpoint_url", "_source_identity_url"}
    body = []
    for f in ("state.py", "deduplication.py"):
        tree = ast.parse((src / f).read_text(encoding="utf-8"))
        for node in tree.body:
            names = ({t.id for t in node.targets if isinstance(t, ast.Name)}
                     if isinstance(node, ast.Assign) else {getattr(node, "name", None)})
            if names & wanted:
                body.append(node)
    assert len(body) == len(wanted), f"engine source moved: could not find all of {sorted(wanted)}"
    ns = {"re": re, "hashlib": hashlib, "urlsplit": urlsplit}
    exec(compile(ast.Module(body=body, type_ignores=[]), "write_services", "exec"), ns)  # noqa: S102
    return ns["source_url_id"]


URLS = ["https://arxiv.org/abs/2607.14935", "  https://vendor.example/Report/  ",
        "http://x.test/a?b=1#c", "UNKNOWN", "", "null", "ftp://x.test/a",
        # okengine#901: a bare service endpoint is no identity; a record-specific query is one
        "https://gis.example.test/arcgis/rest/services/Parcels/MapServer/0/query",
        "https://gis.example.test/arcgis/rest/services/Parcels/MapServer/0/query?where=ID%3D7",
        "https://gis.example.test/arcgis/rest/services/Parcels/FeatureServer/3/",
        "https://data.example.test/resource/abcd-1234.json"]


@needs_engine
@pytest.mark.parametrize("url", URLS)
def test_the_source_url_identity_matches_the_engine(engine, url):
    import reid_sources_by_url
    write_path = _write_path_source_url_id()
    assert engine.helper._source_url_id(url) == write_path(url) == \
        reid_sources_by_url.source_url_id(url)


@needs_engine
def test_a_url_source_is_created_with_the_url_identity(engine):
    url = "https://arxiv.org/abs/2607.14935"
    fm = {"type": "source", "title": "VideoChat3", "url": url}
    assert engine.helper.write_page(engine.wiki, "sources/2026-07-16-videochat3", fm, "B") == \
        "created"
    got = _fm(_only_page(engine.wiki, "sources"))["id"]
    assert got == _write_path_source_url_id()(url)
    assert got == "sources:url-" + hashlib.sha256(url.encode()).hexdigest()[:20]


@needs_engine
def test_a_placeholder_url_source_falls_back_to_a_minted_slug(engine):
    fm = {"type": "source", "title": "Some Report", "url": "UNKNOWN"}
    engine.helper.write_page(engine.wiki, "sources/2026-some-report", fm, "B")
    assert _fm(_only_page(engine.wiki, "sources"))["id"] == "sources:some-report"


@needs_engine
def test_a_bare_service_endpoint_source_falls_back_to_a_minted_slug(engine):
    """okengine#901: every record read from one endpoint shares its URL, so the URL is no identity."""
    fm = {"type": "source", "title": "Parcel 7 read",
          "url": "https://gis.example.test/arcgis/rest/services/Parcels/MapServer/0/query"}
    engine.helper.write_page(engine.wiki, "sources/2026-parcel-7-read", fm, "B")
    assert _fm(_only_page(engine.wiki, "sources"))["id"] == "sources:parcel-7-read"


@needs_engine
def test_an_authority_id_held_by_another_page_is_refused(engine, capsys):
    _page(engine.wiki, "entities/old-name", {"id": "attack:m1036", "type": "course-of-action",
                                            "attack_id": "M1036", "title": "Old name"})
    result = engine.helper.write_page(
        engine.wiki, "entities/account-use-policies",
        {"type": "course-of-action", "attack_id": "M1036", "title": "Account Use Policies"}, "B")
    assert result == "collision"
    assert [p.name for p in (engine.wiki / "entities").rglob("*.md")] == ["old-name.md"]
    assert "attack:m1036" in capsys.readouterr().err


@needs_engine
def test_a_tombstoned_holder_still_owns_its_id(engine):
    _page(engine.wiki, "entities/retired", {"id": "attack:m1036", "type": "course-of-action",
                                           "status": "tombstoned", "title": "Retired"})
    assert engine.helper.write_page(engine.wiki, "entities/revived",
                                    {"type": "course-of-action", "attack_id": "M1036",
                                     "title": "Revived"}, "B") == "collision"


@needs_engine
def test_a_held_slug_is_disambiguated_exactly_as_backfill_ids_does(engine, capsys):
    held = {"id": "entities:acme-corp", "type": "identity", "title": "Acme Corp"}
    _page(engine.wiki, "entities/acme", held)
    fm = {"type": "identity", "title": "Acme Corp"}
    assert engine.helper.write_page(engine.wiki, "entities/acme-corporation", dict(fm), "B") == \
        "created"
    (created,) = (engine.wiki / "entities").rglob("acme-corporation.md")
    got = _fm(created)["id"]
    rel = created.relative_to(engine.wiki).as_posix()[:-3]      # the partitioned seat it got
    twin = engine.root / "twin"
    _page(twin / "wiki", "entities/acme", held)
    _page(twin / "wiki", rel, fm)
    shutil.copy(engine.root / "schema.yaml", twin / "schema.yaml")
    engine.backfill.run(twin, apply=True)
    assert got == _fm(twin / "wiki" / f"{rel}.md")["id"] != held["id"]
    assert "disambiguated" in capsys.readouterr().err


@needs_engine
def test_two_creates_in_one_run_never_share_an_id(engine):
    h = engine.helper
    assert h.write_page(engine.wiki, "entities/a", {"type": "identity", "title": "Same"}, "B") == \
        "created"
    assert h.write_page(engine.wiki, "entities/b", {"type": "identity", "title": "Same"}, "B") == \
        "created"
    (a,), (b,) = (engine.wiki / "entities").rglob("a.md"), (engine.wiki / "entities").rglob("b.md")
    assert _fm(a)["id"] != _fm(b)["id"]
    coa = {"type": "course-of-action", "attack_id": "M1040", "title": "Behavior Prevention"}
    assert h.write_page(engine.wiki, "entities/c", dict(coa), "B") == "created"
    assert h.write_page(engine.wiki, "entities/d", dict(coa), "B") == "collision"


@needs_engine
def test_the_conformance_stand_ins_match_the_engine_api(engine):
    import id_index
    import id_lib
    import schema_lib
    spec = importlib.util.spec_from_file_location("_identity_standins_probe", STANDINS)
    standins = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(standins)
    fake_id, fake_schema, fake_index = (standins.id_lib_standin(), standins.schema_lib_standin(),
                                        standins.id_index_standin())
    pairs = [(getattr(fake_id, n), getattr(id_lib, n))
             for n in ("slug_identity", "make_id", "parse_id", "is_id", "natural_key",
                       "derive_id", "_short_hash")]
    pairs += [(fake_schema.merged_schema, schema_lib.merged_schema),
              (fake_schema.type_id_authority, schema_lib.type_id_authority),
              (fake_index.load, id_index.load), (fake_index.build, id_index.build)]
    for fake, real in pairs:
        f, r = inspect.signature(fake).parameters, inspect.signature(real).parameters
        assert [(p.name, p.kind) for p in f.values()] == [(p.name, p.kind) for p in r.values()], \
            f"conformance stand-in {real.__name__} drifted from the engine's signature"


# ------------------------------------------------- pack-only: the same branches, via stand-ins

# Every pack ships its own copy of the helper (byte-identical, enforced by bundle-compose-check),
# and the coverage gate measures each copy on its own, so each shipped copy is driven here.
COPIES = sorted((ROOT / "packs").glob("*/crons/scripts/_okf_write.py"))


@pytest.fixture(params=COPIES, ids=lambda p: p.parents[2].name)
def standin(request, monkeypatch, tmp_path):
    """Each shipped helper copy with the conformance stand-ins for every identity lib."""
    monkeypatch.delitem(sys.modules, "_okf_write", raising=False)
    monkeypatch.syspath_prepend(str(request.param.parent))
    spec = importlib.util.spec_from_file_location("_identity_standins_unit", STANDINS)
    standins = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(standins)
    helper = _load_helper(path=request.param)
    standins.install(helper, force=True)
    monkeypatch.setattr(helper, "okf_migrate", None)       # flat seat: rel_path is the path
    monkeypatch.setattr(helper, "_importer_guard", None)
    yield helper, tmp_path / "wiki"
    sys.modules.pop("_okf_write", None)


def test_standin_a_create_carries_a_minted_id(standin):
    helper, wiki = standin
    assert helper.write_page(wiki, "entities/acme-corp.md", {"type": "identity",
                                                            "title": "Acme Corp"}, "B") == "created"
    assert _fm(wiki / "entities/acme-corp.md")["id"] == "entities:acme-corp"


def test_standin_a_dry_run_creates_nothing(standin):
    helper, wiki = standin
    assert helper.write_page(wiki, "entities/x", {"type": "identity"}, "B", dry_run=True) == "dry"
    assert not (wiki / "entities").exists()


def test_standin_an_existing_id_survives_a_callers_different_id(standin):
    helper, wiki = standin
    page = _page(wiki, "entities/acme-corp", {"id": "entities:legacy", "type": "identity"})
    assert helper.write_page(wiki, "entities/acme-corp", {"id": "x:y", "type": "identity"},
                             "B") == "updated"
    assert _fm(page)["id"] == "entities:legacy"


def test_standin_a_url_source_gets_the_url_identity(standin):
    helper, wiki = standin
    url = "https://vendor.example/report"
    helper.write_page(wiki, "sources/r", {"type": "source", "title": "R", "url": url + "/"}, "B")
    assert _fm(wiki / "sources/r.md")["id"] == \
        "sources:url-" + hashlib.sha256(url.encode()).hexdigest()[:20]


def test_standin_an_authority_binding_mints_an_authority_id(standin, monkeypatch):
    helper, wiki = standin
    monkeypatch.setattr(helper.schema_lib, "type_id_authority",
                        lambda schema, type_name: ("attack", "attack_id"))
    helper.write_page(wiki, "entities/p", {"type": "course-of-action", "attack_id": "M1"}, "B")
    assert _fm(wiki / "entities/p.md")["id"] == "attack:m1"


def test_standin_a_held_id_refuses_or_disambiguates(standin, monkeypatch, capsys):
    helper, wiki = standin
    monkeypatch.setattr(helper.id_index, "build", lambda vault=None, *, force=False:
                        types.SimpleNamespace(by_id={"entities:same": "entities/other.md",
                                                     "incident:abc": "incidents/abc.md"}))
    assert helper.write_page(wiki, "entities/new", {"type": "identity", "title": "Same"},
                             "B") == "created"
    assert _fm(wiki / "entities/new.md")["id"].startswith("entities:new-")
    assert helper.write_page(wiki, "incidents/abc2", {"id": "incident:abc"}, "B") == "collision"
    assert not (wiki / "incidents").exists()
    err = capsys.readouterr().err
    assert "disambiguated" in err and "incident:abc" in err


def test_standin_without_identity_libs_a_create_is_refused(standin, monkeypatch, capsys):
    """The negative fixture: before #105 this landed an id-less page."""
    helper, wiki = standin
    monkeypatch.setattr(helper, "schema_lib", None)
    assert helper.write_page(wiki, "entities/acme", {"type": "identity"}, "B") == "unverifiable"
    assert not (wiki / "entities").exists()
    assert "schema_lib" in capsys.readouterr().err
    existing = _page(wiki, "entities/kept", {"type": "identity", "title": "Kept"})
    assert helper.write_page(wiki, "entities/kept", {"type": "identity", "sector": "s"},
                             "B") == "updated", "an UPDATE needs no id derivation"
    assert _fm(existing)["sector"] == "s"
