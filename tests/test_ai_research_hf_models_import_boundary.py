"""HF notable-models importer against stand-ins for the engine identity libs (okpacks-library#104).

The coverage lane runs pack-only (no ENGINE_DIR), where the importer's create path is unreachable
by design. These stand-ins implement just the engine API the importer calls, so its branches are
exercised here; `test_the_stand_ins_match_the_engine_api` pins their signatures to the real libs
wherever an engine checkout exists (pack-unit-tests), so the stand-ins cannot drift from the
contract. Behavior against the real libs is tests/test_ai_research_hf_models_import.py.
"""
from __future__ import annotations

import importlib.util
import inspect
import os
import re
import sys
from pathlib import Path

import pytest
import yaml

PACK = Path(__file__).resolve().parents[1] / "packs" / "okpack-ai-research"
SCRIPTS = PACK / "crons" / "scripts"
ENGINE = os.environ.get("ENGINE_DIR") or os.environ.get("OKENGINE_DIR")

MODELS = [
    {"id": "facebook/sam3", "author": "facebook", "pipeline_tag": "mask-generation", "likes": 2808},
    {"id": "openai/whisper-large-v3", "author": "openai",
     "pipeline_tag": "automatic-speech-recognition", "likes": 5000},
]


def _kebab(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", (s or "").lower()).strip("-")


class IdLib:
    @staticmethod
    def derive_id(*, authority=None, local_id=None, minted_scope, slug_source):
        return f"{minted_scope}:{_kebab(slug_source)}", "slug"

    @staticmethod
    def natural_key(fm, fallback=""):
        return fm.get("title") or fm.get("name") or fallback

    @staticmethod
    def slug_identity(raw):
        return re.sub(r"[^a-z0-9]", "", (raw or "").lower())

    @staticmethod
    def is_id(value):
        return isinstance(value, str) and ":" in value

    @staticmethod
    def parse_id(page_id):
        scope, _sep, key = str(page_id).partition(":")
        return scope, key

    @staticmethod
    def make_id(scope, key):
        return f"{_kebab(scope)}:{_kebab(key)}"


class SchemaLib:
    @staticmethod
    def merged_schema(root, namespace=""):
        return {}

    @staticmethod
    def type_id_authority(schema, type_name):
        return None, "external_id"


class OkfMigrate:
    @staticmethod
    def find_page(root, namespace, slug):
        return next((root / "wiki" / namespace).rglob(f"{slug}.md"), None) \
            if (root / "wiki" / namespace).is_dir() else None

    @staticmethod
    def is_partitioned(root, namespace):
        return False

    @staticmethod
    def write_key(root, namespace, slug, fm=None):
        return f"{namespace}/{slug}"


class IdIndex:
    def __init__(self, ids=()):
        self.ids = set(ids)

    def resolve(self, page_id):
        return "held" if page_id in self.ids else None

    @property
    def by_id(self):
        return {pid: "held" for pid in self.ids}


class IdIndexModule:
    held: set = set()

    @classmethod
    def load(cls, path=None):
        return None

    @classmethod
    def build(cls, vault=None, *, force=False):
        return IdIndex(cls.held)


@pytest.fixture
def importer(monkeypatch):
    monkeypatch.syspath_prepend(str(SCRIPTS))
    for m in ("_okf_write", "okpack_run_report"):
        monkeypatch.delitem(sys.modules, m, raising=False)
    name = "hf_models_boundary_under_test"
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / "okpack_ai_research_hf_import.py")
    mod = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, name, mod)
    spec.loader.exec_module(mod)
    monkeypatch.setattr(mod, "okf_migrate", OkfMigrate)
    monkeypatch.setattr(mod, "id_index", IdIndexModule)
    helper = sys.modules["_okf_write"]
    monkeypatch.setattr(helper, "okf_migrate", OkfMigrate)
    monkeypatch.setattr(helper, "id_lib", IdLib)
    monkeypatch.setattr(helper, "schema_lib", SchemaLib)
    monkeypatch.setattr(helper, "id_index", IdIndexModule)
    monkeypatch.setattr(helper, "_IDENTITY_INDEX", {})
    monkeypatch.setattr(helper, "_ID_CLAIMS", {})
    monkeypatch.setattr(IdIndexModule, "held", set())
    monkeypatch.setattr(mod, "_STRICT", False)
    return mod


def _pages(vault: Path) -> dict[str, dict]:
    root = vault / "wiki" / "entities"
    return {p.relative_to(root).as_posix(): yaml.safe_load(p.read_text().split("---")[1])
            for p in sorted(root.rglob("*.md"))} if root.is_dir() else {}


def test_creates_each_new_model_once_with_its_id(importer, tmp_path):
    c = importer.import_models(MODELS, tmp_path, "2026-09-26")
    assert c == {"created": 2, "exists": 0, "total": 2, "unverifiable": 0, "collision": 0}
    assert _pages(tmp_path)["facebook-sam3.md"]["id"] == "entities:sam3"


def test_an_existing_page_anywhere_counts_as_present(importer, tmp_path):
    seat = tmp_path / "wiki" / "entities" / "f" / "a" / "facebook-sam3.md"
    seat.parent.mkdir(parents=True)
    seat.write_text("---\ntype: model\ntitle: sam3\n---\nbody\n")
    c = importer.import_models(MODELS[:1], tmp_path, "2026-09-26")
    assert c["created"] == 0 and c["exists"] == 1


def test_a_held_id_counts_as_present(importer, tmp_path):
    IdIndexModule.held = {"entities:sam3"}
    c = importer.import_models(MODELS[:1], tmp_path, "2026-09-26")
    assert c["created"] == 0 and c["exists"] == 1 and _pages(tmp_path) == {}


def test_two_records_for_one_model_create_one_page(importer, tmp_path):
    twin = dict(MODELS[0], id="facebook/SAM3")        # same title -> same derived id
    c = importer.import_models([MODELS[0], twin], tmp_path, "2026-09-26")
    assert c["created"] == 1 and c["exists"] == 1


def test_a_separator_twin_of_a_live_page_is_a_collision_not_a_create(importer, tmp_path):
    live = tmp_path / "wiki" / "entities" / "facebook-sam-3.md"
    live.parent.mkdir(parents=True)
    live.write_text("---\ntype: model\ntitle: other\nid: entities:other\n---\nbody\n")
    c = importer.import_models(MODELS[:1], tmp_path, "2026-09-26")
    assert c["collision"] == 1 and c["created"] == 0


def test_a_write_failure_is_counted_or_raised_in_strict_mode(importer, tmp_path, monkeypatch):
    (tmp_path / "wiki").write_text("a file where the wiki directory belongs")
    c = importer.import_models(MODELS[:1], tmp_path, "2026-09-26")
    assert c["unverifiable"] == 1 and c["created"] == 0
    monkeypatch.setattr(importer, "_STRICT", True)
    with pytest.raises(OSError):
        importer.import_models(MODELS[:1], tmp_path, "2026-09-26")


def test_without_identity_libs_nothing_is_created(importer, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(importer, "id_index", None)
    c = importer.import_models(MODELS, tmp_path, "2026-09-26")
    assert c["unverifiable"] == 2 and c["created"] == 0 and _pages(tmp_path) == {}
    assert "id_index" in capsys.readouterr().err


def test_without_the_helpers_schema_lib_nothing_is_created(importer, tmp_path, monkeypatch, capsys):
    """The id comes from the shared helper now (okpacks-library#105), so the helper's own identity
    libs gate the run too -- not just the importer's."""
    monkeypatch.setattr(sys.modules["_okf_write"], "schema_lib", None)
    c = importer.import_models(MODELS, tmp_path, "2026-09-26")
    assert c["unverifiable"] == 2 and c["created"] == 0 and _pages(tmp_path) == {}
    assert "schema_lib" in capsys.readouterr().err


def test_a_create_the_helper_refuses_is_counted_by_its_reason(importer, tmp_path, monkeypatch):
    monkeypatch.setattr(importer, "write_page", lambda *a, **k: "unverifiable")
    c = importer.import_models(MODELS[:1], tmp_path, "2026-09-26")
    assert c["unverifiable"] == 1 and c["created"] == 0 and c["collision"] == 0


@pytest.mark.skipif(not (ENGINE and (Path(ENGINE) / "scripts/cron/id_index.py").is_file()),
                    reason="no ENGINE_DIR checkout — stand-in contract UNDETECTABLE here")
def test_the_stand_ins_match_the_engine_api(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(ENGINE) / "scripts" / "cron"))
    for name in ("id_index", "id_lib", "okf_migrate", "schema_lib"):
        # A module cached by an earlier test (a stub or a pack copy) would stand in for the
        # engine's; compare against the engine every time, whatever ran first.
        monkeypatch.delitem(sys.modules, name, raising=False)
    import id_index
    import id_lib
    import okf_migrate
    import schema_lib
    pairs = [(IdLib.derive_id, id_lib.derive_id), (IdLib.natural_key, id_lib.natural_key),
             (IdLib.slug_identity, id_lib.slug_identity), (IdLib.is_id, id_lib.is_id),
             (IdLib.parse_id, id_lib.parse_id), (IdLib.make_id, id_lib.make_id),
             (SchemaLib.merged_schema, schema_lib.merged_schema),
             (SchemaLib.type_id_authority, schema_lib.type_id_authority),
             (OkfMigrate.find_page, okf_migrate.find_page),
             (OkfMigrate.is_partitioned, okf_migrate.is_partitioned),
             (OkfMigrate.write_key, okf_migrate.write_key),
             (IdIndexModule.load, id_index.load), (IdIndexModule.build, id_index.build),
             (IdIndex.resolve, id_index.IdIndex.resolve)]
    for fake, real in pairs:
        f, r = inspect.signature(fake).parameters, inspect.signature(real).parameters
        assert [(p.name, p.kind) for p in f.values()] == [(p.name, p.kind) for p in r.values()], \
            f"stand-in {fake.__qualname__} drifted from the engine's {real.__qualname__}"
