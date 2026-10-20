"""Stand-ins for the engine identity libs `_okf_write` needs to CREATE a page (okpacks-library#105).

`write_page` refuses to create a page whose id it cannot derive, and deriving one takes the engine's
`id_lib`, `schema_lib` and `id_index`, which are staged beside pack scripts at runtime but absent
from a pack-only checkout (public CI, the coverage lane). These suites test importer behavior, not
identity, so they install minimal stand-ins -- only for a lib the real engine did not provide, so a
run with the engine on the path exercises the real one. The identity contract itself is proven
against the REAL engine libs in the library's tests/test_okf_write_page_id.py, which also pins these
stand-ins' signatures to the engine's.

Plain module, no pytest: these suites run under plain python.
"""
import hashlib
import re
import types


def _kebab(text):
    return re.sub(r"[^a-z0-9]+", "-", str(text or "").lower()).strip("-") or "x"


def id_lib_standin():
    m = types.ModuleType("id_lib")
    m.slug_identity = lambda raw: re.sub(r"[^a-z0-9]+", "", str(raw).lower())
    m.qualified_namespace = lambda wiki, path: str(path.relative_to(wiki)).split("/", 1)[0]
    m.make_id = lambda scope, key: f"{_kebab(scope)}:{_kebab(key)}"

    def parse_id(page_id):
        scope, sep, key = str(page_id or "").partition(":")
        return (scope, key) if sep else ("", str(page_id or ""))

    m.parse_id = parse_id
    m.is_id = lambda value: (isinstance(value, str) and ":" in value
                             and m.make_id(*parse_id(value)) == value)
    m.natural_key = lambda fm, fallback="": fm.get("title") or fm.get("name") or fallback

    def derive_id(*, authority=None, local_id=None, minted_scope, slug_source):
        if authority and local_id is not None and str(local_id).strip():
            return m.make_id(authority, str(local_id)), "authority"
        return m.make_id(minted_scope, slug_source), "slug"

    m.derive_id = derive_id
    m._short_hash = lambda raw, n: hashlib.sha256(raw.encode("utf-8")).hexdigest()[:n]
    return m


def schema_lib_standin():
    m = types.ModuleType("schema_lib")
    m.merged_schema = lambda root, namespace="": {}
    m.type_id_authority = lambda schema, type_name: (None, "external_id")
    return m


def id_index_standin():
    m = types.ModuleType("id_index")
    m.load = lambda path=None: None
    m.build = lambda vault=None, *, force=False: types.SimpleNamespace(by_id={})
    return m


def install(writer, force=False):
    """Give a loaded `_okf_write` module a stand-in for each identity lib it could not import --
    or for all three with `force`, when a suite has stubbed `id_lib` itself and a real engine lib
    would otherwise run against that stub."""
    for name, make in (("id_lib", id_lib_standin), ("schema_lib", schema_lib_standin),
                       ("id_index", id_index_standin)):
        if force or getattr(writer, name, None) is None:
            setattr(writer, name, make())
    return writer
