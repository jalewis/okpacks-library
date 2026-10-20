"""okengine#901, engine-free: every pack copy of `_okf_write.py` treats a bare service endpoint URL
as no source identity, and a record-specific URL as one. The engine-parity test in
test_okf_write_page_id.py pins the exact values against the engine; this one needs no engine, so
coverage (measured without one) sees every copy exercised."""
from __future__ import annotations

import hashlib
import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
COPIES = sorted(ROOT.glob("packs/*/crons/scripts/_okf_write.py"))


def _load(path: Path):
    name = f"_okf_write_{path.parts[-4].replace('-', '_')}"
    sys.path.insert(0, str(path.parent))
    try:
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(path.parent))
    return module


def test_every_pack_ships_the_helper():
    assert len(COPIES) >= 6, COPIES


ENDPOINTS = [
    "https://gis.example.test/arcgis/rest/services/Parcels/MapServer/0/query",
    "https://gis.example.test/arcgis/rest/services/Parcels/MapServer/0",
    "https://gis.example.test/arcgis/rest/services/Parcels/FeatureServer/3/",
    "https://data.example.test/resource/abcd-1234.json",
    "  https://gis.example.test/arcgis/rest/services/Parcels/MapServer/0/QUERY  ",
]
RECORDS = [
    "https://gis.example.test/arcgis/rest/services/Parcels/MapServer/0/query?where=ID%3D7",
    "https://data.example.test/resource/abcd-1234.json?parcel=7",
    "https://arxiv.org/abs/2607.14935",
    "https://vendor.example.test/query-language-guide",
]


@pytest.mark.parametrize("path", COPIES, ids=lambda p: p.parts[-4])
def test_a_bare_service_endpoint_is_no_identity(path):
    helper = _load(path)
    for url in ENDPOINTS:
        assert helper._is_service_endpoint_url(url), url
        assert helper._source_url_id(url) == "", url


@pytest.mark.parametrize("path", COPIES, ids=lambda p: p.parts[-4])
def test_a_record_specific_url_keeps_its_identity(path):
    helper = _load(path)
    for url in RECORDS:
        assert not helper._is_service_endpoint_url(url), url
        text = url.strip().removesuffix("/")
        assert helper._source_url_id(url) == \
            "sources:url-" + hashlib.sha256(text.encode("utf-8")).hexdigest()[:20], url


@pytest.mark.parametrize("path", COPIES, ids=lambda p: p.parts[-4])
def test_non_addresses_and_malformed_hosts_are_not_endpoints(path):
    helper = _load(path)
    assert not helper._is_service_endpoint_url("UNKNOWN")
    assert not helper._is_service_endpoint_url(None)
    assert not helper._is_service_endpoint_url("http://[::1/query")  # unbalanced bracket
