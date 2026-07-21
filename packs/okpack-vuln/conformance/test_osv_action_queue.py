#!/usr/bin/env python3
import importlib.util
import json
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import yaml

SCRIPTS = Path(__file__).resolve().parent.parent / "crons" / "scripts"


def load(name):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def test_osv_normalization_aliases_packages_and_ambiguity():
    mod = load("osv_import")
    records = [{"id": "CVE-2026-10000", "modified": "2026-07-18T10:00:00Z",
                "aliases": ["GHSA-aaaa-bbbb-cccc"], "affected": []},
               {"id": "GHSA-aaaa-bbbb-cccc", "modified": "2026-07-18T11:00:00Z",
                "aliases": ["CVE-2026-10000", "CVE-2026-10001"],
                "affected": [{"package": {"ecosystem": "PyPI", "name": "demo", "purl": "pkg:pypi/demo"},
                              "versions": ["1.0"], "ranges": [{"type": "ECOSYSTEM", "events": [
                                  {"introduced": "0"}, {"fixed": "1.1"}]}]}]}]
    out = mod.normalize(records, "2026-07-18T12:00:00Z")
    assert out["osv_ids"] == ["CVE-2026-10000", "GHSA-aaaa-bbbb-cccc"]
    assert "PyPI | demo | pkg:pypi/demo" in out["osv_packages"]
    assert out["osv_affected_versions"] == []  # compact range projection; raw archive keeps enumeration
    assert "pkg:pypi/demo | ECOSYSTEM:fixed:1.1" in out["osv_fixed_versions"]
    assert out["osv_alias_ambiguity"] is True


def test_osv_stamp_idempotent_and_revision_archive(tmp_path):
    mod = load("osv_import")
    text = "---\ntype: cve\ncve_id: CVE-2026-10000\nvendor: Acme\n---\n\nbody\n"
    fields = {"osv_ids": ["CVE-2026-10000"], "osv_retrieved_at": "2026-07-18T12:00:00Z"}
    stamped = mod.stamp_page(text, fields)
    assert stamped and "vendor: Acme" in stamped and "body" in stamped
    assert mod.stamp_page(stamped, fields) is None
    record = {"id": "CVE-2026-10000", "modified": "2026-07-18T10:00:00Z"}
    assert mod.archive_records(tmp_path, [record])[0] == 1
    assert mod.archive_records(tmp_path, [record])[0] == 0
    record["modified"] = "2026-07-18T11:00:00Z"
    assert mod.archive_records(tmp_path, [record])[0] == 1
    assert len(list((tmp_path / "CVE-2026-10000").glob("*.json"))) == 2


def test_osv_observation_is_daily_for_retry_idempotence():
    mod = load("osv_import")
    fields = mod.normalize([{"id": "CVE-2026-10000"}], "2026-07-18")
    text = "---\ntype: cve\ncve_id: CVE-2026-10000\n---\nbody\n"
    first = mod.stamp_page(text, fields)
    assert first is not None and mod.stamp_page(first, fields) is None


def test_action_rules_unknowns_and_fixed_version_distinction():
    mod = load("vulnerability_action_queue")
    now = datetime(2026, 7, 18, 12, tzinfo=timezone.utc)
    act = mod.classify({"cve_id": "CVE-1", "date_added": "2026-07-18",
                        "applicability": "affected", "asset_exposure": "exposed"}, now)
    assert act["queue"] == "Act now"
    gap = mod.classify({"cve_id": "CVE-2", "date_added": "2026-07-18"}, now)
    assert gap["queue"] == "Investigate" and "applicability" in gap["unknown"]
    fixed_available = mod.classify({"cve_id": "CVE-3", "osv_fixed_versions": ["ECOSYSTEM:2.0"]}, now)
    assert fixed_available["queue"] == "Monitor" and fixed_available["remediation"] is True
    fixed_asset = mod.classify({"cve_id": "CVE-4", "applicability": "fixed"}, now)
    assert fixed_asset["queue"] == "Deprioritize"
    high = mod.classify({"cve_id": "CVE-5", "epss_score": .8, "epss_date": "2026-07-18"}, now)
    stale = mod.classify({"cve_id": "CVE-6", "epss_score": .99, "epss_date": "2026-01-01"}, now)
    assert high["queue"] == "Investigate" and stale["queue"] == "Monitor"


def test_action_dashboard_discloses_factors():
    mod = load("vulnerability_action_queue")
    row = mod.classify({"cve_id": "CVE-2026-10000", "date_added": "2026-07-18"},
                       datetime(2026, 7, 18, 12, tzinfo=timezone.utc))
    page = mod.render([row], "2026-07-18T12:00:00Z")
    for value in ("Applicability", "Exposure", "Criticality", "Independent origins", "Recent reports", "unknown"):
        assert value in page
    assert "fixed version means remediation exists" in page


def test_action_dashboard_bounds_rows_but_preserves_totals():
    mod = load("vulnerability_action_queue")
    now = datetime(2026, 7, 18, 12, tzinfo=timezone.utc)
    rows = [mod.classify({"cve_id": f"CVE-2026-{i:05d}"}, now) for i in range(5)]
    page = mod.render(rows, "2026-07-18T12:00:00Z", display_limit=2)
    assert "## Monitor (5)" in page
    assert page.count("https://osv.dev/vulnerability/") == 2
    assert "Showing the highest-priority 2 of 5; 3 additional records" in page


def test_bounded_parallel_fetch_completes_all():
    """The production default is concurrent so the full corpus fits cron's timeout."""
    mod = load("osv_import")
    lock, active, peak = threading.Lock(), [0], [0]
    original = mod.records_for_cve
    def fake(cve, *, delay):
        with lock:
            active[0] += 1
            peak[0] = max(peak[0], active[0])
        time.sleep(0.02)
        with lock:
            active[0] -= 1
        return [{"id": cve}]
    mod.records_for_cve = fake
    try:
        pages = [(Path(f"/{i}"), f"CVE-2026-{10000+i}", "") for i in range(8)]
        out = mod.fetch_all(pages, workers=4, delay=0)
    finally:
        mod.records_for_cve = original
    assert len(out) == 8 and peak[0] > 1 and peak[0] <= 4


if __name__ == "__main__":
    test_osv_normalization_aliases_packages_and_ambiguity()
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        test_osv_stamp_idempotent_and_revision_archive(Path(td))
    test_osv_observation_is_daily_for_retry_idempotence()
    test_action_rules_unknowns_and_fixed_version_distinction()
    test_action_dashboard_discloses_factors()
    test_bounded_parallel_fetch_completes_all()
    print("OK")
