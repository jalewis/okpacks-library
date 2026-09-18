#!/usr/bin/env python3
"""Conformance for epss_import.py (+ kev_import's CWE stamp).

Invariants:
  1. The EPSS CSV parses (comment line carries score_date; malformed rows drop).
  2. Stamping is idempotent — unchanged values return None so a daily run
     doesn't rewrite (and mtime-churn) 1700 pages.
  3. Stamping preserves every other frontmatter field and the body.
  4. The dashboard renders all three sections (horizon / tracked / CWE rollup).
  5. kev_import._cwes normalizes the KEV feed's `cwes` list and drops junk.

Runs standalone (conformance-all.sh) and is pytest-discoverable.
"""
import gzip
import importlib.util
import sys
from pathlib import Path
from collections import Counter

SCRIPTS = Path(__file__).resolve().parent.parent / "crons" / "scripts"


def _load(name: str):
    for m in ("_okf_write", "okf_migrate", name):
        sys.modules.pop(m, None)
    sys.path.insert(0, str(SCRIPTS))
    if name == "kev_import":
        # kev_import imports the engine's okf_migrate (staged alongside pack scripts in a
        # deployment, absent standalone) — stub it; _cwes under test doesn't touch it.
        import types
        sys.modules["okf_migrate"] = types.ModuleType("okf_migrate")
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_CSV = (b"#model_version:v2025.03.14,score_date:2026-07-14T00:00:00+0000\n"
        b"cve,epss,percentile\n"
        b"CVE-2024-39891,0.94321,0.99912\n"
        b"CVE-2021-44228,0.97552,0.99991\n"
        b"not-a-cve,0.5,0.5\n"
        b"CVE-2020-0001,junk,0.1\n")


def test_parse_epss_csv_plain_and_gzip():
    mod = _load("epss_import")
    for raw in (_CSV, gzip.compress(_CSV)):
        scores, date = mod.parse_epss_csv(raw)
        assert date == "2026-07-14"
        assert scores["CVE-2024-39891"] == (0.94321, 0.99912)
        assert "not-a-cve" not in scores and "NOT-A-CVE" not in scores
        assert "CVE-2020-0001" not in scores          # malformed score row dropped
        assert len(scores) == 2


def test_stamp_preserves_fields_and_skips_unchanged():
    mod = _load("epss_import")
    page = ("---\ntype: cve\ncve_id: CVE-2024-39891\nkev: true\n"
            "exploited_by: [some-actor]\n---\n\n# CVE-2024-39891\n\nbody text\n")
    out = mod.stamp_page(page, 0.94321, 0.99912, "2026-07-14")
    assert out is not None
    assert "epss_score: 0.94321" in out and "epss_percentile: 0.99912" in out
    assert "epss_date: '2026-07-14'" in out or "epss_date: 2026-07-14" in out
    assert "exploited_by" in out and "kev: true" in out    # merge, not replace
    assert "body text" in out                              # body untouched
    # second stamp with identical values -> None (no rewrite, no mtime churn)
    assert mod.stamp_page(out, 0.94321, 0.99912, "2026-07-14") is None
    # a moved score stamps again
    assert mod.stamp_page(out, 0.95, 0.99912, "2026-07-14") is not None


def test_stamp_fails_open_on_broken_pages():
    mod = _load("epss_import")
    assert mod.stamp_page("no frontmatter here", 0.5, 0.5, "2026-07-14") is None
    assert mod.stamp_page("---\n[broken: yaml\n---\nbody", 0.5, 0.5, "2026-07-14") is None


def test_select_horizon_emerging_excludes_ancient_risers_need_delta():
    mod = _load("epss_import")
    scores = {
        "CVE-2014-3566": (1.0, 1.0),        # ancient mass-scanned (POODLE) — noise
        "CVE-2026-11111": (0.91, 0.999),    # recent + hot -> emerging
        "CVE-2025-22222": (0.85, 0.99),     # recent + hot -> emerging
        "CVE-2019-33333": (0.30, 0.9),      # old, but JUMPED -> riser
        "CVE-2020-44444": (0.09, 0.5),      # jumped but below the 0.1 floor
        "CVE-2024-39891": (0.94, 0.999),    # tracked -> excluded from both
    }
    tracked = {"CVE-2024-39891"}
    prev = {"CVE-2014-3566": 1.0, "CVE-2019-33333": 0.05, "CVE-2020-44444": 0.01}
    emerging, risers = mod.select_horizon(scores, tracked, prev, "2026-07-14", top=10)
    e_ids = [c for c, *_ in emerging]
    assert e_ids == ["CVE-2026-11111", "CVE-2025-22222"]   # sorted by EPSS, ancient excluded
    assert [c for c, *_ in risers] == ["CVE-2019-33333"]   # delta 0.25; stable+floor rows dropped
    assert abs(risers[0][3] - 0.25) < 1e-9
    # baseline run (no prior state) -> no risers
    _, r0 = mod.select_horizon(scores, tracked, {}, "2026-07-14", top=10)
    assert r0 == []


def test_state_roundtrip(tmp_path=None):
    import tempfile
    mod = _load("epss_import")
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "epss-state.json"
        scores = {"CVE-2026-11111": (0.91, 0.999), "CVE-2007-1": (0.001, 0.1)}
        mod.save_state(p, scores, "2026-07-14")
        prev = mod.load_state(p)
        assert prev == {"CVE-2026-11111": 0.91}      # sub-floor row not persisted
        assert mod.load_state(Path(td) / "missing.json") == {}   # fail-open


def test_daily_history_and_movement_lookup(tmp_path=None):
    import tempfile
    mod = _load("epss_import")
    with tempfile.TemporaryDirectory() as td:
        state = Path(td) / "epss-state.json"
        mod.save_history(state, {"CVE-2026-11111": (0.10, 0.5)}, "2026-06-18")
        mod.save_history(state, {"CVE-2026-11111": (0.40, 0.8)}, "2026-07-11")
        mod.save_history(state, {"CVE-2026-11111": (0.90, 0.99)}, "2026-07-18")
        assert mod.load_history_score(state, "2026-07-18", 7)["CVE-2026-11111"] == 0.40
        assert mod.load_history_score(state, "2026-07-18", 30)["CVE-2026-11111"] == 0.10


def test_dashboard_renders_all_sections():
    mod = _load("epss_import")
    kw = dict(tracked=[("CVE-2024-39891", 0.94321, 0.99912)],
              cwe_counts=Counter({"CWE-787": 3}),
              cwe_samples={"CWE-787": ["CVE-2024-39891"]},
              tracked_total=1723, stamped=42)
    dash = mod.render_dashboard(
        "2026-07-14",
        emerging=[("CVE-2026-11111", 0.91, 0.999)],
        risers=[("CVE-2019-33333", 0.30, 0.9, 0.25)],
        baseline=False, **kw)
    assert "## Emerging" in dash and "CVE-2026-11111" in dash and "0.9100" in dash
    assert "## Risers" in dash and "CVE-2019-33333" in dash and "+0.2500" in dash
    assert "[[cves/CVE-2024-39891]]" in dash
    assert "cwe.mitre.org/data/definitions/787" in dash and "| 3 |" in dash
    assert "1723" in dash and "42" in dash
    # baseline run notes the snapshot instead of an empty table
    dash0 = mod.render_dashboard("2026-07-14", emerging=[], risers=[], baseline=True, **kw)
    assert "baseline snapshot recorded" in dash0


def test_kev_cwes_normalized():
    kev = _load("kev_import")
    assert kev._cwes({"cwes": ["CWE-787", "cwe-79", "  CWE-22 ", "garbage", ""]}) == \
        ["CWE-787", "CWE-79", "CWE-22"]
    assert kev._cwes({}) == []
    assert kev._cwes({"cwes": None}) == []


if __name__ == "__main__":
    test_parse_epss_csv_plain_and_gzip()
    test_stamp_preserves_fields_and_skips_unchanged()
    test_stamp_fails_open_on_broken_pages()
    test_select_horizon_emerging_excludes_ancient_risers_need_delta()
    test_state_roundtrip()
    test_daily_history_and_movement_lookup()
    test_dashboard_renders_all_sections()
    test_kev_cwes_normalized()
    print("OK")
