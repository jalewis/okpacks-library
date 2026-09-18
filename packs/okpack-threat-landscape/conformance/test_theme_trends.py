#!/usr/bin/env python3
"""Conformance: theme_trends links the reports it counts (okpacks-library — count-lane gap).

The landscape trend page counted N reports per theme but named none of them — a dead-end number
with no backlinks. It must LINK every source it counts, so the count is navigable evidence and each
cited report shows the trend in its backlinks. Drives the real script with inline source fixtures.

Standalone (conformance-all.sh) and pytest-discoverable.
"""
import importlib.util
import sys
import tempfile
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent.parent / "crons" / "scripts"


def _load(name):
    sys.path.insert(0, str(SCRIPTS))
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _src(root, rel, theme, year, published=None, precision=None, quality=None):
    p = root / "wiki" / "sources" / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    optional = (f"published: {published}\n" if published else "") + \
               (f"published_precision: {precision}\n" if precision else "") + \
               (f"report_quality: {quality}\n" if quality else "")
    p.write_text(f"---\ntype: source\ntitle: {p.stem}\nsource_channel: annual-report\n"
                 f"report_theme: {theme}\nyear: {year}\n{optional}"
                 "---\nbody\n", encoding="utf-8")


def test_thin_reports_excluded_from_theme_counts():
    """A report flagged report_quality: thin (a filler/synthetic stub) must NOT count toward a theme's
    coverage trend — else a thin stub inflates the count equal to a substantive report (ingest quality
    gate). Substantive reports are counted; the thin one is neither counted nor linked."""
    m = _load("theme_trends")
    with tempfile.TemporaryDirectory() as t:
        v = Path(t)
        for k in ("2024/03/rw-a", "2024/03/rw-b", "2024/03/rw-c"):
            _src(v, k + ".md", "ransomware", 2024)                      # substantive (no flag)
        _src(v, "2024/03/rw-thin.md", "ransomware", 2024, quality="thin")   # thin -> excluded
        assert m.main(["--vault", str(v)]) == 0
        page = (v / "wiki" / "trends" / "theme-ransomware.md").read_text(encoding="utf-8")
        assert "(total 3)" in page and "2024: 3" in page               # 3 counted, not 4
        assert "[[sources/2024/03/rw-thin]]" not in page               # thin not linked
        assert page.count("[[sources/") == 3


def test_theme_trend_links_every_counted_report():
    m = _load("theme_trends")
    with tempfile.TemporaryDirectory() as t:
        v = Path(t)
        keys = ["2024/03/idp-a", "2024/03/idp-b", "2024/03/idp-c"]
        for k in keys:
            _src(v, k + ".md", "identity-security", 2024)
        assert m.main(["--vault", str(v)]) == 0
        page = (v / "wiki" / "trends" / "theme-identity-security.md").read_text(encoding="utf-8")
        # the count is still there ...
        assert "(total 3)" in page and "2024: 3" in page
        assert "title: Identity Security reporting-volume trend" in page
        # ... and every counted report is now a wikilink (navigable + backlink edge)
        for k in keys:
            assert f"[[sources/{k}]]" in page, f"{k} not linked:\n{page}"
        # the linked-report count matches the tallied count (no phantom / missing evidence)
        assert page.count("[[sources/") == 3


def test_titleize_preserves_acronyms():
    """`report_theme` is agent-stamped free text; the trend title must NOT mangle acronyms — a naive
    `.title()` gave "Ai Security" / "Ot Ics Security" (operator report). Assert the acronym-aware
    _titleize: ai-security -> "AI Security", ot-ics-security -> "OT ICS Security", iot -> "IoT"."""
    m = _load("theme_trends")
    cases = {
        "ai-security": "AI Security",
        "ot-ics-security": "OT ICS Security",
        "iot-security": "IoT Security",
        "phishing-social-engineering": "Phishing Social Engineering",
        "ransomware": "Ransomware",
        "cloud-security": "Cloud Security",
    }
    for slug, want in cases.items():
        got = m._titleize(slug)
        assert got == want, f"{slug!r} -> {got!r}, want {want!r}"


def test_ytd_requires_day_precise_sources_and_uses_same_cutoff():
    m = _load("theme_trends")
    with tempfile.TemporaryDirectory() as t:
        v = Path(t)
        for year in (2025, 2026):
            _src(v, f"{year}/early.md", "cloud-security", year, f"{year}-02-01", "day")
            _src(v, f"{year}/late.md", "cloud-security", year, f"{year}-10-01", "day")
        assert m.main(["--vault", str(v), "--min-total", "1", "--as-of", "2026-07-15"]) == 0
        fm = (v / "wiki" / "trends" / "theme-cloud-security.md").read_text(encoding="utf-8")
        assert "comparison: ytd" in fm and "comparison_as_of: 07-15" in fm
        assert "count_ytd_by_year:" in fm and "'2025': 1" in fm and "'2026': 1" in fm


def test_year_only_current_period_suppresses_comparison():
    m = _load("theme_trends")
    with tempfile.TemporaryDirectory() as t:
        v = Path(t)
        _src(v, "2025/a.md", "cloud-security", 2025)
        _src(v, "2026/b.md", "cloud-security", 2026)
        assert m.main(["--vault", str(v), "--min-total", "1", "--as-of", "2026-07-15"]) == 0
        page = (v / "wiki" / "trends" / "theme-cloud-security.md").read_text(encoding="utf-8")
        assert "comparison: partial-period" in page and "count_ytd_by_year" not in page


def test_partial_period_refresh_removes_stale_ytd_fields():
    m = _load("theme_trends")
    with tempfile.TemporaryDirectory() as t:
        v = Path(t)
        for year in (2025, 2026):
            _src(v, f"{year}/a.md", "cloud-security", year, f"{year}-02-01", "day")
        args = ["--vault", str(v), "--min-total", "1", "--as-of", "2026-07-15"]
        assert m.main(args) == 0
        current = v / "wiki" / "sources" / "2026" / "a.md"
        current.write_text(current.read_text(encoding="utf-8").replace(
            "published_precision: day", "published_precision: year"), encoding="utf-8")
        assert m.main(args) == 0
        page = (v / "wiki" / "trends" / "theme-cloud-security.md").read_text(encoding="utf-8")
        assert "comparison: partial-period" in page
        assert "comparison_as_of" not in page and "count_ytd_by_year" not in page


def _run() -> int:
    fails = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn(); print(f"  ok   {name}")
            except AssertionError as e:
                fails += 1; print(f"  FAIL {name}: {e}")
    return fails


if __name__ == "__main__":
    print("== okpack-threat-landscape theme_trends conformance ==")
    n = _run()
    print("all theme_trends tests pass" if not n else f"{n} test(s) failed")
    sys.exit(1 if n else 0)
