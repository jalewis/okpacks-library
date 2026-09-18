#!/usr/bin/env python3
"""Conformance: landscape_reports_import skips already-ingested reports so the --limit budget lands
NEWLY-added reports, instead of re-touching the same alphabetically-first N every week.

Regression for the okcti finding: with 671 reports and limit 120 the weekly cron never reached a
report that sorted past the cap — completeness relied on a manual `--limit 0` full pass. The import
must (a) import a report whose source page doesn't exist, (b) SKIP one whose page exists (cheaply,
before the expensive actor-alias regex), (c) refresh everything under --reprocess, and (d) drain the
backlog across runs when --limit binds.

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


_SUBSTANTIVE = ("Threat activity across the sector. " * 60 + " "
                + " ".join(f"CVE-2025-00{i:02d}" for i in range(12)) + " https://vendor.example/report")


def _report(reports_dir, year, filename, h1, thin=False):
    # default body is SUBSTANTIVE (long + CVEs + a URL) so tests unrelated to the quality gate pass;
    # thin=True writes the short, marker-less, synthetic/filler profile the gate filters.
    body = "A brief note on trends." if thin else _SUBSTANTIVE
    p = Path(reports_dir) / "Markdown Conversions" / year / filename
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(f"# {h1}\n\n{body}\n", encoding="utf-8")


def _quality_of(vault, basename):
    import yaml
    p = next((Path(vault) / "wiki" / "sources").rglob(basename))
    fm = yaml.safe_load(p.read_text(encoding="utf-8").split("---", 2)[1])
    return fm.get("report_quality")


def _sources(vault):
    return sorted(p.name for p in (Path(vault) / "wiki" / "sources").rglob("*.md"))


def _run(m, vault, reports, *extra):
    return m.main(["--vault", str(vault), "--dir", str(reports), "--years", "2026", *extra])


def test_skips_ingested_and_imports_only_new():
    m = _load("landscape_reports_import")
    with tempfile.TemporaryDirectory() as t:
        vault = Path(t) / "vault"; (vault / "wiki").mkdir(parents=True)
        reports = Path(t) / "reports"
        _report(reports, "2026", "Acme-Threat-Report-2026.md", "Acme Annual Threat Report 2026")
        assert _run(m, vault, reports) == 0
        first = _sources(vault)
        assert len(first) == 1, first                       # the one report imported

        # add a SECOND report, re-run: only the NEW one is imported, the existing is skipped
        _report(reports, "2026", "Beta-Ransomware-Report-2026.md", "Beta Ransomware Report 2026")
        _run(m, vault, reports)
        second = _sources(vault)
        assert len(second) == 2, second                     # new added, existing not duplicated
        assert set(first) <= set(second)                    # the first page survived unchanged

        # third run, nothing new -> no writes, no duplication (fast-path: all skipped)
        _run(m, vault, reports)
        assert _sources(vault) == second


def test_reprocess_reimports_without_duplicating():
    m = _load("landscape_reports_import")
    with tempfile.TemporaryDirectory() as t:
        vault = Path(t) / "vault"; (vault / "wiki").mkdir(parents=True)
        reports = Path(t) / "reports"
        _report(reports, "2026", "Acme-Threat-Report-2026.md", "Acme Threat Report 2026")
        _run(m, vault, reports)
        before = _sources(vault)
        assert _run(m, vault, reports, "--reprocess") == 0  # refresh path runs clean
        assert _sources(vault) == before                    # rewrites in place, no dup


def test_limit_caps_new_reports_and_drains_over_runs():
    m = _load("landscape_reports_import")
    with tempfile.TemporaryDirectory() as t:
        vault = Path(t) / "vault"; (vault / "wiki").mkdir(parents=True)
        reports = Path(t) / "reports"
        for i in range(5):
            _report(reports, "2026", f"Vendor{i}-Report-2026.md", f"Vendor{i} Threat Report 2026")
        _run(m, vault, reports, "--limit", "2")
        assert len(_sources(vault)) == 2                     # only 2 NEW imported this run
        _run(m, vault, reports, "--limit", "2")
        assert len(_sources(vault)) == 4                     # next run drains 2 more (ingested skipped)
        _run(m, vault, reports, "--limit", "2")
        assert len(_sources(vault)) == 5                     # last one; then steady-state


def test_filters_thin_and_flags_substantive():
    m = _load("landscape_reports_import")
    with tempfile.TemporaryDirectory() as t:
        vault = Path(t) / "vault"; (vault / "wiki").mkdir(parents=True)
        reports = Path(t) / "reports"
        _report(reports, "2026", "Real-Threat-Report-2026.md", "Real Threat Report 2026")            # substantive
        _report(reports, "2026", "Filler-Scam-Report-2026.md", "Filler Scam Report 2026", thin=True)  # thin
        _run(m, vault, reports)
        got = _sources(vault)
        assert len(got) == 1, got                                    # thin one filtered out
        assert _quality_of(vault, got[0]) == "substantive"          # kept one is flagged


def test_short_but_substantive_is_kept():
    """A SHORT report that still carries CVEs/URLs is substantive, not thin — the gate needs BOTH
    short and low-substance, so real short reports aren't dropped."""
    m = _load("landscape_reports_import")
    with tempfile.TemporaryDirectory() as t:
        vault = Path(t) / "vault"; (vault / "wiki").mkdir(parents=True)
        reports = Path(t) / "reports"
        p = reports / "Markdown Conversions" / "2026" / "Terse-KEV-Report-2026.md"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("# Terse KEV Report 2026\n\nShort but real: "
                     + " ".join(f"CVE-2026-01{i:02d}" for i in range(10)) + "\n", encoding="utf-8")
        _run(m, vault, reports)
        assert len(_sources(vault)) == 1                             # kept despite being short


def test_keep_thin_ingests_flagged():
    m = _load("landscape_reports_import")
    with tempfile.TemporaryDirectory() as t:
        vault = Path(t) / "vault"; (vault / "wiki").mkdir(parents=True)
        reports = Path(t) / "reports"
        _report(reports, "2026", "Filler-Report-2026.md", "Filler Report 2026", thin=True)
        _run(m, vault, reports, "--keep-thin")
        got = _sources(vault)
        assert len(got) == 1                                         # ingested (not filtered)
        assert _quality_of(vault, got[0]) == "thin"                 # but flagged thin


if __name__ == "__main__":
    test_skips_ingested_and_imports_only_new()
    test_reprocess_reimports_without_duplicating()
    test_limit_caps_new_reports_and_drains_over_runs()
    test_filters_thin_and_flags_substantive()
    test_short_but_substantive_is_kept()
    test_keep_thin_ingests_flagged()
    print("OK")
