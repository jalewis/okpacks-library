#!/usr/bin/env python3
"""Conformance for severity_normalize.py — self-heals free-text severity to a canonical CVSS band.

Invariants:
  1. coerce() returns the band ONLY when exactly one band token is present; already-canonical or
     zero/ambiguous values return None (never guessed).
  2. main() coerces off-enum pages (any type), leaves canonical + non-coercible ones, counts the
     latter as skipped; body + other frontmatter preserved; --dry-run writes nothing; idempotent.
  3. The band list is read from the vault's schema.yaml enums.severity (contract-driven).

Standalone (conformance-all.sh) and pytest-discoverable — no module-level pytest import.
"""
import importlib.util
import sys
import tempfile
from pathlib import Path

import yaml

SCRIPT = Path(__file__).resolve().parent.parent / "crons" / "scripts" / "severity_normalize.py"


def _load():
    spec = importlib.util.spec_from_file_location("severity_normalize", SCRIPT)
    m = importlib.util.module_from_spec(spec)
    sys.modules["severity_normalize"] = m
    spec.loader.exec_module(m)
    return m


def _write(p, fm, body="body"):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("---\n" + yaml.safe_dump(fm, sort_keys=False) + "---\n\n" + body + "\n", encoding="utf-8")


def _read(p):
    t = p.read_text(encoding="utf-8")
    return yaml.safe_load(t[3:t.find("\n---", 3)]) or {}


BANDS = ["critical", "high", "medium", "low", "none"]


def test_coerce_only_unambiguous():
    m = _load()
    assert m.coerce("critical (unauthenticated RCE exploit)", BANDS) == "critical"
    assert m.coerce("High severity", BANDS) == "high"
    assert m.coerce("critical", BANDS) is None            # already canonical
    assert m.coerce("critical/high", BANDS) is None       # two band tokens -> ambiguous, don't guess
    assert m.coerce("informational", BANDS) is None       # no band token -> leave for corpus_audit
    assert m.coerce("critically important", BANDS) is None  # 'critically' is not the token 'critical'


def _vault(t):
    root = Path(t)
    (root / "schema.yaml").write_text(yaml.safe_dump(
        {"enums": {"severity": BANDS}, "field_enums": {"severity": {"enum": "severity"}}}), encoding="utf-8")
    return root


def test_main_coerces_and_preserves():
    m = _load()
    with tempfile.TemporaryDirectory() as t:
        root = _vault(t); wiki = root / "wiki"
        # a misfiled source with free-text severity (the real okcti case) + curated fields to preserve
        _write(wiki / "cves" / "CVE-2026-8037.md",
               {"type": "cve", "cve_id": "CVE-2026-8037",
                "severity": "critical (unauthenticated RCE exploit)", "kev": True}, body="CVE body.")
        _write(wiki / "cves" / "CVE-1.md", {"type": "cve", "severity": "high"})          # canonical -> untouched
        _write(wiki / "cves" / "CVE-2.md", {"type": "cve", "severity": "informational"})  # non-coercible -> skipped

        assert m.main(["--vault", str(root)]) == 0
        fixed = _read(wiki / "cves" / "CVE-2026-8037.md")
        assert fixed["severity"] == "critical" and fixed["kev"] is True                   # coerced, curated kept
        assert "CVE body." in (wiki / "cves" / "CVE-2026-8037.md").read_text()            # body preserved
        assert _read(wiki / "cves" / "CVE-1.md")["severity"] == "high"                    # untouched
        assert _read(wiki / "cves" / "CVE-2.md")["severity"] == "informational"           # left for audit


def test_dry_run_and_idempotent():
    m = _load()
    with tempfile.TemporaryDirectory() as t:
        root = _vault(t); wiki = root / "wiki"
        page = wiki / "cves" / "CVE-9.md"
        _write(page, {"type": "cve", "severity": "Critical - actively exploited"})
        before = page.read_text()
        assert m.main(["--vault", str(root), "--dry-run"]) == 0
        assert page.read_text() == before                                                 # dry-run wrote nothing
        assert m.main(["--vault", str(root)]) == 0
        assert _read(page)["severity"] == "critical"
        mt = page.stat().st_mtime_ns
        assert m.main(["--vault", str(root)]) == 0                                         # second run: no change
        assert page.stat().st_mtime_ns == mt


if __name__ == "__main__":
    test_coerce_only_unambiguous()
    test_main_coerces_and_preserves()
    test_dry_run_and_idempotent()
    print("OK")
