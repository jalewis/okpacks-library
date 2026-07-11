"""cve_mentions: count CVE-ID prose mentions across sources/briefings, stamp report_mentions +
recent_report_mentions onto the matching cve/ pages, write the top-N dashboard. Idempotent."""
import importlib.util
import sys
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")
SCRIPT = Path(__file__).resolve().parent.parent / "crons" / "scripts" / "cve_mentions.py"


def _load():
    spec = importlib.util.spec_from_file_location("cve_mentions", SCRIPT)
    m = importlib.util.module_from_spec(spec)
    sys.modules["cve_mentions"] = m
    spec.loader.exec_module(m)
    return m


def _fm(p, fm, body=""):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("---\n" + yaml.safe_dump(fm) + "---\n\n" + body + "\n", encoding="utf-8")


def test_stamps_report_mentions(tmp_path):
    m = _load()
    wiki = tmp_path / "wiki"
    _fm(wiki / "cves" / "CVE-2026-48282.md", {"type": "cve", "cve_id": "CVE-2026-48282", "vendor": "Acme"})
    _fm(wiki / "cves" / "CVE-2026-45659.md", {"type": "cve", "cve_id": "CVE-2026-45659"})
    # two source docs cite the first CVE (one recent, one old); one cites the second
    _fm(wiki / "sources" / "s1.md", {"type": "source", "published": "2026-07-01"},
        "Exploited via CVE-2026-48282 and again CVE-2026-48282 (one appearance).")
    _fm(wiki / "sources" / "s2.md", {"type": "source", "published": "2020-01-01"}, "Old note on cve-2026-48282.")
    _fm(wiki / "briefings" / "b1.md", {"type": "briefing", "published": "2026-07-05"}, "Watch CVE-2026-45659.")

    assert m.main(["--vault", str(tmp_path), "--recent-days", "120"]) == 0
    fm1 = yaml.safe_load((wiki / "cves" / "CVE-2026-48282.md").read_text().split("---")[1])
    assert fm1["report_mentions"] == 2 and fm1["recent_report_mentions"] == 1   # 2 docs, 1 recent
    assert fm1["vendor"] == "Acme"                                              # other frontmatter preserved
    fm2 = yaml.safe_load((wiki / "cves" / "CVE-2026-45659.md").read_text().split("---")[1])
    assert fm2["report_mentions"] == 1
    dash = (wiki / "dashboards" / "top-cves-by-reporting.md").read_text()
    assert "CVE-2026-48282" in dash and "Top" in dash

    # idempotent: a second run changes nothing
    before = (wiki / "cves" / "CVE-2026-48282.md").read_text()
    assert m.main(["--vault", str(tmp_path)]) == 0
    assert (wiki / "cves" / "CVE-2026-48282.md").read_text() == before
