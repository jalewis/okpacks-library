#!/usr/bin/env python3
"""The vuln pack consumes the engine-staged shared NVD lane (#267)."""
import json
from pathlib import Path

PACK = Path(__file__).resolve().parents[1]


def test_nvd_cron_selects_cve_profile_and_pack_has_no_fork():
    jobs = json.loads((PACK / "crons" / "domain-crons.json").read_text(encoding="utf-8"))
    job = next(row for row in jobs if row["name"] == "okpack-vuln-nvd-import")
    assert job["script"] == "/opt/data/scripts/nvd_import.py"
    assert job["env"] == {"NVD_PAGE_MODEL": "cve"}
    assert not (PACK / "crons" / "scripts" / "nvd_import.py").exists()


if __name__ == "__main__":
    test_nvd_cron_selects_cve_profile_and_pack_has_no_fork()
    print("shared NVD lane conformance: OK")
