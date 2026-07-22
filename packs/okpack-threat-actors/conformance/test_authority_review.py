#!/usr/bin/env python3
"""Direct-authority import and reconciliation conformance."""
import importlib.util
import os
import shutil
import sys
import tempfile
from pathlib import Path

import yaml

PACK = Path(__file__).resolve().parent.parent
SCRIPTS = PACK / "crons" / "scripts"
LIB_ROOT = PACK.parents[2]


def _engine_lib() -> Path | None:
    for cand in (os.environ.get("OKENGINE_DIR"), str(LIB_ROOT.parent / "okengine")):
        path = Path(cand) / "scripts" / "cron" / "authority_lib.py" if cand else Path("/")
        if path.is_file():
            return path
    return None


def _load(name: str, path: Path):
    sys.modules.pop(name, None)
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _fm(path: Path) -> dict:
    return yaml.safe_load(path.read_text().split("---", 2)[1])


def test_attack_records_are_directly_disposed_by_policy():
    authority = _engine_lib()
    if authority is None:
        print("  skip ATT&CK authority test (set OKENGINE_DIR)")
        return
    with tempfile.TemporaryDirectory() as t:
        scripts = Path(t) / "scripts"
        scripts.mkdir()
        for name in ("_okf_write.py", "attack_import.py"):
            shutil.copy(SCRIPTS / name, scripts / name)
        shutil.copy(authority, scripts / "authority_lib.py")
        sys.path.insert(0, str(scripts))
        sys.modules.pop("_okf_write", None)
        attack = _load("attack_import_test", scripts / "attack_import.py")
        obj = {"type": "intrusion-set", "id": "intrusion-set--1", "name": "APT One",
               "modified": "2026-07-19T12:34:56.789Z",
               "external_references": [{"source_name": "mitre-attack", "external_id": "G0001",
                                        "url": "https://attack.mitre.org/groups/G0001/"}]}
        records, _ = attack.build_records([{"objects": [obj]}])
        rec = records[obj["id"]]
        assert "needs_review" not in rec["fm"]
        vault = Path(t) / "vault"
        attack.write_page(attack.content_root(vault), rec["path"], rec["fm"], attack.render_body(rec),
                          authority_policy=attack.MITRE_AUTHORITY_POLICY,
                          reviewed_at=rec["reviewed_at"])
        fm = _fm(vault / "wiki" / "entities" / "apt-one.md")
        assert fm["needs_review"] is False
        assert fm["review_state"] == "approved"
        assert fm["reviewed_at"] == "2026-07-19T12:34:56Z"


def test_cisa_reconcile_adds_canonical_source_and_clears_review():
    authority = _engine_lib()
    if authority is None:
        return
    with tempfile.TemporaryDirectory() as t:
        root = Path(t)
        scripts = root / "scripts"
        scripts.mkdir()
        for name in ("_okf_write.py", "authority_review_reconcile.py"):
            shutil.copy(SCRIPTS / name, scripts / name)
        shutil.copy(authority, scripts / "authority_lib.py")
        sys.path.insert(0, str(scripts))
        sys.modules.pop("_okf_write", None)
        reconcile = _load("authority_reconcile_test", scripts / "authority_review_reconcile.py")
        vault = root / "vault"
        actor = vault / "wiki" / "entities" / "f" / "fsb-center-16.md"
        source = vault / "wiki" / "sources" / "2026" / "07" / "13" / "cisa-router.md"
        actor.parent.mkdir(parents=True)
        source.parent.mkdir(parents=True)
        actor.write_text("""---
type: actor
title: FSB Center 16
attribution_confidence: confirmed
needs_review: true
np_source_refs: [sources/2026/07/13/cisa-router]
---
# FSB Center 16
See sources/2026//nsa-cisa-fsb-center-16-router-hardening.
""")
        source.write_text("""---
type: source
publisher: CISA Cybersecurity Advisories
kind: government-alert
published: 2026-07-13T12:00:00+00:00
url: https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-194a
---
# Advisory
Russian Federal Security Service FSB Center 16 cyber actors target routers.
""")
        result = reconcile.reconcile(vault, apply=True, actor="fsb-center-16")
        assert result == {"eligible": 1, "updated": 1, "skipped": 0, "errors": 0}
        fm = _fm(actor)
        assert fm["needs_review"] is False
        assert fm["review_state"] == "approved"
        assert fm["sources"] == ["sources/2026/07/13/cisa-router"]
        assert fm["authority_source_url"].startswith("https://www.cisa.gov/")
        assert "sources/2026/07/13/cisa-router" in actor.read_text()


def test_news_only_actor_stays_review_gated():
    authority = _engine_lib()
    if authority is None:
        return
    with tempfile.TemporaryDirectory() as t:
        root = Path(t)
        scripts = root / "scripts"
        scripts.mkdir()
        for name in ("_okf_write.py", "authority_review_reconcile.py"):
            shutil.copy(SCRIPTS / name, scripts / name)
        shutil.copy(authority, scripts / "authority_lib.py")
        sys.path.insert(0, str(scripts))
        sys.modules.pop("_okf_write", None)
        reconcile = _load("authority_reconcile_news_test", scripts / "authority_review_reconcile.py")
        vault = root / "vault"
        actor = vault / "wiki" / "entities" / "n" / "news-actor.md"
        actor.parent.mkdir(parents=True)
        actor.write_text("---\ntype: actor\ntitle: News Actor\nattribution_confidence: confirmed\nneeds_review: true\n---\nnews\n")
        result = reconcile.reconcile(vault, apply=True)
        assert result["eligible"] == 0
        assert _fm(actor)["needs_review"] is True


if __name__ == "__main__":
    failures = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"  ok   {name}")
            except Exception as exc:  # noqa: BLE001
                failures += 1
                print(f"  FAIL {name}: {exc}")
    raise SystemExit(1 if failures else 0)
