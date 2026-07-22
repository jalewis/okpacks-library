#!/usr/bin/env python3
"""Conformance: the STIX 2.1 + OCSF projectors map the composed vault's FRIENDLY canonical types
to the correct external objects (okengine#181).

okpack-threat-actors is the composition ROOT of the security bundle, so it carries the reference
projectors (`projectors/stix.py`, `projectors/ocsf.py`). This proves they still project correctly
after the friendly-name reconciliation: a `type: actor` page must emit a STIX `intrusion-set`,
`technique` an `attack-pattern`, `cve` a `vulnerability`, etc. — and a `detection` page an OCSF
Detection Finding. Deterministic (no network); pytest-discoverable and standalone-runnable.
"""
import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _load(name):
    spec = importlib.util.spec_from_file_location(f"projectors.{name}", ROOT / "projectors" / f"{name}.py")
    m = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = m
    spec.loader.exec_module(m)
    return m


stix = _load("stix")
ocsf = _load("ocsf")

# friendly canonical type -> the STIX SDO type it must project to
_STIX_EXPECT = {
    "actor": "intrusion-set", "technique": "attack-pattern", "cve": "vulnerability",
    "malware": "malware", "tool": "tool", "campaign": "campaign",
    "indicator": "indicator", "infrastructure": "infrastructure",
    "course-of-action": "course-of-action", "identity": "identity", "publisher": "identity",
}


def _sdo_types(page):
    return {o["type"] for o in stix.project_page(page, page.get("id", "x")).get("bundle", {}).get("objects", [])}


def test_friendly_types_project_to_expected_stix_sdo():
    for ftype, expected in _STIX_EXPECT.items():
        page = {"type": ftype, "name": f"example-{ftype}", "id": f"example-{ftype}"}
        got = _sdo_types(page)
        assert expected in got, f"{ftype!r} -> {sorted(got)}, expected STIX {expected!r}"


def test_stix_projection_is_deterministic():
    page = {"type": "actor", "name": "APT-Example", "id": "apt-example"}
    a = stix.project_page(page, "apt-example")["bundle"]
    b = stix.project_page(page, "apt-example")["bundle"]
    assert a == b, "same page must project to an identical (deterministic) STIX bundle"


def test_detection_and_finding_project_to_ocsf():
    det = ocsf.project_page({"type": "detection", "name": "Sample rule", "confidence": "high"}, "sample-rule")
    assert det is not None and det["event"]["class_uid"] == ocsf.CLASS_UID   # OCSF Detection Finding
    find = ocsf.project_page({"type": "finding", "name": "A finding", "severity": "high"}, "a-finding")
    assert find is not None and find["event"]["class_uid"] == ocsf.CLASS_UID
    # a non-event type is NOT an OCSF finding (it's STIX)
    assert ocsf.project_page({"type": "actor", "name": "x"}, "x") is None


def _run() -> int:
    fails = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"  ok   {name}")
            except AssertionError as e:
                fails += 1
                print(f"  FAIL {name}: {e}")
    return fails


if __name__ == "__main__":
    print("== okpack-threat-actors projector conformance ==")
    n = _run()
    print("projectors OK" if not n else f"{n} projector test(s) failed")
    sys.exit(1 if n else 0)
