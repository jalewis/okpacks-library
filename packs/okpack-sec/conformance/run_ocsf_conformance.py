#!/usr/bin/env python3
"""OCSF projection conformance for okf-sec (spec §1.3 two-altitude event layer).

Proves the event-layer types (`finding`, `detection`) project to valid OCSF **Detection Findings**.
Per fixture:
  1. project → an OCSF event (deterministic, golden-stable);
  2. structural check — class/category/type_uid arithmetic + required attrs;
  3. official check — `py-ocsf-models` `DetectionFinding(**event)` (real OCSF model validation).
     Skipped with a notice if not installed; CI installs it;
  4. documented-loss invariant — recorded loss == exactly the keys in `event.unmapped`;
  5. golden compare against conformance/golden-ocsf/<name>.json (or --update).

Usage:
    python3 conformance/run_ocsf_conformance.py            # validate + golden (exit 1 on fail)
    python3 conformance/run_ocsf_conformance.py --update    # (re)write golden
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from projectors.ocsf import project_page, CLASS_UID, CATEGORY_UID, TYPE_UID  # noqa: E402

GOLDEN = Path(__file__).resolve().parent / "golden-ocsf"

# Event-layer fixtures (mirroring the STIX coverage fixtures for finding/detection).
FIXTURES = [
    ("finding-unpatched-xz", "unpatched-xz-prod", {
        "type": "finding", "name": "Unpatched xz on production hosts", "severity": "high",
        "status": "open", "created": "2026-06-16", "updated": "2026-06-16",
        "rels": {"related-to": ["[[entities/vulnerability/xz-utils-backdoor]]"]}, "tags": ["exposure"]}),
    ("detection-sigma", "sigma-encoded-powershell", {
        "type": "detection", "name": "Sigma — encoded PowerShell with anomalous parent",
        "rule_format": "sigma", "confidence": "medium", "created": "2026-06-16", "updated": "2026-06-16",
        "rels": {"detects": ["[[entities/attack-pattern/t1059-001-powershell]]"]},
        "tags": ["sigma", "execution"]}),
]


def structural_errors(event: dict) -> list:
    errs = []
    if event.get("class_uid") != CLASS_UID:
        errs.append(f"class_uid != {CLASS_UID}")
    if event.get("category_uid") != CATEGORY_UID:
        errs.append(f"category_uid != {CATEGORY_UID}")
    if event.get("type_uid") != TYPE_UID:
        errs.append(f"type_uid != {TYPE_UID} (class_uid*100 + activity_id)")
    md = event.get("metadata") or {}
    if not md.get("version") or not md.get("product"):
        errs.append("metadata missing version/product")
    if not isinstance(event.get("severity_id"), int):
        errs.append("severity_id not int")
    if "time" not in event:
        errs.append("missing time")
    fi = event.get("finding_info") or {}
    if not fi.get("uid") or not fi.get("title"):
        errs.append("finding_info missing uid/title")
    return errs


def loss_invariant_errors(result: dict) -> list:
    """recorded loss == exactly the keys carried in event.unmapped."""
    on_obj = set((result["event"].get("unmapped") or {}).keys())
    recorded = set(result["loss"])
    return [] if on_obj == recorded else [f"loss mismatch: recorded={sorted(recorded)} unmapped={sorted(on_obj)}"]


def ocsf_errors(event: dict):
    """Validate via the official py-ocsf-models Detection Finding model, if installed."""
    try:
        from py_ocsf_models.events.findings.detection_finding import DetectionFinding
    except Exception:  # noqa: BLE001
        return [], False
    try:
        DetectionFinding(**event)
        return [], True
    except Exception as e:  # noqa: BLE001
        return [f"py-ocsf-models rejected: {str(e)[:200]}"], True


def main() -> int:
    update = "--update" in sys.argv
    GOLDEN.mkdir(exist_ok=True)
    fail = 0
    ran = False
    for name, slug, page in FIXTURES:
        result = project_page(page, slug)
        if result is None:
            print(f"FAIL  {name}: not an event-layer type")
            fail += 1
            continue
        event = result["event"]
        errs = structural_errors(event) + loss_invariant_errors(result)
        oe, r = ocsf_errors(event)
        ran = ran or r
        errs += oe

        gp = GOLDEN / f"{name}.json"
        payload = {"event": event, "loss": result["loss"]}
        if update:
            gp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
        elif gp.exists():
            if json.loads(gp.read_text()) != payload:
                errs.append("golden mismatch (run --update if intended)")
        else:
            errs.append("golden missing (run --update)")

        if errs:
            fail += 1
            print(f"FAIL  {name}  (loss={result['loss']})")
            for e in errs:
                print(f"        - {e}")
        else:
            print(f"ok    {name}  (loss={result['loss']})")

    note = "validated via py-ocsf-models" if ran else \
        "py-ocsf-models not installed — structural+golden only (pip install py-ocsf-models)"
    print(f"\n{len(FIXTURES) - fail}/{len(FIXTURES)} fixtures pass · {note}")
    if update:
        print("golden-ocsf written.")
    return 1 if fail else 0


if __name__ == "__main__":
    raise SystemExit(main())
