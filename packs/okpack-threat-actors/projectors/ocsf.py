"""Project okf-cti event-layer pages → OCSF (Detection Finding, class_uid 2004).

The two-altitude model (spec §1.3): entity pages → STIX 2.1 (`projectors/stix.py`);
event/observation records → OCSF. okf-cti's OCSF-facing types are `finding` (an analyst
finding/judgment) and `detection` (a detection rule/analytic). Both project to an OCSF
**Detection Finding** — the modern findings class (Security Finding 2001 is deprecated).

Pure stdlib. Deterministic — ids/time derived from page content, so output is golden-stable.
Fields with no OCSF home ride the OCSF `unmapped` object (documented loss, the OCSF analog of
STIX `x_okfcti_*`). Entity types return None (they are STIX, not OCSF).

API: project_page(frontmatter: dict, slug: str) -> {"event": <ocsf dict>, "loss": [...]} | None
"""
from __future__ import annotations

from datetime import datetime, timezone

OCSF_VERSION = "1.3.0"
PRODUCT = {"name": "okf-cti", "vendor_name": "okpack-cti"}
CLASS_UID = 2004          # Detection Finding
CATEGORY_UID = 2          # Findings
ACTIVITY_ID = 1           # Create
TYPE_UID = CLASS_UID * 100 + ACTIVITY_ID   # 200401
OCSF_TYPES = {"finding", "detection"}

# okf-cti `severity` → OCSF severity_id (0 Unknown · 1 Informational · 2 Low · 3 Medium · 4 High · 5 Critical · 6 Fatal)
SEVERITY_ID = {"none": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
SEVERITY_NAME = {0: "Unknown", 1: "Informational", 2: "Low", 3: "Medium", 4: "High", 5: "Critical", 6: "Fatal"}
# okf-cti `finding` status → OCSF (status_id, status)
FINDING_STATUS = {"open": (1, "New"), "investigating": (2, "In Progress"), "confirmed": (2, "In Progress"),
                  "resolved": (4, "Resolved"), "dismissed": (3, "Suppressed")}
# okf-cti `confidence` (detection) → OCSF confidence_id (1 Low · 2 Medium · 3 High)
CONFIDENCE_ID = {"low": 1, "medium": 2, "high": 3}
CONFIDENCE_NAME = {1: "Low", 2: "Medium", 3: "High"}

# Envelope keys consumed by common mapping (never documented loss).
_ENVELOPE = {"type", "name", "description", "created", "updated", "tags"}


def _epoch_ms(date) -> int:
    """A 'YYYY-MM-DD' page date → epoch milliseconds (UTC). Deterministic; 0 if absent/bad."""
    if not date:
        return 0
    try:
        dt = datetime.strptime(str(date)[:10], "%Y-%m-%d").replace(tzinfo=timezone.utc)
        return int(dt.timestamp() * 1000)
    except Exception:  # noqa: BLE001
        return 0


def project_page(page: dict, slug: str):
    """Project one okf-cti page to an OCSF Detection Finding. None for non-event types."""
    okf_type = page.get("type")
    if okf_type not in OCSF_TYPES:
        return None
    name = page.get("name") or slug.replace("-", " ")
    consumed = set(_ENVELOPE)
    loss: dict = {}

    finding_info: dict = {"uid": f"{okf_type}--{slug}", "title": name}
    if page.get("description"):
        finding_info["desc"] = page["description"]
    if page.get("tags"):
        finding_info["types"] = list(page["tags"])

    event = {
        "metadata": {"version": OCSF_VERSION, "product": PRODUCT},
        "category_uid": CATEGORY_UID, "category_name": "Findings",
        "class_uid": CLASS_UID, "class_name": "Detection Finding",
        "activity_id": ACTIVITY_ID, "activity_name": "Create",
        "type_uid": TYPE_UID,
        "time": _epoch_ms(page.get("created")),
        "finding_info": finding_info,
        "message": page.get("description") or name,
    }

    if okf_type == "finding":
        sid = SEVERITY_ID.get(page.get("severity"), 1)
        event["severity_id"] = sid
        event["severity"] = SEVERITY_NAME[sid]
        if page.get("status") in FINDING_STATUS:
            event["status_id"], event["status"] = FINDING_STATUS[page["status"]]
        consumed |= {"severity", "status"}
    else:  # detection — a rule/analytic, not severity-bearing; map confidence → OCSF confidence
        event["severity_id"], event["severity"] = 1, "Informational"
        event["status_id"], event["status"] = 1, "New"
        cid = CONFIDENCE_ID.get(page.get("confidence"))
        if cid:
            event["confidence_id"], event["confidence"] = cid, CONFIDENCE_NAME[cid]
            consumed.add("confidence")
        if page.get("rule_format"):
            finding_info["types"] = (finding_info.get("types") or []) + [f"rule:{page['rule_format']}"]
            consumed.add("rule_format")

    # documented loss: every remaining field → OCSF `unmapped`
    unmapped = {k: v for k, v in page.items() if k not in consumed and v is not None}
    if unmapped:
        event["unmapped"] = unmapped
        loss = unmapped

    return {"event": event, "loss": sorted(loss)}
