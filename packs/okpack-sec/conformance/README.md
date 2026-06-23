# okf-sec projection conformance

Proves — not claims — that okf-sec pages project to **valid STIX 2.1** (entities) and **valid OCSF**
(the event layer: `finding`/`detection`) — the two-altitude model (spec §1).

```bash
# STIX (entities) — spec §7.3, freeze item D
pip install stix2                          # optional, enables the official-validator leg
python3 conformance/run_conformance.py     # validate + golden compare (exit 1 on any failure)
python3 conformance/run_conformance.py --update   # (re)write golden fixtures after an intended change

# OCSF (event layer)
pip install py-ocsf-models                  # optional, enables the official OCSF model validation
python3 conformance/run_ocsf_conformance.py        # finding/detection -> Detection Finding (2004)
python3 conformance/run_ocsf_conformance.py --update
```

The OCSF suite mirrors the STIX one: project → structural check → official validation
(`py-ocsf-models` `DetectionFinding`) → documented-loss invariant (recorded loss == `event.unmapped`
keys) → golden compare (`conformance/golden-ocsf/`).

## What it checks, per fixture
1. **Project** the page → a STIX bundle via `projectors/stix.py` (deterministic ids/timestamps).
2. **Structural** — id/timestamp/`spec_version` shapes + per-SDO required properties.
3. **Official** — every object parsed through the OASIS `stix2` library (real STIX 2.1 validation).
   Skipped with a notice if `stix2` isn't installed; CI installs it (`.github/workflows/validate.yml`).
4. **Documented-loss invariant** — the recorded loss set equals *exactly* the `x_okfsec_*` custom
   properties on the primary object: no silent loss, no phantom loss.
5. **Golden** — byte-stable compare against `golden/<name>.json`.

## Status
- **18 fixtures — every okf-sec type — all pass official `stix2` validation.** The 12 entity types
  project to proper STIX 2.1 SDOs; the 6 okf-native types (software, detection, concept, finding,
  prediction, dashboard) project to valid `x-okfsec-<type>` **custom objects** (lossy-but-valid).
- **v0.2 refinements** (nicer native mappings): software → STIX `software` SCO; concept →
  `grouping`; finding/detection → OCSF.
- **Prototype limitation:** cross-page link resolution. The single-page projector derives target
  ids from `[[entities/<type>/<slug>]]` link paths; a whole-vault exporter would resolve links
  against the page graph.
- At the v0.1 extraction this moves to the `okf` repo as shared conformance machinery.
