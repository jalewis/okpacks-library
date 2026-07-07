# Changelog — okf-sec

All notable changes to the okf-sec spec + reference implementation. Changes are classified per
spec §12.2 — **Breaking** / **Additive** / **Editorial**. Format loosely follows
[Keep a Changelog]. okf-sec uses `MAJOR.MINOR`; **pre-1.0, a MINOR bump may break.**

[Keep a Changelog]: https://keepachangelog.com/

## 0.3.0 — **Breaking**: okpack-sec becomes a pack BUNDLE (okengine#181)

The monolith (14 owned types, one schema) is decomposed into a family of focused composable packs;
`okpack-sec` is now a `kind: bundle` that owns nothing and declares a recipe composing them:

- **host** `okpack-threat-actors` (actor/campaign/malware/tool/technique) + STIX 2.1 / OCSF projectors
- **compose** `okpack-vuln` (cve), `okpack-threat-landscape` (metric/publisher), `okpack-indicators`
  (indicator/infrastructure), `okpack-detections` (detection/course-of-action), `okpack-incidents`
  (incident/identity)

STIX/legacy type names resolve to the friendly canonical types via each pack's `type_aliases`
(threat-actor→actor, attack-pattern→technique, vulnerability→cve, mitigation→course-of-action,
organization→identity, …). `framework pull okpack-sec` reproduces the full security vault in one
command. The pre-bundle monolith (schema, importers, conformance) remains in git history; the STIX/
OCSF projectors were preserved and moved to the composition-root pack.

## [Unreleased]

### Added (additive — §12.2)
- **OKF-SEC-SPEC §13 Multi-source entity resolution (MDM)** — documents the multi-source
  observation/canonical model that was implemented (`source_registry` + `merge_policy` in
  `schema.yaml`, the engine's `canonical_assemble`) but absent from the spec: the two page kinds
  (`observations/<source>/` vs canonical `entities/`), which types are multi-source, the
  over-merge-guarded canonical resolution (okengine#39), the `merge_policy` fusion
  (union/consensus/latest), the `source_registry` Admiralty weights, and conflict surfacing
  (`conflicts` / `needs_review`). Pack side of okengine#38 (okpacks-library#7).

### Added (additive — §12.2)
- **`incident` type** (OKF-SEC-SPEC §8, schema.yaml, CLAUDE.md) — a first-class security
  *event* (breach / ransomware hit / data leak), distinct from `campaign` (sustained operation)
  and `finding` (analyst output), projecting to the STIX 2.1 `incident` stub SDO. Adds the
  `incident_type` enum (breach/data-leak/ransomware/…, extensible) + `Incidents` browse group.
  The chat agent had been inventing `type: incident` for lack of one (okpacks-library#32).
- **Actor-body synthesis guidance for `page-quality-enrich`** (CLAUDE.md): a new "Enriching a page"
  section directs the enrich agent to augment thin actor pages (`intrusion-set`/`threat-actor`) with
  sourced `## Tradecraft` / `## Recent activity` / `## Motivation & attribution` sections grounded
  ONLY in citing sources, cross-linked, appended (never replacing the MITRE baseline or agent-added
  sections). Unblocked once #2 (attack-refs) gave flagship actors citing sources (okpacks-library#10).

### Changed (clarification — no schema/projection change)
- **`threat-actor` vs `intrusion-set` typing rule sharpened** (OKF-SEC-SPEC §5, schema comments,
  CLAUDE.md): `intrusion-set` is now stated as the DEFAULT for any named adversary *group* —
  APTs, ransomware crews, syndicates — and `threat-actor` is reserved for a named *individual*
  human operator. Removes the prior "crew → threat-actor" ambiguity that split named adversaries
  across two types (a query filtered to one saw only a fraction). Both types still project to
  their STIX SDOs and already browse together under the "Threat actors" `display_group`; an actor
  *search* must span both. No change to types/enums/projection (okpacks-library#14).

Second profile release: promotes OCSF to a normative, conformance-proven projection, finishes the
v0.2 spec follow-through (#13), and completes the engine-v0.2.0 alignment (#12). Pre-1.0, so a MINOR
may break (§12.1).

### Changed
- **OCSF projection promoted from informative (v0.1) to normative (v0.2).** Both altitudes are now
  normative and CI-proven against the standards' official validators: entity layer → STIX 2.1 +
  ATT&CK (`stix2`), event layer (`finding`/`detection`) → OCSF Detection Finding (`py-ocsf-models`).

### Added (additive — §12.2)
- `CLAUDE.md`: conflicting-intelligence handling — when sources disagree (e.g. APT29 vs APT28),
  append both claims with their sources, drop `confidence` to `low`, add a `## Disputed` note, and
  flag for human review; never silently overwrite.
- `validate.py`: defang check for `indicator.value` (live ip/domain/url/email → warn; flag-not-gate).
- v0.2.0 engine adaptation (#12): bump engine pin to `v0.2.0`; drop pack-level `strict_types`
  (now engine-owned); add `pack.yaml` composition manifest (validated, `owns` synced to `schema.yaml`);
  adopt composable-okpacks identity keys — `owner: okpack-sec` on all types, `id_authority`/`id_field`
  on the mitre/cve-backed types, `mitre_id` now required on `course-of-action`.
- README (#14): note the cron-plus scheduler plugin as a deploy prerequisite (the fleet silently
  won't schedule without it).
- `finding.required` reconciled (#13.3): kept `severity` required as an intentional okpack-sec
  tightening vs the engine base `[type, status]`; recorded in spec §10.6.
- OCSF projector (#13.1): `projectors/ocsf.py` projects the event-layer types (`finding`, `detection`)
  to OCSF **Detection Findings** (class 2004) — severity/status/confidence → OCSF ids, identity →
  `finding_info`, no-OCSF-home fields → `unmapped`. Validated against the official `py-ocsf-models`
  (`conformance/run_ocsf_conformance.py`: structural + golden + documented-loss invariant; CI-enforced).
- Whole-vault link resolution (#13.2): the STIX projector resolves `rels`/wikilink targets against
  the real page graph — `build_vault_index` maps each page to its true type+identity STIX id, so a
  link (even slug-only `[[apt29]]` or a by-letter path) resolves to the id the target actually emits;
  the link-path-shape heuristic remains the single-page fallback. `project_vault` projects a whole
  vault with cross-links resolved. Tested by `conformance/test_vault_resolution.py` (CI-enforced).
  This closes the v0.2 spec follow-through (#13).

### Editorial
- Spec header: lineage note crediting the Google Open Knowledge Format (OKF) as the base format
  (formalizing Karpathy's "LLM wiki" pattern); okf-sec is its security profile.

### Still deferred (future)
- Nicer native STIX maps (`software`→STIX `software` SCO, `concept`→`grouping`).

## [0.1] — 2026-06-17 (targets OKF base v0.1)

Initial profile release. Pre-1.0, so a future MINOR may break (§12.1).

### Added
- Page envelope, founding rules, and the projection model — STIX 2.1 + ATT&CK normative;
  OCSF informative, deferred to v0.2.
- Type roster with STIX-2.1-aligned canonical names + `type_aliases` for legacy/vault names;
  `identity` consolidates vendor/org/person/agency.
- Relationship vocabulary (`rels`) — controlled predicates projecting to STIX SROs.
- Field dictionary with every enum spelled out; machine-readable `enums` + `field_enums` in
  `schema.yaml`.
- 18 worked examples (3 exemplars in §3–5 + 7 in §8.1) covering every type.
- Versioning & governance (§12): change classes, alias-deprecation policy, conformance levels.
- STIX 2.1 projection (`projectors/stix.py`) + conformance suite (`conformance/`): all 18 types pass
  the official OASIS `stix2` validator (CI-wired, golden fixtures, documented-loss invariant).
- Enforcement (`validate.py`): type/alias integrity; enum values incl. list-of-object
  (`refs[].std`, `cvss[].*`) — gated; required-field, `rels`-predicate, and `refs[]`-shape checks
  (flag-not-gate); `§N` cross-ref resolution; spec↔schema drift guard (generated §9.5 machine reference).
- Versioning: `schema.yaml` `okf_sec_version` pins the spec version a pack implements.

### Not yet (v0.2 / future)
- v0.2: normative OCSF mapping; nicer native maps (software→SCO, concept→grouping).
- Full-vault cross-page link resolution in the projector (single-page resolves via link paths).

<!-- Template for releases after v0.1 is cut:
## [0.2] — YYYY-MM-DD
### Breaking
### Additive
### Editorial
-->
