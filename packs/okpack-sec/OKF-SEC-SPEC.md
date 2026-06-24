# OKF-SEC — Security profile of the Open Knowledge Format

**Status:** `okf-sec v0.2` (targets OKF base v0.1) · STIX 2.1 + ATT&CK + OCSF projection normative
· versioning policy in §12, change log in `CHANGELOG.md`
**Layer:** profile on top of OKF base (markdown + YAML frontmatter; only `type` is required)
**Goal:** one canonical markdown record per security noun that can *project* to STIX 2.1,
MITRE ATT&CK, and OCSF (all normative) — a superset store, lossy-but-valid export.
**License:** Apache-2.0 (matching the OKF ecosystem — engine and packs).
**Lineage:** the [Google Open Knowledge Format](https://cloud.google.com/blog/products/data-analytics/how-the-open-knowledge-format-can-improve-data-sharing)
(OKF) — Google's minimal markdown + YAML-frontmatter convention for sharing structured context with
AI agents, which formalizes Andrej Karpathy's ["LLM wiki"](https://gist.github.com/karpathy/442a6bf555914893e9891c11519de94f)
pattern. OKF is deliberately bare-bones; **okf-sec is its security profile**, and OKEngine is a
conformant runtime.

> **okf-sec v0.2.** The taxonomy, relationship vocabulary, field dictionary, enums, governance, and
> the projections — STIX 2.1 + ATT&CK (all 18 types) and OCSF (the `finding`/`detection` event layer),
> each proven against the standard's official validator (§7.3) — are normative and frozen. Reference
> implementation: `schema.yaml`, `validate.py`, `projectors/`, and `conformance/` in this repo (§11).

---

## 0. Scope and non-goals

- **In scope:** the canonical frontmatter envelope, per-type field sets, the cross-standard
  xref block, and the projection contract (how a page emits valid STIX/ATT&CK/OCSF).
- **Non-goal — lossless round-tripping.** You cannot round-trip STIX ↔ OCSF; they model
  different things. okf-sec is the **superset**; export to any one standard emits the subset
  that standard covers. Import maps in and fills xrefs. Honest target: *lossy-but-valid*, both ways.
- **Non-goal — replacing the standards.** okf-sec is the AI-agent *storage and reasoning*
  layer. STIX/ATT&CK/OCSF remain the wire/interchange formats it speaks.
- **Enrichment is source-agnostic.** "Enrichment data" per type names the underlying *standards
  and public feeds* (ATT&CK, NVD, CISA KEV, EPSS, abuse.ch, MISP, BGP/RPKI, …). How a deployment
  fetches them — directly, or via an aggregator service — is **out of scope**; no specific service
  is part of the spec.
- **Projection scope (v0.2).** Two altitudes, both **normative** and conformance-proven (§7.3):
  STIX 2.1 + ATT&CK for the **entity** layer (all 18 types, official `stix2`), and OCSF for the
  **event** layer (`finding`/`detection` → OCSF **Detection Finding** class 2004, official
  `py-ocsf-models`). OCSF was informative-and-deferred in v0.1; it is promoted to normative in v0.2.

---

## 1. Founding rules

1. **Types carry *kind*; fields carry *specificity*.** `CVE` is not a type — it is a
   `vulnerability` with a `cve_id`. `ransomware` is `malware{category: ransomware}`. A
   `government-agency` is an `identity{sector: government}`. The type axis stays small and
   stable; richness lives in fields. This single rule kills the type-sprawl class
   (`cve`, `ransomware-family`, `law-enforcement`, generic `entity`…) seen in real vaults.
2. **Canonical store + projections.** The markdown page is the source of truth. STIX, ATT&CK,
   and OCSF are *views* generated from it, never the primary store.
3. **Two altitudes, two projection targets.**
   - **Entity pages** (durable nouns: this actor, this CVE, this technique) → **STIX 2.1 SDOs**
     and **ATT&CK** objects.
   - **Event/observation records** (`finding`, `detection` sightings, "seen on host X at time T")
     → **OCSF**. Do *not* force entity pages into OCSF's event shape — that is a category error
     (OCSF `vulnerability_finding` is an *event*; STIX `vulnerability` is a *definition*).
4. **Flag, not gate.** "Required" below means *expected* — a missing required field stamps the
   page for review (`needs_review`), it does not reject the write. This is what lets you file a
   0-day `vulnerability` with `cve_id: null` and enrich the ID later (e.g. from NIRDS).
5. **Bounded flexibility.** A *tiny strict core* (the noun axis + identity field + projection
   contract) plus an *open but schema'd* extension surface (`refs`, `rels`, `tags`, domain
   fields). Rigid where interoperability lives; open where agent ergonomics live.

---

## 2. The page envelope (common frontmatter)

Every okf-sec entity page shares this envelope. Per-type sections add their own fields. Field
semantics — types, allowed values, formats — are defined normatively in **§9 (Field dictionary)**;
relationships in **§6**.

```yaml
---
type: <one of the okf-sec types>      # OKF base requirement (the only hard-required field)
name: "<human label>"                  # natural-language identity; the page's display key
aliases: ["<other names>"]             # alias soup lives here (projects to STIX `aliases`)
description: "<one-paragraph what/why>"

# --- provenance / lifecycle (OKF common-optional, renamed for security work) ---
created: 2026-06-16                     # first authored
updated: 2026-06-16                     # last touched (drives tier hot/warm/cold)
first_seen: 2026-01-04                  # when the thing was first observed in the wild
last_seen:  2026-06-10                  # most recent sighting
confidence: 0.0–1.0 | low|medium|high   # analyst confidence (numeric never flags; see review)
tlp: clear | green | amber | amber+strict | red   # sharing restriction (marked on projection)
sources: ["[[sources/2026-06-10-vendor-report]]"]   # provenance wikilinks (Admiralty-scored)
tags: [kebab, case, labels]

# --- cross-standard identifiers (THE superset hook) ---
refs:                                   # every external identifier this noun carries
  - {std: cve,          id: "CVE-2024-3094"}
  - {std: cwe,          id: "CWE-506"}
  - {std: mitre-attack, id: "T1195.001", url: "https://attack.mitre.org/techniques/T1195/001/"}
  - {std: nvd,          url: "https://nvd.nist.gov/vuln/detail/CVE-2024-3094"}
stix:                                   # projection hints (optional; defaults inferred)
  type: vulnerability                   # override when the SDO name differs (e.g. intrusion-set)
  id: vulnerability--<stable-uuid>      # pin a stable STIX id across exports (else derived)

# --- typed relationships (project to STIX SROs; see §6) ---
rels:
  exploited-by: ["[[entities/malware/xz-backdoor]]"]
  affects:      ["[[entities/software/xz-utils]]"]
---
```

**Why `refs:` as a list of `{std, id, url}`** — it maps 1:1 onto STIX `external_references`,
carries *many* IDs per noun (a vuln is often CVE + GHSA + CWE + vendor advisory at once), and
survives the 0-day case (a noun with zero `cve` refs is still a valid `vulnerability`). Top-level
convenience fields (`cve_id`, `mitre_id`) MAY mirror the primary ref for ergonomics/search.

**Why `rels:` as typed predicates** — each predicate maps to a STIX relationship type, so the
graph projects to SROs mechanically (§6). Body `[[wikilinks]]` are still accepted (flag-not-gate),
but typed rels are what make the projection lossless on the relationship axis.

A multi-source noun (one described by several disagreeing sources) is additionally stored as
per-source **observation** pages that fuse into this canonical envelope — adding `source`,
`canonical`, `reliability`, `credibility`, `assembled_from`, and `conflicts`. See **§13**.

---

## 3. Type: `vulnerability`

> A weakness with narrative weight (exploited / KEV / widely affected). A CVE is the common
> *identifier* of a vulnerability, not a separate type — file the vuln, attach the CVE as a ref.

**Identity:** `name` (always) + `cve_id` (the natural key when assigned; **nullable** for 0-days).

| Field | Tier | Notes / projection |
|---|---|---|
| `name` | R | short title ("xz-utils backdoor (CVE-2024-3094)") → STIX `name` |
| `cve_id` | ★ | nullable; mirrors `refs[std=cve]` → STIX `external_references` |
| `description` | ★ | → STIX `description` |
| `severity` | ★ | `none\|low\|medium\|high\|critical` (usually derived from CVSS) |
| `cvss` | ★ | list: `[{version: "3.1", base_score: 10.0, vector: "...", severity: critical}]` |
| `epss` | | `{score: 0.94, percentile: 0.99, date: 2026-06-10}` (exploit-prediction) |
| `cwe` | ★ | `[CWE-506]` weakness class → `refs` / STIX `external_references` |
| `capec` | | `[CAPEC-442]` attack pattern of the weakness |
| `exploitation` | ★ | `{status: unreported\|poc\|active\|weaponized, kev: true, kev_date: ..., ransomware_use: false}` |
| `affected` | ★ | list: `[{vendor, product, cpe: "cpe:2.3:a:...", versions: "<5.6.2"}]` |
| `patched` | ★ | `{available: true, date: 2026-04-01, fixed_versions: ["5.6.2"]}` |
| `disclosed` / `published` / `modified` | | disclosure + NVD timestamps |
| `exploit_refs` | | links to public PoCs / exploit code |
| `rels.exploited-by` | ★ | malware / actor / campaign → STIX SRO `exploits` (reversed) |
| `rels.affects` | ★ | software / product entities → SRO |

**STIX 2.1 projection (`vulnerability` SDO):**

| okf-sec | STIX 2.1 |
|---|---|
| `type` | `vulnerability` |
| `name`, `description` | `name`, `description` |
| `cve_id`, `cwe`, `refs[*]` | `external_references[{source_name, external_id, url}]` |
| `created`/`updated` | `created`/`modified` |
| `tlp` | `object_marking_refs` → TLP marking-definition |
| `cvss`, `epss`, `exploitation`, `affected`, `patched` | **no native STIX 2.1 fields** → emit as `extensions` / `x_okfsec_*` custom props (documented loss) |

**OCSF projection:** entity → enriches the **Vulnerability Finding** class (uid 2002): page
populates the embedded `vulnerability` object (`cve.uid`, `cve.cvss`, `cwe.uid`, `references`,
`is_exploit_available`, `is_fix_available`). The page is the *definition*; OCSF consumes it inside
*finding events* authored at the `finding` layer.

**Enrichment data:** NVD (CVSS, CPE, CWE), CISA **KEV**, **EPSS**, OWASP, CPE Dictionary.

<details><summary>Full example page</summary>

```markdown
---
type: vulnerability
name: "xz-utils backdoor (CVE-2024-3094)"
aliases: ["xz backdoor", "liblzma backdoor"]
description: "Malicious code planted in xz-utils 5.6.0/5.6.1 liblzma, enabling SSH RCE on
  affected distros via a multi-stage build-time supply-chain implant."
created: 2026-06-16
updated: 2026-06-16
first_seen: 2024-03-29
confidence: high
tlp: clear
severity: critical
cve_id: CVE-2024-3094
cvss:
  - {version: "3.1", base_score: 10.0, vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", severity: critical}
epss: {score: 0.94, percentile: 0.99, date: 2026-06-10}
cwe: [CWE-506]
exploitation: {status: weaponized, kev: true, kev_date: 2024-03-29, ransomware_use: false}
affected:
  - {vendor: "tukaani", product: "xz-utils", cpe: "cpe:2.3:a:tukaani:xz:5.6.0:*:*:*:*:*:*:*", versions: "5.6.0 – 5.6.1"}
patched: {available: true, date: 2024-03-30, fixed_versions: ["5.6.2"]}
refs:
  - {std: cve, id: "CVE-2024-3094"}
  - {std: cwe, id: "CWE-506"}
  - {std: nvd, url: "https://nvd.nist.gov/vuln/detail/CVE-2024-3094"}
rels:
  exploited-by: ["[[entities/malware/xz-backdoor]]"]
  affects: ["[[entities/software/xz-utils]]"]
sources: ["[[sources/2024/03/2024-03-29-redhat-xz-backdoor]]"]
tags: [supply-chain, ssh, backdoor, linux]
---

## Summary
…analyst narrative…

## Detection
…sigma/yara pointers ([[entities/detection/...]])…
```
</details>

---

## 4. Type: `attack-pattern`

> A MITRE ATT&CK (sub)technique — adversary behavior. Canonical name is `attack-pattern`
> (STIX SDO name); the vault's `technique` is accepted as an alias on import.

**Identity:** `mitre_id` (e.g. `T1059.001`) — the natural key. `name` always present.

| Field | Tier | Notes / projection |
|---|---|---|
| `name` | R | "PowerShell" → STIX `name` |
| `mitre_id` | R | `T1059.001`; mirrors `refs[std=mitre-attack]` |
| `description` | ★ | → STIX `description` |
| `aliases` | | → STIX `aliases` |
| `is_subtechnique` | ★ | bool → `x_mitre_is_subtechnique` |
| `parent_technique` | ★ | `T1059` / `[[wikilink]]` → SRO `subtechnique-of` |
| `tactics` | R | `[execution]` (kill-chain phases) → STIX `kill_chain_phases` |
| `platforms` | ★ | `[windows, linux, macos, cloud, …]` → `x_mitre_platforms` |
| `data_sources` | | ATT&CK data sources/components → `x_mitre_data_sources` |
| `detection` | ★ | prose detection guidance → `x_mitre_detection` |
| `permissions_required`, `defenses_bypassed` | | → `x_mitre_*` |
| `capec` | | `[CAPEC-…]` → `external_references` |
| `d3fend` | | MITRE D3FEND countermeasure ids (defensive mapping) |
| `version` | | `x_mitre_version` |
| `rels.used-by` | ★ | actors/malware → SRO `uses` (reversed) |
| `rels.mitigated-by` | | mitigations (M-ids) → SRO `mitigates` (reversed) |
| `rels.detected-by` | ★ | detection entities → SRO `detects` (reversed) |

**STIX 2.1 projection (`attack-pattern` SDO):**

| okf-sec | STIX 2.1 |
|---|---|
| `type` | `attack-pattern` |
| `name`, `description`, `aliases` | same |
| `mitre_id`, `capec`, `refs[*]` | `external_references` (`source_name: mitre-attack` / `capec`) |
| `tactics` | `kill_chain_phases[{kill_chain_name: mitre-attack, phase_name}]` |
| `is_subtechnique`, `platforms`, `detection`, `data_sources`, `version` | `x_mitre_*` custom props (ATT&CK's own STIX uses these) |
| `parent_technique`, `used-by`, `mitigated-by`, `detected-by` | SROs (`subtechnique-of`, `uses`, `mitigates`, `detects`) |

**OCSF projection:** ATT&CK is embedded in OCSF events via the `attack` object
(`technique.uid`/`name`, `tactic.uid`/`name`, `version`). The page is the *controlled vocabulary*
that OCSF event records reference — not a standalone OCSF object.

**Enrichment data:** MITRE **ATT&CK**, **D3FEND**, **CAPEC**, OWASP Top 10 mappings.

<details><summary>Full example page</summary>

```markdown
---
type: attack-pattern
name: "PowerShell"
mitre_id: T1059.001
description: "Adversaries abuse PowerShell for execution of commands, scripts, and in-memory
  payloads, often to evade disk-based detection."
is_subtechnique: true
parent_technique: T1059
tactics: [execution]
platforms: [windows]
detection: "Monitor for powershell.exe spawning with encoded commands; script-block logging
  (4104); unusual parent processes."
capec: [CAPEC-242]
created: 2026-06-16
updated: 2026-06-16
refs:
  - {std: mitre-attack, id: "T1059.001", url: "https://attack.mitre.org/techniques/T1059/001/"}
  - {std: capec, id: "CAPEC-242"}
rels:
  used-by: ["[[entities/threat-actor/apt29]]", "[[entities/malware/empire]]"]
  detected-by: ["[[entities/detection/sigma-encoded-powershell]]"]
tags: [lolbin, execution, windows]
---

## Procedure examples
…how specific actors/malware use it ([[wikilinks]])…
```
</details>

---

## 5. Type: `threat-actor`

> A named adversary. STIX splits the *human/organization* (`threat-actor` SDO) from the *named
> intrusion cluster* (`intrusion-set` SDO), and **okf-sec carries both as first-class types** (§8).
> **Default: `intrusion-set`** — any named adversary *group* (APT, ransomware crew, syndicate;
> e.g. APT29, LockBit, Evil Corp) is an intrusion-set; that is where the bulk of named adversaries
> live and what an actor query must span. Reserve **`threat-actor`** for a named *individual* human
> operator (rare in open intel) — a crew/gang is a group, hence an intrusion-set, NOT a
> threat-actor. Both kinds browse together under the "Threat actors" `display_group`
> (`schema.yaml`), so a *search* for actors must not filter to a single type. The `stix.type` is an **escape
> hatch** — a page typed one way that should project as the other sets it explicitly.

**Identity:** `name` (the alias-soup canonical name). No global ID standard; ATT&CK Group id
(`Gxxxx`) attaches as a ref when present.

| Field | Tier | Notes / projection |
|---|---|---|
| `name` | R | canonical name ("APT29") → STIX `name` |
| `aliases` | R | the soup: `["Cozy Bear","Midnight Blizzard","Nobelium"]` → `aliases` |
| `description` | ★ | → STIX `description` |
| `actor_class` | ★ | `nation-state\|crime-syndicate\|hacktivist\|insider\|commodity` → drives `stix.type` + `threat_actor_types` |
| `attribution` | ★ | `{country: RU, sponsor: "SVR", confidence: high}` (suspected origin) |
| `first_seen` / `last_seen` / `active` | ★ | → STIX `first_seen`/`last_seen` |
| `motivation` | ★ | `{primary: organizational-gain, secondary: [espionage]}` → STIX `primary_motivation` / `secondary_motivations` (open-vocab) |
| `sophistication` | | STIX open-vocab (`minimal`…`strategic`) |
| `resource_level` | | STIX open-vocab (`individual`…`government`) |
| `goals` | | → STIX `goals` |
| `targets` | ★ | `{sectors: [energy, government], regions: [EU], countries: [UA]}` → SRO `targets` (identity/location) |
| `mitre_id` | ★ | `G0016` → `refs[std=mitre-attack]` |
| `rels.uses-technique` | ★ | attack-patterns → SRO `uses` |
| `rels.uses-malware` | ★ | malware/tools → SRO `uses` |
| `rels.attributed-campaigns` | ★ | campaigns → SRO `attributed-to` (reversed) |
| `rels.related-to` | | overlapping/associated groups → SRO `related-to` |

**STIX 2.1 projection — SDO is conditional:**

| okf-sec | STIX `threat-actor` | STIX `intrusion-set` |
|---|---|---|
| `name`, `aliases`, `description` | same | same |
| `actor_class` | `threat_actor_types` (open-vocab) | *(no types field)* |
| `motivation.*` | `primary_motivation`/`secondary_motivations` | same |
| `sophistication`, `resource_level` | both | both |
| `first_seen`/`last_seen` | both | both |
| `attribution.country` | SRO `attributed-to` → `identity`/`location`, or `x_okfsec_attribution` | same |
| `mitre_id`, `refs[*]` | `external_references` | `external_references` |
| `targets`, `uses_*`, `attributed-campaigns` | SROs | SROs |

> **Default SDO rule:** a named adversary *group* (the common case — a named cluster/crew/gang,
> `actor_class ∈ {nation-state, crime-syndicate, hacktivist, commodity}`) → `intrusion-set`; only a
> named *individual* operator/persona → `threat-actor`. `stix.type` overrides.

**OCSF projection:** minimal — OCSF has limited first-class threat-actor modeling; the page feeds
the `actor`/attribution context of finding events. Mostly a STIX/ATT&CK noun.

**Enrichment data:** threat-actor profiles, attribution data, campaign analysis, MISP
threat-actor galaxy.

<details><summary>Full example page</summary>

```markdown
---
type: threat-actor
name: "APT29"
aliases: ["Cozy Bear", "Midnight Blizzard", "Nobelium", "The Dukes"]
description: "Russian SVR-attributed cyber-espionage group targeting government, diplomatic,
  and tech sectors; known for stealthy, long-dwell intrusions and supply-chain operations."
actor_class: nation-state
attribution: {country: RU, sponsor: "SVR", confidence: high}
first_seen: 2008-01-01
active: true
motivation: {primary: organizational-gain, secondary: [espionage]}
sophistication: strategic
resource_level: government
targets: {sectors: [government, defense, technology], regions: [NA, EU], countries: [US, UA]}
mitre_id: G0016
created: 2026-06-16
updated: 2026-06-16
stix: {type: intrusion-set}
refs:
  - {std: mitre-attack, id: "G0016", url: "https://attack.mitre.org/groups/G0016/"}
rels:
  uses-technique: ["[[entities/attack-pattern/t1059-001-powershell]]"]
  uses-malware: ["[[entities/malware/wellmess]]"]
  attributed-campaigns: ["[[entities/campaign/sunburst-solarwinds]]"]
sources: ["[[sources/2026/06/2026-06-10-mandiant-apt29-update]]"]
tags: [russia, svr, espionage, apt]
---

## Recent activity
…append-only sightings…
```
</details>

---

## 6. Relationship vocabulary (`rels`)

The `rels:` block is the graph — and the graph is the product (adversary topology, attribution
chains, kill-chain coverage all fall out of traversing it). To stay traversable *and*
projectable, the predicate set is a **controlled vocabulary**, not free text.

**Core property:** a canonical okf-sec predicate string **is** its STIX 2.1 `relationship_type`
(both hyphenated). `rels.uses` → a STIX `relationship` with `relationship_type: "uses"`,
mechanically. Reverse aliases (§6.2) and okf-native predicates (§6.3) are the only exceptions.
Note STIX `relationship_type` is an **open vocabulary**, so projection guarantees *valid* STIX, not
membership in STIX's *suggested* per-SDO relationship set: okf-native predicates (`detects`/`affects`
→ `x_okfsec_*`) and some canonical predicates are valid STIX without being STIX-standard semantics.

**Value forms.** Each predicate takes a list; an entry is either a bare wikilink or an object
carrying *edge* metadata (which projects to SRO properties):

```yaml
rels:
  uses:
    - "[[entities/attack-pattern/t1059-001-powershell]]"
    - {target: "[[entities/malware/wellmess]]", confidence: high, first_seen: 2020-04-01, description: "loader stage"}
```
Edge keys → STIX SRO: `confidence`→`confidence`, `first_seen`/`last_seen`→`start_time`/`stop_time`,
`description`→`description`.

### 6.1 Canonical predicates (subject = the page)

| predicate (= STIX `relationship_type`) | typical subject → object | meaning |
|---|---|---|
| `uses` | actor/intrusion-set/campaign/malware → attack-pattern/malware/tool/infrastructure | wields a capability (sugar: `uses-technique`/`uses-malware`/`uses-tool` → fold to `uses`) |
| `targets` | actor/intrusion-set/campaign/malware/attack-pattern → identity/vulnerability/location | victimology |
| `attributed-to` | campaign/intrusion-set → threat-actor/intrusion-set | attribution edge |
| `authored-by` | malware/tool → threat-actor/identity | who built it |
| `owns` | identity → infrastructure | ownership (usually authored reverse as `owned-by`) |
| `compromises` | actor/intrusion-set/campaign → infrastructure | took over victim asset |
| `exploits` | malware/tool → vulnerability | weaponizes a vuln |
| `delivers` | malware → malware | delivery of a payload |
| `downloads` / `drops` | malware → malware/tool | staged retrieval / write |
| `variant-of` | malware → malware | family lineage |
| `communicates-with` | malware/infrastructure → infrastructure/indicator | C2 channel — **infra topology** |
| `beacons-to` | malware → infrastructure | callback — **infra topology** |
| `exfiltrates-to` | malware → infrastructure | data egress — **infra topology** |
| `controls` | infrastructure/malware → infrastructure/malware | operator control — **infra topology** |
| `consists-of` | infrastructure → infrastructure | composition — **infra topology** |
| `hosts` | infrastructure → malware/tool/infrastructure | serves content — **infra topology** |
| `resolves-to` | indicator (domain/url) → indicator (ip) | DNS resolution (SCO-level) |
| `indicates` | indicator → attack-pattern/campaign/intrusion-set/malware/threat-actor/tool/infrastructure | what the IOC points to |
| `mitigates` | course-of-action → attack-pattern/malware/tool/vulnerability/indicator | defensive countermeasure |
| `subtechnique-of` | attack-pattern → attack-pattern | ATT&CK parent/child |
| `originates-from` | actor/malware/campaign/attack-pattern → location | suspected origin |
| `located-at` | identity/infrastructure/threat-actor → location | geolocation |
| `related-to` | any → any | **last resort** — only when no precise predicate fits |

The seven predicates tagged **infra topology** are the adversary-infrastructure topology layer
(see the `infrastructure` note in §8): traverse them to render the C2/hosting map.

### 6.2 Reverse aliases (subject = the *object* page; projector flips to canonical)

Author from whichever page is natural; the projector emits one SRO in canonical STIX direction.

| reverse alias | normalizes to |  | reverse alias | normalizes to |
|---|---|---|---|---|
| `used-by` | `uses` | | `owned-by` | `owns` |
| `exploited-by` | `exploits` | | `hosted-by` | `hosts` |
| `mitigated-by` | `mitigates` | | `affected-by` | `affects` |
| `detected-by` | `detects` | | `attributed-campaigns` | `attributed-to` |

### 6.3 okf-native predicates (no STIX SRO)

| predicate | subject → object | projection |
|---|---|---|
| `detects` | detection → attack-pattern/malware | detection is not a STIX SDO → map detection to an `indicator` + `indicates`, else `x_okfsec_detects` |
| `affects` | vulnerability → software | CVE→CPE has no native STIX SRO → `x_okfsec_affects` (or `related-to`) |

### 6.4 Rules

- **Prefer the most specific canonical predicate.** `related-to` is the fallback of last resort;
  a vault full of `related-to` is an ungraph.
- **Typed sugar folds to its base** on projection (`uses-malware` → `uses`).
- **Unknown predicate = flag, not reject.** An unrecognized predicate still lands; it projects to
  `x_okfsec_<predicate>` and stamps `needs_review`, so the vocabulary grows deliberately, never by
  silent drift.
- **One SRO per target.** A predicate with N targets emits N SROs.

---

## 7. The projection contract

A *projector* turns a page (or a vault subgraph) into a standard's objects. The contract:

1. **Entity pages → STIX 2.1 SDOs + SROs.**
   - Frontmatter scalar fields → SDO properties (tables above).
   - `refs[*]` → `external_references`.
   - `rels.<predicate>` → one SRO per target, predicate → STIX relationship type
     (`uses`, `targets`, `exploits`, `attributed-to`, `mitigates`, `detects`, `subtechnique-of`,
     `variant-of`, `related-to`). Reversed predicates (`exploited-by`, `used-by`) emit the SRO in
     canonical STIX direction.
   - Non-STIX fields (CVSS, EPSS, KEV, ATT&CK `x_mitre_*`) → `extensions` / `x_okfsec_*`. **Every
     such field is documented loss** — a STIX-only consumer drops it; a STIX-2.1+extensions
     consumer keeps it.
   - **okf-native types** (`software`, `detection`, `concept`, `finding`, `prediction`, `dashboard`)
     have no STIX SDO. In v0.1 they project to valid **`x-okfsec-<type>` custom objects** (lossy-but-
     valid: a strict consumer ignores unknown types, an extension-aware one keeps them). v0.2 refines
     the obvious ones — `software`→STIX `software` SCO, `concept`→`grouping`, `finding`/`detection`→OCSF.
2. **Event/finding records → OCSF Detection Finding (class 2004).** `finding` and `detection` project
   via `projectors/ocsf.py`: severity/status/confidence map to the OCSF ids, the page identity →
   `finding_info`, and fields with no OCSF home ride the `unmapped` object (documented loss).
   Conformance-tested against the official `py-ocsf-models` (`conformance/run_ocsf_conformance.py`).
   *(Normative in v0.2 — §0.)* Entity pages are *not* projected to OCSF.
3. **Validation = the proof.** A page "supports STIX" only if `project_stix(page)` passes a STIX 2.1
   validator. The reference projector (`projectors/stix.py`) + conformance suite (`conformance/`) do
   exactly this: **all 18 okf-sec types → STIX → pass the official OASIS `stix2` validator**
   (CI-enforced), with the documented-loss set asserted to equal exactly the `x_okfsec_*` properties.
   No projector test ⇒ the support claim is unverified.
4. **TLP is marked on projection — not enforced.** The projector stamps the page's `tlp` as a STIX
   `object_marking_ref`; *honoring* it — withholding or redacting `amber`/`red` per a consumer's
   clearance — is the **consumer's** responsibility. okf-sec defines the marking, not a clearance/
   redaction engine. *Limitation:* `amber+strict` currently maps to the STIX `amber` marking (TLP 2.0
   amber-strict has no STIX-2.1-predefined marking id); the distinction is kept in the page's `tlp`
   field but not in the STIX marking.

---

## 8. Full type roster

Canonical name = STIX 2.1 SDO where one exists; legacy/vault names are accepted as **aliases**
(normalized on read; see `schema.yaml` `type_aliases`). The generic vault type `entity` is
**deprecated** — it must be retyped, never aliased. `R` = required (flag-not-gate); `★` = recommended.

| okf-sec (canonical) | aliases | STIX SDO | required (R) | identity / key fields |
|---|---|---|---|---|
| `source` | — | `report` | type, source_kind, publisher, published, reliability, credibility | provenance; `refs`→object_refs |
| `vulnerability` | `cve` | vulnerability | type | `cve_id`★ (nullable), cvss, kev, affected, cwe |
| `attack-pattern` | `technique` | attack-pattern | type, `mitre_id` | tactics, platforms, detection |
| `threat-actor` | — | threat-actor | type | persona; actor_class, motivation, attribution |
| `intrusion-set` | `group`, `apt-group` | intrusion-set | type | named cluster (APT29); `mitre_id` G, aliases |
| `malware` | `ransomware`, `ransomware-family` | malware | type | `category`★ (ransomware/loader/rat…), is_family |
| `tool` | — | tool | type | dual-use/offensive tooling actors wield |
| `software` | `product` | *(none → x_)* | type | `cpe`★, vendor, affected-by (vulns) |
| `campaign` | — | campaign | type | `first_seen`/`last_seen`, objective, attributed-to |
| `incident` | — | incident | type | breach/attack **event**; `incident_type`★, `sector`, `affected_count`, `date_disclosed`, vector; `actor`→intrusion-set |
| `indicator` | `ioc` | indicator | type, `ioc_type`, `value` | **named indicators only** (§ note) |
| `infrastructure` | `host` | infrastructure | type | `infra_type` (asn/ip-block/c2/server), asn, cidr |
| `identity` | `vendor`,`organization`,`company`,`person`,`agency`,`government-agency`,`team` | identity | type, `identity_class` | `identity_class` (individual/group/organization/class), `sector` |
| `course-of-action` | `mitigation` | course-of-action | type | `mitre_id` M; defends `attack-pattern` |
| `detection` | — | *(none → okf-native)* | type, `rule_format` | sigma/yara/suricata; detects `attack-pattern`/`malware` |
| `concept` | — | *(grouping; no SDO)* | type | cross-cutting pattern/segment grouping |
| `finding` | — | *(OCSF finding layer)* | type, severity, status | **human-authored** (permissions.findings); `severity` required is an okpack-sec tightening vs the base `[type, status]` (§10.6) |
| `prediction` | — | *(none — okf-native)* | type, status, confidence, subject, resolves_by | falsifiable dated forward claim |
| `dashboard` | — | *(none — okf-native)* | type, title | curated query/view page |

**Per-type projection notes (beyond the three exemplars):**

- **`source` → STIX `report`.** A source page that links the entities it discusses *is* a STIX
  report: `refs`/body wikilinks → `object_refs`; `published` → `published`; Admiralty
  `reliability`/`credibility` → `confidence` + `x_okfsec_admiralty`. This makes provenance
  first-class in STIX, not lost.
- **`malware` / `tool` → STIX `malware` / `tool`.** `category` → `malware_types`/`tool_types`
  (open-vocab); `is_family` → `is_family`; `rels.uses`→ SROs; `rels.targets`→ vulnerabilities/identities.
- **`software` → no SDO.** Emit as `x_okfsec_software` with `cpe`; relationships to `vulnerability`
  (`has`/`affected-by`) still project as SROs against the vuln SDO.
- **`campaign` → STIX `campaign`.** `attributed-to`→ SRO to `intrusion-set`/`threat-actor`;
  `uses`→ malware/attack-pattern; `exploits`→ vulnerability.
- **`incident` → STIX `incident`.** STIX 2.1 ships `incident` as a **stub SDO** (core properties
  only, meant for extension), so okf-sec fields project as `x_okfsec_*` extension properties
  (`incident_type`, `affected_count`, `data_exposed`, `sector`, `date_disclosed`); `actor`→ SRO
  `attributed-to` (`intrusion-set`/`threat-actor`), `targets`→ SRO to `identity`/`location`,
  `exploits`→ vulnerability. An `incident` is a discrete dated **event** — distinct from `campaign`
  (a sustained named operation) and `finding` (analyst output).
- **`indicator` → STIX `indicator`.** `value`+`ioc_type` → a STIX **pattern**
  (`[ipv4-addr:value = '1.2.3.4']`); `valid_from` ← `first_seen`. **Inline-by-default rule:** bulk
  IOCs stay listed on the `source`/`campaign` page; only campaign-anchoring / reused-infrastructure
  indicators get their own page (and thus their own STIX SDO). Avoids the 30k-indicator noise floor.
- **`infrastructure` → STIX `infrastructure`.** Adversary assets: C2, staging servers, malicious
  IP blocks, hosting/bulletproof ASNs. **Named fields:** `infra_type` (asn|ip-block|c2|server|
  domain-front), `asn`, `cidr`/`ip_range`, `owner`, `hosting_provider`, `country`,
  `first_seen`/`last_seen`. **Projection:** `infra_type` → `infrastructure_types`; `asn`/`cidr` →
  `x_okfsec_*` (real okf-sec fields — STIX's `infrastructure` SDO has no native slot, so they ride
  an extension, not dropped); `owner`/`hosting_provider` → `rels.owned-by` → `identity`;
  `rels.communicates-with`/`consists-of`/`hosts` → infra/indicator topology SROs.
  **Enrichment** = ownership/attribution (whois/RDAP, PeeringDB, IANA — *who owns/announces this block*).
  **Static identifier (ASN/CIDR) is in; routing dynamics are out:** BGP/AS-level connectivity and
  routing-security telemetry (hijack/route-leak/RPKI validation) is a distinct **network-topology**
  domain at the *event* altitude — a sibling profile or the finding/detection layer, not this CTI
  entity taxonomy.
- **`identity` → STIX `identity`.** `identity_class` → `identity_class`; `sector` → `sectors`
  (open-vocab). This is the consolidation of the vault's `vendor`/`organization`/`person` sprawl.
- **`course-of-action` → STIX `course-of-action`.** `mitre_id` (Mxxxx) → external ref;
  `rels.mitigates` → SRO to `attack-pattern`.
- **`detection` → no STIX SDO.** okf-native; the rule body stays verbatim; `rels.detects` links
  `attack-pattern`/`malware`. Projects to **OCSF** detection/finding context, not a STIX entity.
- **`concept`/`prediction`/`dashboard` → okf-native.** No standard projection; `concept` *may*
  emit a STIX `grouping` if a consumer wants the cluster. These are the AI-agent reasoning layer.

---

### 8.1 Worked examples (additional types)

The three exemplars (§3–5) cover the deepest types; these seven cover every remaining *distinct
structural pattern* (the rest — `tool`, `software`, `course-of-action`, `concept`, `finding`,
`prediction`, `dashboard` — follow these by analogy). They interlink deliberately (one APT29 /
SUNBURST graph) to show the relationship vocabulary in use.

<details><summary><code>source</code> — provenance, Admiralty-scored → STIX <code>report</code></summary>

```markdown
---
type: source
name: "Mandiant — APT29 supply-chain update (2026-06-10)"
source_kind: vendor-research
publisher: "Mandiant (Google Cloud)"
published: 2026-06-10
url: "https://www.mandiant.com/resources/blog/apt29-supply-chain-update"
raw: raw/2026/06/2026-06-10-mandiant-apt29.html      # dedupe key
reliability: A          # first-party vendor lab on own telemetry
credibility: 2          # probably true
tlp: clear
bias_flags: [vendor-commercial]
rels:
  related-to: ["[[entities/threat-actor/apt29]]", "[[entities/campaign/sunburst-solarwinds]]"]
tags: [apt29, supply-chain, russia]
---

## Summary
What's new vs. known: APT29 rotated C2 onto a new bulletproof ASN…

## Entities extracted
- [[entities/threat-actor/apt29]] — new infrastructure
- [[entities/infrastructure/as65535-bulletproof]]
```
→ STIX `report`: `published`→`published`; `rels`/body wikilinks → `object_refs`;
`reliability`+`credibility` → `confidence` + `x_okfsec_admiralty`.
</details>

<details><summary><code>indicator</code> — named, campaign-anchoring → STIX <code>indicator</code></summary>

```markdown
---
type: indicator
name: "APT29 C2 — telemetry-fronting domain"
ioc_type: domain
value: "cdn-telemetry[.]example"      # DEFANGED on the page
confidence: high
tlp: amber
first_seen: 2026-05-02
last_seen: 2026-06-08
rels:
  indicates: ["[[entities/campaign/sunburst-solarwinds]]"]
  resolves-to: ["[[entities/indicator/198-51-100-44]]"]
  communicates-with: ["[[entities/infrastructure/as65535-bulletproof]]"]
tags: [c2, apt29]
---

Gets its own page because it anchors a campaign / reused infrastructure. Bulk IOCs stay
listed inline on the source or campaign page (spec §1, §8).
```
→ STIX `indicator`: `value`+`ioc_type` → pattern `[domain-name:value = 'cdn-telemetry.example']`
(the projector **un-defangs**); `first_seen`→`valid_from`; `tlp: amber`→ marking-definition.
</details>

<details><summary><code>identity</code> — the vendor/org/person consolidation → STIX <code>identity</code></summary>

```markdown
---
type: identity
name: "SolarWinds"
identity_class: organization
sector: [technology]
aliases: ["SolarWinds Worldwide LLC"]
description: "US IT-management software vendor; supply-chain vector in the SUNBURST campaign."
rels:
  owns: ["[[entities/software/solarwinds-orion]]"]
tags: [vendor, supply-chain-victim]
---
```
→ STIX `identity`: `identity_class`→`identity_class`; `sector`→`sectors`. One type replaces the
vault's `vendor`/`organization`/`person`/`agency` sprawl — the kind lives in `identity_class`.
</details>

<details><summary><code>infrastructure</code> — adversary asset, ASN/CIDR static → STIX <code>infrastructure</code></summary>

```markdown
---
type: infrastructure
name: "Bulletproof host — AS65535"
infra_type: asn
asn: "AS65535"                 # static identifier (in scope)
cidr: "198.51.100.0/24"        # RFC 5737 example range
owner: "Offshore Hosting Ltd"
country: NL
first_seen: 2025-11-01
rels:
  hosts: ["[[entities/malware/wellmess]]"]
  owned-by: ["[[entities/identity/offshore-hosting-ltd]]"]
tags: [bulletproof, c2-hosting]
---
```
→ STIX `infrastructure`: `infra_type`→`infrastructure_types`; `asn`/`cidr`→`x_okfsec_*`;
`owned-by`→`owns` SRO (from the identity). BGP routing *dynamics* stay out (network-topology domain).
</details>

<details><summary><code>malware</code> — family, category + lineage → STIX <code>malware</code></summary>

```markdown
---
type: malware
name: "WellMess"
category: remote-access-trojan        # kind = field, not a `rat` type
is_family: true
first_seen: 2018-07-01
description: "Cross-platform (Go/.NET) RAT used by APT29 for command execution and file transfer over HTTP/DNS."
refs:
  - {std: mitre-attack, id: "S0514", url: "https://attack.mitre.org/software/S0514/"}
rels:
  uses: ["[[entities/attack-pattern/t1071-001-web-protocols]]"]
  variant-of: ["[[entities/malware/wellmail]]"]
  authored-by: ["[[entities/threat-actor/apt29]]"]
tags: [rat, go, apt29]
---
```
→ STIX `malware`: `category`→`malware_types`; `is_family`→`is_family`; `refs`→`external_references`;
`uses`/`variant-of`/`authored-by`→ SROs.
</details>

<details><summary><code>campaign</code> — attribution chain → STIX <code>campaign</code></summary>

```markdown
---
type: campaign
name: "SUNBURST / SolarWinds supply-chain"
aliases: ["UNC2452 campaign"]
first_seen: 2020-03-01
last_seen: 2020-12-01
description: "Trojanized SolarWinds Orion updates delivered SUNBURST to ~18,000 orgs; selective follow-on intrusions."
rels:
  attributed-to: ["[[entities/threat-actor/apt29]]"]
  uses: ["[[entities/malware/sunburst]]"]
  exploits: ["[[entities/vulnerability/cve-2020-10148]]"]
  targets: ["[[entities/identity/solarwinds]]"]
tags: [supply-chain, espionage]
---
```
→ STIX `campaign`: `first_seen`/`last_seen` map directly; `attributed-to`→ SRO to
`intrusion-set`/`threat-actor`; `uses`/`exploits`/`targets`→ SROs.
</details>

<details><summary><code>detection</code> — okf-native, embeds a rule → no STIX SDO</summary>

```markdown
---
type: detection
name: "Sigma — encoded PowerShell with anomalous parent"
rule_format: sigma
confidence: medium
rels:
  detects: ["[[entities/attack-pattern/t1059-001-powershell]]"]
tags: [sigma, powershell, execution]
---

## Rule
​```yaml
title: Encoded PowerShell via anomalous parent
logsource: {product: windows, category: process_creation}
detection:
  sel: {Image|endswith: '\powershell.exe', CommandLine|contains: ' -enc '}
  condition: sel
​```
```
No STIX SDO (detection isn't one): the rule body stays verbatim; `detects` projects to
`x_okfsec_detects` (or, if mapped to an `indicator`, `indicates`). OCSF detection/finding mapping
is v0.2 (§0).
</details>

---

## 9. Field dictionary (normative)

Every **envelope** field (§9.1), the commonly-used **type-specific** fields (§9.1a), every **enum**
(§9.2), and the **compound shapes** (§9.3) are defined here; remaining type-specific fields are
defined in their type sections (§3–5) and roster (§8). `rels` is defined in §6. Entry format —
**`field`** — *type* · tier · `allowed/format` — meaning → projection.
Tiers: **R** required · **★** recommended · *opt* optional · *sys* system-set (don't author).
Flag-not-gate applies: a missing **R** field flags `needs_review`, never rejects.

### 9.1 Envelope fields (any type)

- **`type`** — enum · R · a §8 canonical type or a `type_aliases` key (normalized to canonical) — the page's kind → STIX SDO type.
- **`name`** — string · ★ · free text — human display name / natural-language identity; projection falls back to the page slug if absent → STIX `name`.
- **`aliases`** — list[string] · opt — other names / a.k.a.s → STIX `aliases`.
- **`description`** — string (markdown) · ★ — one-paragraph what/why → STIX `description`.
- **`title`** — string · opt — display title for non-entity pages (`dashboard`) → n/a.
- **`created`** — date `YYYY-MM-DD` · ★ — first authored → STIX `created`.
- **`updated`** — date · ★ — last substantive edit; drives hot/warm/cold tier → STIX `modified`.
- **`first_seen`** — date · opt — earliest real-world observation of the thing → STIX `first_seen` (SDOs that support it).
- **`last_seen`** — date · opt — most recent observation → STIX `last_seen`.
- **`confidence`** — number `0.0–1.0` *or* enum `low|medium|high` · ★ — analyst confidence in the page's core claim; never flags → STIX `confidence` (numeric×100; low=15/medium=50/high=85).
- **`tlp`** — enum · ★ · §9.2 — sharing restriction; *marked* (not enforced) on projection (§7.4) → STIX TLP `marking-definition`.
- **`sources`** — list[wikilink→`sources/…`] · ★ — provenance pages this derives from → feeds STIX `report.object_refs` from the source side.
- **`related`** — list[wikilink] · opt — loose see-also not worth a typed predicate → optional `related-to` SRO.
- **`tags`** — list[kebab-case] · opt — free labels → STIX `labels`.
- **`refs`** — list[object] · ★ · §9.4 — cross-standard identifiers → STIX `external_references`.
- **`stix`** — object · opt · §9.4 — projection hints/overrides → controls SDO type/id.
- **`rels`** — object · ★ · §6 — typed relationship graph → STIX SROs.
- **`needs_review`** — bool · *sys* — set by the write-gate (§9.2 review verdicts / missing-R / severity disagreement); not authored → not projected.
- **`status`** — enum · *(type-specific)* · §9.2 — lifecycle state for `prediction`/`finding`; plus engine `tombstoned` on any tombstoned page → not projected (engine lifecycle).
- **`superseded_by`** — wikilink · opt — on a tombstoned page, the page that replaces it → not projected.

### 9.1a Selected type-specific fields

Defined here because they recur across examples/roster; other type-specific fields live in the type
sections (§3–5) and compound schemas (§9.3).

- **`publisher`** — string · R(source) — the source's publishing org/channel → `x_okfsec_publisher`.
- **`url`** — url · ★(source) — canonical link to the source → `report.external_references[].url`.
- **`raw`** — path · ★(source) — exact raw-capture path; the ingest **dedupe key** → not projected.
- **`objective`** — string · opt(campaign) — the campaign's goal (e.g. espionage) → `x_okfsec_objective`.
- **`active`** — bool · opt(threat-actor/intrusion-set) — whether the actor is currently operating → `x_okfsec_active`.
- **`subject`** — wikilink · R(prediction) — the entity the prediction is about → `x_okfsec_subject`.
- **`resolves_by`** — date · R(prediction) — when the prediction resolves → `x_okfsec_resolves_by`.
- **`made_on`** — date · ★(prediction) — when filed; with `resolves_by` derives `horizon` → `x_okfsec_made_on`.

### 9.2 Controlled enumerations (closed unless marked *extensible*)

- **`tlp`**: `clear` · `green` · `amber` · `amber+strict` · `red`  (TLP 2.0).
- **`severity`**: `none` · `low` · `medium` · `high` · `critical`. Derivation: highest `cvss[].base_score` band (none=0, low<4, medium<7, high<9, critical≥9) unless analyst-set; on disagreement the page is flagged (§10, decision 5).
- **`confidence`** (categorical): `low` · `medium` · `high`  (or numeric `0.0–1.0`).
- **review verdicts** (asserting one stamps `needs_review`, G3): `confirmed` · `false-positive` · `refuted`.
- **`reliability`** (source, Admiralty — publisher/channel): `A` first-party gov/CERT or vendor lab on own telemetry · `B` established research blog · `C` reputable news · `D` single-analyst/unverified · `E` doubtful · `F` cannot judge.
- **`credibility`** (source, Admiralty — this report's claims): `1` confirmed by multiple independent · `2` probably true · `3` plausible/single-source · `4` doubtful · `5` improbable · `6` cannot judge.
- **`source_kind`**: `advisory` · `vendor-research` · `incident-report` · `news` · `blog`.
- **`bias_flags`** (*extensible*): `vendor-commercial` · `single-witness` · `attribution-speculative` · `sensationalized` · `state-aligned`.
- **`ioc_type`** (indicator): `ip` · `domain` · `hash` · `url` · `email`  (*extensible* to other STIX SCO types: `file` · `mutex` · `registry-key` · `user-agent`).
- **`infra_type`** (infrastructure → STIX `infrastructure_types`): `asn` · `ip-block` · `c2`(command-and-control) · `server` · `domain-front` · `botnet` · `hosting-malware` · `phishing` · `staging` · `exfiltration` · `anonymization`(proxy/vpn/tor) · `reconnaissance` · `undefined`.
- **`identity_class`** (identity → STIX `identity_class`): `individual` · `group` · `organization` · `system` · `class` · `unknown`.
- **`sector`** (identity/targets → STIX `industry-sector`, *extensible*): `agriculture` · `aerospace` · `automotive` · `chemical` · `commercial` · `communications` · `construction` · `defense` · `education` · `energy` · `entertainment` · `financial-services` · `government` · `healthcare` · `hospitality-leisure` · `infrastructure` · `insurance` · `manufacturing` · `mining` · `non-profit` · `pharmaceuticals` · `retail` · `technology` · `telecommunications` · `transportation` · `utilities`.
- **`actor_class`** (threat-actor → STIX `threat_actor_types`): `nation-state` · `crime-syndicate` · `criminal` · `hacker` · `activist`(hacktivist) · `insider-accidental` · `insider-disgruntled` · `competitor` · `spy` · `terrorist` · `sensationalist` · `unknown`.
- **`sophistication`** (threat-actor → STIX): `none` · `minimal` · `intermediate` · `advanced` · `expert` · `innovator` · `strategic`.
- **`resource_level`** (threat-actor → STIX): `individual` · `club` · `contest` · `team` · `organization` · `government`.
- **`motivation`** (threat-actor primary/secondary → STIX `attack-motivation`): `accidental` · `coercion` · `dominance` · `ideology` · `notoriety` · `organizational-gain` · `personal-gain` · `personal-satisfaction` · `revenge` · `unpredictable`.
- **`category`** (malware → STIX `malware_types`): `adware` · `backdoor` · `bootkit` · `bot` · `ddos` · `downloader` · `dropper` · `exploit-kit` · `keylogger` · `ransomware` · `remote-access-trojan` · `resource-exploitation` · `rogue-security-software` · `rootkit` · `screen-capture` · `spyware` · `trojan` · `virus` · `webshell` · `wiper` · `worm` · `unknown`.
- **`category`** (tool → STIX `tool_types`): `denial-of-service` · `exploitation` · `information-gathering` · `network-capture` · `credential-exploitation` · `remote-access` · `vulnerability-scanning` · `unknown`.
- **`rule_format`** (detection, *extensible*): `sigma` · `yara` · `yara-l` · `suricata` · `snort` · `kql` · `spl` · `eql` · `osquery`.
- **`exploitation.status`** (vulnerability): `unreported` · `poc` · `active` · `weaponized`.
- **`status`** (prediction): `open` · `confirmed` · `refuted` · `partial` · `expired-ungraded`.
- **`status`** (finding): `open` · `investigating` · `confirmed` · `resolved` · `dismissed`.
- **`horizon`** (prediction, derived from `resolves_by − made_on`): `short` ≤90d · `medium` ≤365d · `long` ≤1825d · `strategic` >1825d.

### 9.3 Compound-field schemas

- **`cvss`** — list of `{version: "2.0"|"3.0"|"3.1"|"4.0", base_score: 0.0–10.0, vector: <CVSS vector string>, severity: <severity>}`.
- **`epss`** — `{score: 0.0–1.0, percentile: 0.0–1.0, date: <date>}`.
- **`exploitation`** — `{status: <exploitation.status>, kev: bool, kev_date: <date>?, ransomware_use: bool?}`.
- **`affected`** — list of `{vendor: str, product: str, cpe: "cpe:2.3:…"?, versions: <range expr>}`.
- **`patched`** — `{available: bool, date: <date>?, fixed_versions: [str]?}`.
- **`attribution`** (threat-actor) — `{country: <ISO 3166-1 alpha-2>?, sponsor: str?, confidence: <confidence>}`.
- **`motivation`** (threat-actor) — `{primary: <motivation>, secondary: [<motivation>]?}`.
- **`targets`** (threat-actor/campaign) — `{sectors: [<sector>]?, regions: [str]?, countries: [<ISO2>]?}`.
- **infra identity** (infrastructure) — `asn: "AS####"` · `cidr`/`ip_range: <CIDR>` · `owner: str` · `hosting_provider: str` · `country: <ISO2>`.
- **`cpe`** (software) — string, CPE 2.3 URI (`cpe:2.3:a:vendor:product:version:…`).

### 9.4 `refs[]` and `stix` blocks

- **`refs[]`** — `{std: <ref-std>, id: str?, url: <url>?}` — at least one of `id`/`url` required. **`std` vocabulary** (→ STIX `external_references.source_name`): `cve` · `cwe` · `capec` · `mitre-attack` · `mitre-d3fend` · `nvd` · `ghsa` · `cpe` · `cisa-kev` · `epss` · `misp` · `stix` · `vendor-advisory` · `url` (*extensible*).
- **`stix`** — `{type: <STIX SDO name>?, id: "<sdo>--<uuid>"?}` — override the projected SDO (e.g. `intrusion-set`) and/or pin a stable STIX id across exports.
- **convenience mirrors**: top-level `cve_id` / `mitre_id` MAY duplicate the primary `refs` entry of that standard for search ergonomics; `refs` is authoritative.

---

### 9.5 Machine reference (generated — mirrors `schema.yaml`)

The authoritative value lists, **generated from `schema.yaml` and drift-checked in CI**:
`validate.py` fails if this block is stale, and `python3 validate.py --fix` regenerates it. So the
spelled-out enums can never silently diverge from what the validator/write-gate enforce. The §9.2
prose is the *annotated human reference*; this block is the machine-checked source of truth for the
*values* (and `schema.yaml` itself is the ultimate SoT).

<!-- BEGIN GENERATED okf-sec machine reference (do not edit — `python3 validate.py --fix`) -->

**okf-sec version** — `0.2`

**Canonical types** — `source` · `vulnerability` · `attack-pattern` · `threat-actor` · `intrusion-set` · `malware` · `tool` · `software` · `campaign` · `incident` · `indicator` · `infrastructure` · `identity` · `course-of-action` · `detection` · `concept` · `finding` · `prediction` · `dashboard`

**Type aliases** — `cve`→`vulnerability` · `technique`→`attack-pattern` · `ioc`→`indicator` · `host`→`infrastructure` · `product`→`software` · `group`→`intrusion-set` · `apt-group`→`intrusion-set` · `mitigation`→`course-of-action` · `ransomware`→`malware` · `ransomware-family`→`malware` · `vendor`→`identity` · `organization`→`identity` · `company`→`identity` · `person`→`identity` · `agency`→`identity` · `government-agency`→`identity` · `government-entity`→`identity` · `team`→`identity`

**Enumerations** (*extensible* marked at the binding below)
- `tlp`: `clear` · `green` · `amber` · `amber+strict` · `red`
- `severity`: `none` · `low` · `medium` · `high` · `critical`
- `reliability`: `A` · `B` · `C` · `D` · `E` · `F`
- `credibility`: `1` · `2` · `3` · `4` · `5` · `6`
- `source_kind`: `advisory` · `vendor-research` · `incident-report` · `news` · `blog`
- `bias_flags`: `vendor-commercial` · `single-witness` · `attribution-speculative` · `sensationalized` · `state-aligned`
- `ioc_type`: `ip` · `domain` · `hash` · `url` · `email` · `file` · `mutex` · `registry-key` · `user-agent`
- `infra_type`: `asn` · `ip-block` · `c2` · `server` · `domain-front` · `botnet` · `hosting-malware` · `phishing` · `staging` · `exfiltration` · `anonymization` · `reconnaissance` · `undefined`
- `identity_class`: `individual` · `group` · `organization` · `system` · `class` · `unknown`
- `sector`: `agriculture` · `aerospace` · `automotive` · `chemical` · `commercial` · `communications` · `construction` · `defense` · `education` · `energy` · `entertainment` · `financial-services` · `government` · `healthcare` · `hospitality-leisure` · `infrastructure` · `insurance` · `manufacturing` · `mining` · `non-profit` · `pharmaceuticals` · `retail` · `technology` · `telecommunications` · `transportation` · `utilities`
- `actor_class`: `nation-state` · `crime-syndicate` · `criminal` · `hacker` · `activist` · `insider-accidental` · `insider-disgruntled` · `competitor` · `spy` · `terrorist` · `sensationalist` · `unknown`
- `sophistication`: `none` · `minimal` · `intermediate` · `advanced` · `expert` · `innovator` · `strategic`
- `resource_level`: `individual` · `club` · `contest` · `team` · `organization` · `government`
- `motivation`: `accidental` · `coercion` · `dominance` · `ideology` · `notoriety` · `organizational-gain` · `personal-gain` · `personal-satisfaction` · `revenge` · `unpredictable`
- `malware_category`: `adware` · `backdoor` · `bootkit` · `bot` · `ddos` · `downloader` · `dropper` · `exploit-kit` · `keylogger` · `ransomware` · `remote-access-trojan` · `resource-exploitation` · `rogue-security-software` · `rootkit` · `screen-capture` · `spyware` · `trojan` · `virus` · `webshell` · `wiper` · `worm` · `unknown`
- `tool_category`: `denial-of-service` · `exploitation` · `information-gathering` · `network-capture` · `credential-exploitation` · `remote-access` · `vulnerability-scanning` · `unknown`
- `rule_format`: `sigma` · `yara` · `yara-l` · `suricata` · `snort` · `kql` · `spl` · `eql` · `osquery`
- `exploitation_status`: `unreported` · `poc` · `active` · `weaponized`
- `prediction_status`: `open` · `confirmed` · `refuted` · `partial` · `expired-ungraded`
- `finding_status`: `investigating` · `open` · `confirmed` · `resolved` · `dismissed`
- `incident_type`: `breach` · `data-leak` · `ransomware` · `extortion` · `defacement` · `ddos` · `wiper` · `supply-chain` · `espionage` · `bec` · `fraud` · `account-compromise` · `outage` · `unknown`
- `horizon`: `short` · `medium` · `long` · `strategic`
- `ref_std`: `cve` · `cwe` · `capec` · `mitre-attack` · `mitre-d3fend` · `nvd` · `ghsa` · `cpe` · `cisa-kev` · `epss` · `misp` · `stix` · `vendor-advisory` · `url`
- `cvss_version`: `2.0` · `3.0` · `3.1` · `4.0`

**Field → enum bindings**
- `tlp` → `tlp`
- `severity` → `severity`
- `reliability` → `reliability`
- `credibility` → `credibility`
- `source_kind` → `source_kind`
- `bias_flags` → `bias_flags` *(extensible)*
- `ioc_type` → `ioc_type` *(extensible)*
- `infra_type` → `infra_type`
- `identity_class` → `identity_class`
- `actor_class` → `actor_class`
- `sophistication` → `sophistication`
- `resource_level` → `resource_level`
- `rule_format` → `rule_format` *(extensible)*
- `horizon` → `horizon`
- `exploitation.status` → `exploitation_status`
- `motivation.primary` → `motivation`
- `motivation.secondary` → `motivation`
- `targets.sectors` → `sector` *(extensible)*
- `incident_type` → `incident_type` *(extensible)*
- `status` → `prediction`→`prediction_status`, `finding`→`finding_status`
- `category` → `malware`→`malware_category`, `tool`→`tool_category`

**List-of-object enum bindings**
- `refs[]`: `std`→`ref_std` *(ext)*
- `cvss[]`: `version`→`cvss_version`, `severity`→`severity`

**Relationship predicates** (`rels`)
- canonical: `uses` · `uses-technique` · `uses-malware` · `uses-tool` · `targets` · `attributed-to` · `authored-by` · `owns` · `compromises` · `exploits` · `delivers` · `downloads` · `drops` · `variant-of` · `communicates-with` · `beacons-to` · `exfiltrates-to` · `controls` · `consists-of` · `hosts` · `resolves-to` · `indicates` · `mitigates` · `subtechnique-of` · `originates-from` · `located-at` · `related-to`
- reverse: `used-by` · `exploited-by` · `mitigated-by` · `detected-by` · `owned-by` · `hosted-by` · `affected-by` · `attributed-campaigns`
- okf-native: `detects` · `affects`

<!-- END GENERATED okf-sec machine reference -->

---

## 10. Resolved decisions

1. **Indicators — inline by default.** Bulk IOCs stay on source/campaign pages; only
   named/anchoring indicators get `indicator` pages (and STIX SDOs). *(Decided.)*
2. **`identity` consolidation — yes.** `vendor`/`organization`/`person`/`agency`/`team` fold into
   one `identity` type keyed by `identity_class` + `sector`. Biggest cleanup of vault sprawl. *(Decided.)*
3. **Custom props — `x_okfsec_*`.** Non-standard fields (CVSS, EPSS, KEV, ATT&CK `x_mitre_*`,
   Admiralty, software/infra detail) project to `x_okfsec_*` custom properties. A registered STIX
   extension-definition is a later hardening step if a consumer needs strict 2.1. *(Decided.)*
4. **Projector home — the engine.** `project_stix` / `project_ocsf` live in `okengine`
   (domain-general machinery, reusable across packs); okf-sec is the first profile to exercise them.
   *(Decided — engine work is a separate, flagged change; nothing in this pack writes to okengine.)*
5. **`severity` provenance — store both, flag on disagreement.** Keep analyst `severity` *and*
   `cvss`; if `severity` disagrees with the CVSS-derived band, flag for review (never silently
   overwrite). *(Decided.)*
6. **`finding` requires `severity` — intentional tightening.** The engine base `finding` requires
   only `[type, status]`; okpack-sec **owns** `finding` and tightens it to `[type, severity, status]`.
   A security finding is a prioritization artifact, so it must carry an explicit `severity` (the enum
   includes `none` for the informational case). Flag-not-gate, so a finding missing it is flagged,
   not rejected. *(Decided — reconciles #13.3.)*

---

## 11. Reference implementation

The conformant reference implementation of this spec ships in this repo:

- `schema.yaml` — the machine contract (types, `type_aliases`, enums, field/list/`rels` bindings).
- `validate.py` — Core-conformance checks (§12.4): enum values (gated); required-field presence,
  `rels` predicates, and `refs[]` shape (flag-not-gate); type/alias integrity; the §9.5 spec↔schema
  drift block; and `§N` cross-ref resolution.
- `projectors/stix.py` + `conformance/` — the STIX 2.1 projector and its conformance suite: all 18
  types validated against the official `stix2` library, with golden fixtures and the documented-loss
  invariant (§7.3). `rels`/wikilink targets resolve against the whole-vault page graph
  (`build_vault_index` / `project_vault`) — a link resolves to the target page's true type+identity
  id, not the link path shape; the path-shape heuristic remains the single-page fallback. CI-enforced.
- `projectors/ocsf.py` + `conformance/run_ocsf_conformance.py` — the OCSF projector (event layer:
  `finding`/`detection` → Detection Finding 2004), validated against the official `py-ocsf-models`,
  with golden fixtures + the documented-loss (`unmapped`) invariant. CI-enforced. *(v0.2 work.)*

**Home.** okf-sec lives in **`okpacks-library/packs/okpack-sec`** — the canonical, public pack.
Extraction to a dedicated, neutral **`okf`** repo (base OKF + `profiles/okf-sec.md` + projection +
conformance) remains a distant contingency — done only if a second profile/implementer appears or
it's published as a standalone standard; the prep is in place (`okf_sec_version` pin + clean file
separation).

---

## 12. Versioning & governance

### 12.1 Version
- This spec is **okf-sec v0.2**, targeting **OKF base v0.1** (markdown + YAML frontmatter,
  `type` required).
- Versions are `MAJOR.MINOR`. Per semver convention, **before 1.0 a MINOR bump may break**; from
  1.0, a breaking change requires a MAJOR bump.
- An implementation declares the version it conforms to. A pack pins it via `schema.yaml`
  `okf_sec_version` (e.g. `"0.2"`).

### 12.2 Change classes
Every change is exactly one of:
- **Breaking** (MAJOR; pre-1.0 MINOR): rename/remove a canonical type; remove an enum value; add a
  new **required** field; change a field's type or meaning; remove a `rels` predicate or a
  `type_alias`; change a projection mapping so existing pages emit *different* STIX.
- **Additive** (MINOR; pre-1.0 PATCH): new optional type or field; new value in an *extensible*
  enum; new `rels` predicate, `type_alias`, or `refs[].std`; new `x_okfsec_*` projection field.
  Existing conformant pages stay valid.
- **Editorial** (PATCH): prose, examples, non-normative notes — no conformance impact.

> Adding a value to a **closed** enum is additive for *producers* but consumers must tolerate
> unknown values — treat it as MINOR and announce it.

### 12.3 `type_aliases` deprecation
- Aliases absorb legacy/vault names so older corpora stay conformant. **Aliases are stable within a
  MAJOR version** — never silently dropped.
- Adding an alias is additive; **removing one is breaking** and must ship deprecated (marked in
  `schema.yaml` + CHANGELOG) for at least one MINOR release before removal at a MAJOR.
- The generic `entity` type is **not** an alias — it is invalid and must be retyped.

### 12.4 Conformance levels
An implementation states the level it meets; **Core** is the floor:
- **Core** — parses; `type` is canonical or a declared alias; enum values valid (**gated**); required
  (tier R) fields present and `rels` predicates ∈ §6 vocabulary (**checked, flag-not-gate** per
  §1.4/§6.4). *(All checked by `validate.py`.)*
- **Projection** — `project_stix(page)` emits valid STIX 2.1 and the documented-loss set is exactly
  the `x_okfsec_*` extension (§7.3). *(Available once the conformance suite lands — freeze item D.)*

### 12.5 Stability surfaces
- **Stable** (governed by this policy): the type roster, required fields, enum *names* + closed
  values, the `rels` vocabulary, the `refs[].std` set, and the STIX projection mappings.
- **Open extension point** (additive by nature): `x_okfsec_*` custom properties, *extensible*
  enums, `tags`, and domain-specific optional fields.

### 12.6 Process
- Changes land via commits to the `okpacks-library` repo (okf-sec lives under `packs/okpack-sec`);
  if it is ever extracted (§11), they move to the `okf` repo's issues/PRs. Each is recorded in
  `CHANGELOG.md`, classified per §12.2.
- A release = a tagged version + a CHANGELOG entry. **v0.1 was cut 2026-06-17** (tag `okf-sec-v0.1`);
  the latest is **v0.2.1**. Extraction to a dedicated `okf` repo remains a distant contingency (§11).

---

## 13. Multi-source entity resolution (MDM)

Many security nouns are described by **multiple sources that disagree** — an actor by MITRE ATT&CK,
ThaiCERT, and Microsoft (different aliases, origin, motivation); a CVE by CISA KEV and NVD (divergent
CVSS/severity). okf-sec stores **each source's view separately** and fuses them **deterministically**,
so disagreement is preserved and attributable instead of silently overwritten. (This is distinct
from `finding`/`detection` *sightings* — "seen on host X at time T", §1 — which are event records,
not per-source views of one noun.) Mechanics: `schema.yaml` `source_registry` + `merge_policy`
(below) and the engine's `canonical_assemble`.

### 13.1 Two page kinds

| | path | who writes it |
|--|--|--|
| **observation** | `wiki/observations/<source>/<slug>.md` | a no_agent importer — one source's per-noun view; never hand-edited; hidden from the browse rail (reached by drill-down from the canonical) |
| **canonical** | `wiki/entities/<slug>.md` | `canonical_assemble` (deterministic) — the fused golden record the reader sees and agents enrich |

An **observation** carries the §2 envelope plus: `source` (a `source_registry` key), `reliability` /
`credibility` (that source's Admiralty weights), and `canonical` (the golden-record slug it belongs
to). A **canonical** is assembled from every observation sharing its `canonical` slug, and carries
`assembled_from` (the contributing observations) plus, on disagreement, `conflicts` + `needs_review`.

### 13.2 Which types are multi-source

- **actors** (`threat-actor` / `intrusion-set`) — `mitre-attack`, `thaicert`, `microsoft`.
- **malware / tools** (`malware` / `tool`) — `thaicert` (tgc-tools), `mitre-attack`.
- **vulnerabilities** (`vulnerability`) — `cisa-kev`, `nvd` (divergent CVSS/severity is the canonical
  multi-source case).

Single-source nouns stay as plain `entities/` pages — no observation overlay needed.

### 13.3 Canonical resolution (which observations fuse together)

An observation's `canonical` slug ties it to its golden record. Importers resolve it by matching the
incoming name + aliases against existing canonicals, **guarded against over-merge** (okengine#39):
merge only on a **primary-name match or ≥2 shared keys**; a lone shared alias **mints a distinct
canonical and flags it for review** rather than collapsing two genuinely different entities that
happen to reuse one alias token (the live failure was ThaiCERT's Iranian `Iridium` folding into
`Sandworm`, which carries Microsoft's `IRIDIUM` alias). A curated cross-source co-reference mapping
(the Microsoft "Rosetta Stone") may vouch a single shared alias as trusted. **Vulnerabilities skip
resolution** — the CVE id is the natural canonical key.

### 13.4 Fusion (`merge_policy`)

The assembler fuses each field across a canonical's observations per `schema.yaml` `merge_policy`:

- **union** — combine all values, deduped, order-stable (additive sets/relationships): `aliases`,
  `target_sectors`, `tags`, `refs`, `rels`, `sources`, `related`, `malware_type`, `motivation`.
- **consensus** — headline value = **highest source `reliability`** (recency tiebreak); **all** distinct
  values preserved with attribution; **>1 distinct value flags review** (G3): `suspected_origin`,
  `category`, `severity`, `tlp`, `identity_class`, `actor_class`, `sophistication`, `resource_level`,
  `ioc_type`, `infra_type`.
- **latest** — most-recently-observed value wins (evolving status): `last_seen`, `exploitation`,
  `cvss`, `kev`, `epss`.
- A field **not listed** defaults by value shape: lists → union, scalars → consensus.

### 13.5 Source registry + Admiralty weights

`source_registry` declares each ingest source's **standing Admiralty weights** — `reliability` (A–F,
the publisher/channel) and `credibility_default` (1–6, the typical claim) — which `consensus` uses as
fusion weights:

| key | source | class | reliability | credibility |
|--|--|--|--|--|
| `mitre-attack` | MITRE ATT&CK | framework | A | 2 |
| `thaicert` | ThaiCERT / ETDA Threat Group Cards | community | B | 3 |
| `cisa-kev` | CISA Known Exploited Vulnerabilities | government | A | 1 |
| `nvd` | NVD (NIST) | government | A | 2 |
| `microsoft` | Microsoft Threat Intelligence (Rosetta Stone) | vendor | A | 2 |

These standing weights apply only to the registry's reference-data importers. Agent-ingested **feed**
sources are Admiralty-scored per `source` page instead (§2), carrying their own `reliability` /
`credibility`.

### 13.6 Conflict surfacing

When `consensus` sees more than one distinct value for a field, the canonical records `conflicts`
(each contested field's competing values, each with its source) and sets `needs_review: true` (queued
in `wiki/_review-queue.md`). This mirrors the **G3 flag-not-gate** model: the assembler never silently
picks a winner on a contested field — a human resolves it. `assembled_from` lists the contributing
observations for provenance and re-assembly.

### 13.7 Reference implementation

Importers (`crons/scripts/okpack_sec_*_import.py`) write observations when run in
`--observations` / `OKPACK_SEC_OBSERVATIONS` mode; the over-merge guard is `mdm_resolve.py` (pack
adapter) over the engine's `entity_resolve`; fusion is the engine's `canonical_assemble`. Conformance:
`conformance/test_importers.py` (observation output + over-merge-guard regressions).
