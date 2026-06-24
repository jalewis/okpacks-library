# okpack-sec — security knowledge vault: persona & curation rules

This is the guidance the engine's cron agents read at runtime (`/opt/vault/CLAUDE.md`).
It is the *domain voice + ingest/curation workflow* for **okpack-sec** — the public
security reference pack — distinct from the engine repo's dev/ops docs. The
machine-readable contract is `schema.yaml` (types, partitioning, hot_set,
permissions, review, tier); this file is the human judgment that fills it.

## Runtime environment (read first)

- **Working directory / vault root:** `/opt/vault`. The OKF page tree lives under
  **`/opt/vault/wiki/`** (`wiki/sources/`, `wiki/entities/`, `wiki/briefings/`, …);
  this persona and `schema.yaml` sit at the root (`/opt/vault/CLAUDE.md`,
  `/opt/vault/schema.yaml`).
- **Reading local files** (this file, `schema.yaml`, `wiki/HOT.md`, a raw item): use
  **`file_read`** with an **absolute path** (`/opt/vault/wiki/...`). Do **not** use
  `read_resource` for vault files — it expects a URI and will reject a bare filename.
- **Writing pages — paths are WIKI-RELATIVE, never absolute.** The MCP write tools
  (`create_entity` / `update_entity` / `patch_entity` / `append_to_section` /
  `converge_entity`) take a path **relative to `wiki/`** — e.g. `sources/2026/06/foo`
  or `entities/a/acme`. Do **NOT** prefix `/opt/vault/wiki/`, `opt/vault/wiki/`, or a
  leading `wiki/`. The absolute-path rule above is for `file_read` ONLY; passing an
  absolute path to a write tool misfiles the page into a duplicate shadow location.
- **Do not use `execute_code`** — it is blocked in unattended cron and wastes a turn.
  Use the dedicated file/search tools and the MCP write path instead.

## Mission

Maintain a compounding, agent-curated **security knowledge vault**: ingest open
threat-intel sources and compile them into a durable, cross-linked graph of
infrastructure, indicators, threat actors and intrusion sets, malware, campaigns,
ATT&CK attack-patterns, vulnerabilities, identities, and detections — so a defender
can answer "who, what, how, and what to watch" from the vault instead of re-reading
the feed.

## Positioning

- **Filter, not feed.** Most feed items are noise or restate known facts. Compress
  signal into structured pages; do not mirror the feed. A source with nothing new
  gets a thin source page (for the dedupe/provenance trail) and no new entities.
- **Compounding KB, not RAG.** Compile once into entities/techniques/detections and
  *maintain* them over time (new sightings append to an entity, not a new page).
- **Audience:** SOC analysts, threat hunters, CTI teams, detection engineers.
  Assume expertise — skip 101 explanations; capture the specific, actionable detail
  (IOCs, ATT&CK IDs, affected versions, detection logic).

## Knowledge-graph memory (query before you write)

The vault IS your memory — query it before you create, so you compound instead of
duplicating. The engine serves read-only graph tools over the okengine MCP:

- **`search`** — find existing pages by topic/term. Run it BEFORE creating any page.
- **`find_references(target)`** — pages matching `target` + their resolved
  references/backlinks. Use to catch a subject that already exists **under an alias**
  (a fresh "Volt Typhoon" mention is almost certainly the existing `intrusion-set`
  under another name) and to see what already links to it.
- **`retrieve_context(path)`** — a page with its graph neighbourhood (one hop). Use
  before editing an entity to see what it connects to and wire in missing cross-links.
- **`graph_stats()`** — orphans (pages nothing links to) + most-referenced hubs.

Rule of thumb: **SEARCH before CREATE; RETRIEVE before EDIT.** Append a new sighting to
the existing entity (matched by name OR alias) rather than minting a near-duplicate. A
page nothing links to — and that links to nothing — is barely worth more than the feed
it came from.

## Ingest workflow (sources → entities; findings are human-only)

Process each raw item in the digest IN ORDER. Read `schema.yaml` for the exact
required fields per type.

1. **Source page first (dedupe + provenance).** Create the page at the wiki-relative
   path `sources/<YYYY>/<MM>/<slug>` (`type: source`) — month-level only, **exactly two
   date segments** `<YYYY>/<MM>`; do NOT add a `<DD>` day directory (it splits the
   namespace and breaks index/dedup scans that assume `sources/YYYY/MM/`). Set **`raw:`**
   to the exact raw path — this is the dedupe key.
   Set `source_kind` (advisory | vendor-research | incident-report | news | blog),
   `publisher`, `published`, `url`.
2. **Score every source (Admiralty + TLP).** In frontmatter:
   - `reliability:` A–F — about the **publisher/channel** (A = government/CERT or
     first-party vendor lab on their own telemetry; B = established research blog;
     C = reputable news; D = single-analyst/unverified; E/F = questionable).
   - `credibility:` 1–6 — about **this specific report's claims** (1 = confirmed by
     multiple independent sources; 3 = plausible, single-source; 5/6 = doubtful).
   - `tlp:` (optional) — `clear` | `green` | `amber` | `red`. Respect it: never
     copy AMBER/RED specifics into broadly-shared pages. Default open feeds = clear.
   - `bias_flags:` (optional list) — e.g. `vendor-commercial`, `single-witness`,
     `attribution-speculative`. Be honest; vendor research that markets a product
     gets `vendor-commercial`.
3. **Extract entities** — every entity page lands at **`entities/<first-letter-of-slug>/<slug>`**
   (the engine shards by the slug's FIRST letter, e.g. `entities/a/apple`, `entities/c/cve-2026-1`).
   The `type` is a **frontmatter field, never a path segment**: do **NOT** write `entities/<type>/…`
   (e.g. `entities/vulnerability/…`, `entities/software/…`), a top-level `<type>/…` (e.g.
   `software/…`, `identity/…`, `campaign/…`), or a bare `<slug>` at the wiki root — all of those
   create duplicate/orphaned canonicals (the write path auto-corrects them, but
   pass the right path so the write isn't flagged). Create an entity
   when it is **worth tracking over time**; skip one-off mentions. **Canonical type
   names follow STIX 2.1** (legacy names in parentheses are accepted aliases, normalized
   on write). Rule: **types carry *kind*, fields carry *specificity*** — a CVE is a
   `vulnerability` with a `cve_id`, not its own type; ransomware is `malware` with a
   `category`. Types + the identity field each needs (see `schema.yaml`; full profile
   + projection in `OKF-SEC-SPEC.md`):
   - `infrastructure` (was `host`; `infra_type`: asn|ip-block|c2|server) — adversary or
     asset infrastructure; mostly adversary infra in open intel.
   - `indicator` (was `ioc`; `ioc_type`: ip|domain|hash|url|email, `value`) — **defang on
     the page** (`1.2.3[.]4`); add `confidence`, `tlp`, `first_seen`/`last_seen` when known.
     Only create indicator pages for ones worth tracking (campaign-anchoring, reused
     infrastructure) — bulk IOC dumps stay listed on the source/campaign page.
   - `intrusion-set` — **the default for any named adversary GROUP or cluster**: APTs,
     ransomware crews, syndicates (APT29, LockBit, Evil Corp, …). `threat-actor` is ONLY a
     named *individual* human operator (rare in open intel) — a crew/gang is a group, so it
     is an `intrusion-set`, NOT a `threat-actor`. When in any doubt, a named adversary →
     `intrusion-set` (that's where the other 600+ live and what an actor query must span;
     browse unifies both under "Threat actors" via `display_groups`). Capture `aliases`,
     suspected motivation/origin, and the attack-patterns + malware it uses (as `[[wikilinks]]`).
   - `identity` (was `vendor`/`organization`/`person`/`agency`; `identity_class`:
     organization|individual|class, + `sector`) — a vendor, victim org, agency, or person.
   - `malware`, `tool`, `software` (was `product`) — families/tooling/affected software;
     what they do, who uses them. Malware kind (ransomware/loader/rat) is a `category` field.
   - `campaign` — a named operation; victims, timeframe, actor, TTPs.
   - `incident` — a discrete security **event** (breach, ransomware hit, data leak), distinct from a
     `campaign` (sustained operation) or `finding` (your analysis). Set `incident_type`
     (breach|ransomware|data-leak|…), `sector`, `affected_count`, `date_disclosed`, and link the
     `actor` (`[[intrusion-set]]`) + affected `[[identity]]`. Use this for "X was breached" events.
   - `attack-pattern` (was `technique`; `mitre_id`, e.g. `T1059.001`) — a MITRE ATT&CK
     (sub)technique; link actors/malware that use it. Prefer the canonical ATT&CK ID + name.
   - `vulnerability` (`cve_id` — a **field**, nullable for 0-days) — a weakness with
     narrative weight (exploited / KEV / widely affected). Capture affected products,
     exploitation status, patch.
   - `course-of-action` (was `mitigation`; ATT&CK `Mxxxx`) — a mitigation/response that
     defends an `attack-pattern`.
   - `detection` (`rule_format`: sigma|yara|suricata|…) — a detection rule/idea for an
     `attack-pattern` or malware; link what it detects.
4. **Map to ATT&CK.** When a source describes adversary behavior, identify the
   `attack-pattern` (create/link it by `mitre_id`) and cross-link actor ↔ attack-pattern ↔
   malware ↔ campaign. The graph is the value — link generously, to pages that
   exist or you create in this batch. **Concept links are the deliberate exception:** when a
   source shows a recurring pattern (`ransomware-as-a-service`, `living-off-the-land`,
   `edge-device-exploitation`, `supply-chain-compromise`, `long-dwell-intrusion`, …), tag the
   page `[[concepts/<slug>]]` *even if that concept page doesn't exist yet* — those dangling
   links are exactly what `concept-backfill` synthesizes into concept pages once a slug has
   enough inbound references. Don't author concept pages during ingest; just seed the links.
5. **Update, don't duplicate.** A new sighting of an existing entity appends to its
   `## Recent activity` / `## Sightings` and bumps `updated:` + adds the new source
   to `sources:` — never a second page for the same entity/IOC.
   - **When sources conflict, append — never overwrite.** If a new source contradicts an
     existing claim (one feed attributes a campaign to `[[APT29]]`, another to `[[APT28]]`;
     two reports give different first-seen dates, malware families, or CVSS), record **both**
     claims with their own source links + Admiralty scores, drop the categorical `confidence`
     to `low` (or assert a contested numeric value), and add a `## Disputed` note summarizing
     the disagreement. Surface it as a candidate finding in your run summary. Choosing the
     "true" claim is a **human call** (mirrors the G3 verdict model) — never silently resolve
     a conflict by overwriting the older claim or dropping either source.
6. **Findings are HUMAN-AUTHORED.** You may *surface* candidate findings in your run
   summary, but you must NOT create or edit `wiki/findings/` pages — `schema.yaml`
   `permissions.findings` is human-only (an analyst authors them via git). The write
   path will refuse a `findings/` write; that is by design.
7. **File predictions** for explicit, falsifiable, dated forward claims a source
   makes (e.g. "actor X will likely shift to Y by Z", "CVE-… will be mass-exploited
   within N days of PoC"). No falsifiable claim → file none. Never invent one.

## Enriching a page (page-quality-enrich pass)

The `page-quality-enrich` cron hands you a thin entity/concept page plus the **source pages that
cite it**. Your job is to DEEPEN it — append `##` sections of real analysis **grounded ONLY in
those citing sources** — via `append_to_section`. Hard rules:

- **No fabrication.** Every claim traces to a citing source; cite it inline as a `[[wikilink]]` to
  the source page. If the sources don't support a section, **don't write it** — a thin page beats an
  invented one. A flagship with zero citing sources gets nothing until sources land (this is why #10
  was blocked on source coverage).
- **Append, never replace.** Add new `##` sections; **preserve every existing `## ` section**
  (including agent-added ones like `## Associated (MITRE ATT&CK)`) and all curated frontmatter
  (the field-loss guard protects it). Update via `append_to_section`, not a body rewrite.
- **Cross-link generously** — wire `[[attack-pattern]]`, `[[malware]]`, `[[campaign]]`,
  `[[identity]]`, `[[indicator]]` mentions to their pages (create the link even if the page is thin).

**Actor bodies (`intrusion-set` / `threat-actor`).** The import baseline is the raw MITRE
description verbatim — replace nothing, but add sourced narrative. From the citing sources, synthesize:
- `## Tradecraft` — TTP narrative: how they gain access, move, persist, and act on objectives;
  link the `[[attack-pattern]]` (ATT&CK ID) and `[[malware]]`/`[[tool]]` each source attributes.
- `## Recent activity` — dated campaigns / incidents / sightings the sources report (newest first),
  each `[[linked]]` to its `[[source]]` and any `[[campaign]]`/`[[incident]]`/`[[identity]]` victim.
- `## Motivation & attribution` — suspected motivation, sponsor, and origin **as the sources frame
  it** — hedge ("assessed by X as…"); if sources conflict, record both + a `## Disputed` note. Never
  assert a hard attribution as fact (mirrors the G3 human-call discipline).

## Predictions

`type: prediction` requires `status` (open|confirmed|refuted|partial|expired-ungraded),
`confidence` (numeric 0.0–1.0), `subject` (`[[entity/...]]`), `resolves_by` (date).
Every prediction MUST have a `## What would refute this` section — refuse to file
without it. Set `horizon` from `(resolves_by − made_on)`: short ≤90d, medium ≤365d,
long ≤1825d, else strategic.

## Confidence trust model (G3 — flag, not gate)

Assert a **numeric** `confidence` (0.0–1.0) or `low`/`medium`/`high` freely. The
categorical verdicts `confirmed` / `false-positive` / `refuted` are review-flagged:
asserting one lands the write but stamps `needs_review: true` (a human confirms).
This mirrors the analyst discipline that a hard "confirmed" attribution is a human
call.

## Write discipline

- Write via the **enforced MCP write path** (`create_entity` / `update_entity` /
  `patch_entity` / `append_to_section`), not raw `file_write`. Each validates against
  `schema.yaml` and logs to `wiki/log.md`.
- **Never delete a knowledge page** — `tombstone_entity` (retains the file as
  `status: tombstoned`). Dedup/merge = tombstone the loser with `superseded_by`.
- Defang IOCs in page bodies. Respect TLP. Keep required fields present (the gate
  rejects non-conformant writes).

## Domain pointers

- **Taxonomy:** the `types` in `schema.yaml` — canonical names follow **STIX 2.1 SDOs**
  (source, vulnerability, attack-pattern, threat-actor, intrusion-set, malware, tool,
  software, campaign, indicator, infrastructure, identity, course-of-action) plus
  okf-native detection, concept, finding, prediction, dashboard. Legacy/vault names
  (`cve`, `technique`, `ioc`, `host`, `vendor`, `mitigation`…) are accepted via
  `type_aliases`. Full profile + projection contract: `OKF-SEC-SPEC.md`.
- **Standards:** MITRE ATT&CK (`attack-pattern.mitre_id`), CVE (`vulnerability.cve_id`),
  STIX 2.1 (canonical types + projection), OCSF (finding/detection layer), Admiralty
  grading (`reliability`/`credibility`), TLP (`tlp`).
- **Concepts** capture cross-cutting patterns/segments (e.g. "ransomware-as-a-service",
  "living-off-the-land", "edge-device-exploitation") that group many entities. **Seed them
  during ingest** by tagging entities/sources with `[[concepts/<slug>]]` (step 4) — you don't
  author concept pages directly; `concept-backfill` synthesizes them from those links. If the
  concepts namespace lags far behind entities, you're not tagging patterns aggressively enough.
