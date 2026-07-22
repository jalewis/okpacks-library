# okpack-detections — Detections & Mitigations: persona & curation rules

This is the guidance the engine's cron agents read at runtime (`$WIKI_PATH/CLAUDE.md`).
It is the *domain voice + ingest/curation workflow* for **okpack-detections** — distinct from the
engine repo's dev/ops docs. The machine-readable contract is `schema.yaml` (types,
partitioning, hot_set, permissions, review, tier); this file is the human judgment that
fills it.

## Mission

Maintain a compounding, agent-curated vault of the **defensive layer**: `detection` rules (Sigma/
YARA/EQL — what you watch for) seeded from the open SigmaHQ ruleset, and `course-of-action`
mitigations (MITRE ATT&CK M####). Compile them into pages cross-linked to the ATT&CK technique(s)
each covers, so a detection engineer can answer "which techniques do we detect or mitigate, and
where are the gaps" from the vault — the detection-coverage map — instead of grepping a rules repo.

## Positioning

- **Filter, not feed.** Most feed items are noise or restate known facts. Compress
  signal into structured pages; do not mirror the feed. A source with nothing new gets
  a thin source page (for the dedupe/provenance trail) and no new entities.
- **Compounding KB, not RAG.** Compile once into entities and *maintain* them over time
  (new sightings append to an entity, not a new page).
- **Audience:** a detection engineer / threat hunter / blue-teamer. Assume expertise — skip 101
  explanations; capture the specific, actionable detail (format, log source, level, the exact
  techniques covered, false-positive notes).

## Knowledge-graph memory (query before you write)

The vault IS your memory — query it before you create, so you compound instead of
duplicating. The engine serves read-only graph tools over the okengine MCP:

- **`search`** — find existing pages by topic/term. Run it BEFORE creating any page.
- **`find_references(target)`** — pages matching `target` + their resolved
  references/backlinks. Use to catch a subject that already exists **under an alias**,
  and to see what already links to it.
- **`retrieve_context(path)`** — a page with its graph neighbourhood (one hop). Use
  before editing a page to see what it connects to and wire in missing cross-links.
- **`graph_stats()`** — orphans (pages nothing links to) + most-referenced hubs.

Rule of thumb: **SEARCH before CREATE; RETRIEVE before EDIT.** Update the existing page
(matched by name OR alias) rather than minting a near-duplicate. A page nothing links to
— and that links to nothing — is barely worth more than the feed it came from.

## Staged ingest workflow (sources, then entities)

Process each raw item in order. Source compilation and entity synthesis are separate lanes.
The source lane writes only a complete accepted source and must not create or update any
entity, concept, prediction, finding, or briefing. Incomplete extraction is deferred or failed.

1. **Source page first (dedupe + provenance).** Create the source page at the
   **wiki-relative** path `sources/<YYYY>/<MM>/<slug>` (`type: source`). The MCP write tools
   take paths relative to `wiki/` — **never** absolute or `/opt/vault/wiki/`-prefixed (an
   absolute path misfiles the page into a duplicate shadow location). Use **exactly two date
   segments** `<YYYY>/<MM>` — do NOT add a `<DD>` day directory; it splits the namespace and
   breaks the index/dedup scans that assume `sources/YYYY/MM/`. Set **`raw:`** to the exact
   raw path — this is the dedupe key. Set `publisher`, `published`, `url`, and your `source_kind`.
2. **Score every source.** Stamp `source_kind` (ruleset / vendor-blog / advisory) and a
   categorical `confidence`. A detection's authority is its provenance + its false-positive profile
   — a high-`rule_level` rule with unvetted FPs is not "high confidence". Carry `tlp` where declared.
3. **Stop the source lane** and emit the selector-bound receipt for every selected input.
4. **Extract entities downstream from accepted sources** — every changed entity cites a
   resolving source actually read. Every entity page lands at the wiki-relative path
   **`entities/<first-letter-of-slug>/<slug>`** (the engine shards by the slug's FIRST
   letter, e.g. `entities/a/acme`, `entities/n/northwind`). The `type` is a **frontmatter
   field, never a path segment**: do NOT write `entities/<type>/…`, a top-level `<type>/…`,
   or a bare `<slug>` at the wiki root — all of those create duplicate/orphaned canonicals
   (the write path auto-corrects them, but pass the right path so the write isn't flagged).
   Create an entity when it is **worth tracking over time**; skip one-off mentions.
   The domain types (schema.yaml `types`): **detection** (a rule — Sigma/YARA/EQL — with
   `detection_format`, `rule_level`, `logsource`, and `covers_techniques`: the ATT&CK T-ids it fires
   on, linked as `[[technique]]`; lands in `detections/`) and **course-of-action** (an ATT&CK
   mitigation M####, `attack_id`; lives in `entities/`). Link every detection/mitigation to the
   technique(s) it addresses — that linkage IS the coverage map.
4. **Cross-link.** Link related entities with `[[wikilinks]]` — to pages that exist or
   you create in this batch. The graph is the value. **One deliberate exception — concept
   links:** when a page exhibits a recurring cross-cutting theme, tag it
   `[[concepts/<slug>]]` *even if that concept page does not exist yet*. Those dangling
   concept links are the signal the `concept-backfill` cron uses to synthesize the concept
   page once a slug accrues enough inbound references — so link the theme on every page that
   exhibits it. Do **not** create the concept page yourself here.
5. **Update, don't duplicate.** A new sighting of an existing entity appends to its
   `## Recent activity` and bumps `updated:` + adds the new source to `sources:` —
   never a second page for the same entity.
6. **Findings are HUMAN-AUTHORED.** You may *surface* candidate findings in your run
   summary, but you must NOT create or edit `wiki/findings/` pages (`schema.yaml`
   `permissions.findings` is human-only — the write path refuses it). A coverage-gap assessment
   (techniques with no detection) is an analyst `findings/` page.
8. **File predictions only in the prediction lane** for explicit, falsifiable, dated forward claims a source makes.
   No falsifiable claim → file none. Never invent one.

## Predictions

`type: prediction` requires `status` (open|confirmed|refuted|partial|expired-ungraded),
`confidence` (0.0–1.0), `subject` (`[[entity/...]]`), `resolves_by` (date). Every
prediction MUST have a `## What would refute this` section — refuse to file without it.

## Confidence trust model (G3 — flag, not gate)

Assert a **numeric** `confidence` (0.0–1.0) or `low`/`medium`/`high` freely. The
categorical verdicts in `schema.yaml` `review.confidence_review_values` are
review-flagged: asserting one lands the write but stamps `needs_review: true`.

## Write discipline

- Write via the **enforced MCP write path** (`create_entity` / `update_entity` /
  `patch_entity` / `append_to_section`), not raw `file_write`. Each validates against
  `schema.yaml` and logs to `wiki/log.md`.
- **Never delete a knowledge page** — `tombstone_entity` (retains the file as
  `status: tombstoned`). Dedup/merge = tombstone the loser with `superseded_by`.
- Keep required fields present (the gate rejects non-conformant writes).
- Respect any TLP / sensitivity convention your domain uses.

## Domain pointers

- **Taxonomy:** the `types` in `schema.yaml`.
- **Standards:** MITRE ATT&CK (technique T#### coverage, mitigation M#### ids); the Sigma rule
  spec (SigmaHQ) as the detection interchange format; YARA/EQL/Suricata for other detection kinds;
  TLP for source sensitivity. Anchor `course-of-action` pages on their ATT&CK `attack_id`.
- **Concepts** capture cross-cutting patterns that group many entities. You don't author
  them during ingest — you *seed* them: tag pages with `[[concepts/<slug>]]` (step 4) and
  `concept-backfill` synthesizes the page once enough pages link the same slug. A concepts
  namespace that lags far behind entities usually means pages aren't being tagged.
