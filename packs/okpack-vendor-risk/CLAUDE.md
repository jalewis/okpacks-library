# okpack-vendor-risk — Vendor / supply-chain risk: persona & curation rules

This is the guidance the engine's cron agents read at runtime (`$WIKI_PATH/CLAUDE.md`).
It is the *domain voice + ingest/curation workflow* for **okpack-vendor-risk** — distinct from the
engine repo's dev/ops docs. The machine-readable contract is `schema.yaml` (types,
partitioning, hot_set, permissions, review, tier); this file is the human judgment that
fills it.

## Mission

Maintain a compounding vendor / supply-chain risk vault: ingest public vendor-risk
sources (advisories, breach disclosures, sanctions/watchlist publications, status
pages, financial/trade press) and compile them into a durable graph of vendors,
products, components, incidents, and vulnerabilities — so procurement/GRC/security
readers can answer "which suppliers should worry us this quarter, and why" from the
vault instead of re-reading the feed. The operator's dependency profile (the vendor
register, contracts/, the risk-ranking target config) decides RELEVANCE; the feeds
only supply evidence.

## Positioning

- **Filter, not feed.** Most feed items are noise or restate known facts. Compress
  signal into structured pages; do not mirror the feed. A source with nothing new gets
  a thin source page (for the dedupe/provenance trail) and no new entities.
- **Compounding KB, not RAG.** Compile once into entities and *maintain* them over time
  (new sightings append to an entity, not a new page).
- **Audience:** procurement / GRC / security / resilience owners of a vendor
  register. Assume expertise — skip 101 explanations; capture the specific,
  actionable detail (which product, which version range, which contract owner
  cares).

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

## Ingest workflow (sources → entities)

Process each raw item in the digest IN ORDER. Read `schema.yaml` for the exact required
fields per type.

1. **Source page first (dedupe + provenance).** Create the source page at the
   **wiki-relative** path `sources/<YYYY>/<MM>/<slug>` (`type: source`). The MCP write tools
   take paths relative to `wiki/` — **never** absolute or `/opt/vault/wiki/`-prefixed (an
   absolute path misfiles the page into a duplicate shadow location). Use **exactly two date
   segments** `<YYYY>/<MM>` — do NOT add a `<DD>` day directory; it splits the namespace and
   breaks the index/dedup scans that assume `sources/YYYY/MM/`. Set **`raw:`** to the exact
   raw path — this is the dedupe key. Set `publisher`, `published`, `url`, and your `source_kind`.
2. **Score every source.**
   > TODO: define your source-quality rubric. okpack-sec uses Admiralty
   > `reliability` (A–F, the channel) + `credibility` (1–6, the claim) + `tlp` +
   > `bias_flags`. Adapt to your domain's notion of trust, or simplify to a single
   > `confidence`. Add the scoring fields to `source.required` in schema.yaml if you
   > want the gate to enforce them.
3. **Extract entities** — every entity page lands at the wiki-relative path
   **`entities/<first-letter-of-slug>/<slug>`** (the engine shards by the slug's FIRST
   letter, e.g. `entities/a/acme`, `entities/n/northwind`). The `type` is a **frontmatter
   field, never a path segment**: do NOT write `entities/<type>/…`, a top-level `<type>/…`,
   or a bare `<slug>` at the wiki root — all of those create duplicate/orphaned canonicals
   (the write path auto-corrects them, but pass the right path so the write isn't flagged).
   Create an entity when it is **worth tracking over time**; skip one-off mentions.
   > TODO: list your domain entity types + the identity field each needs (mirror
   > schema.yaml `types`).
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
   `permissions.findings` is human-only — the write path refuses it).
   > TODO: delete this rule if your domain has no human-only gate.
7. **File predictions** for explicit, falsifiable, dated forward claims a source makes.
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
- **Standards:** > TODO: list the canonical external IDs/standards your domain anchors
  on (e.g. an ID scheme, a grading system, a classification).
- **Concepts** capture cross-cutting patterns that group many entities. You don't author
  them during ingest — you *seed* them: tag pages with `[[concepts/<slug>]]` (step 4) and
  `concept-backfill` synthesizes the page once enough pages link the same slug. A concepts
  namespace that lags far behind entities usually means pages aren't being tagged.

## Vendor-risk curation rules (pack-specific)

- **Organizations only.** Never score, profile, or editorialize about vendor STAFF or
  executives. People appear at most as named public-role facts inside a cited incident
  page — never as pages of their own, never with risk language.
- **High-stakes claims are gated.** Sanctions, litigation, and financial-distress claims
  need independent, cited sources (the grounding audit is the enforcement); until then
  they are `confidence: low` observations that must NOT move a ranking or headline a
  brief.
- **incident pages are the event stream.** One dated page per discrete event in
  `incidents/` (`type: incident`, `date:`, `kind: breach|outage|recall|sanction|lawsuit|
  financial-distress`, `vendor: [[entities/...]]`, `sources:`). Ongoing situations get
  dated follow-up entries appended, not duplicate pages.
- **contracts/ is the operator's register — READ ONLY.** Contract pages (criticality,
  renewal_date, owner_team) are human-authored; the agent links to them and uses their
  criticality to prioritize, but never creates or edits them (the write path enforces
  this).
- **Vendor aliases matter.** Feeds spell the same supplier five ways; keep `aliases:`
  on vendor pages current — the risk-ranking lane folds evidence by declared aliases
  and cannot merge what you don't declare.
- **Link the dependency chain.** component pages link upward (`part_of:` a product) and
  to their supplier (`supplied_by:` a vendor); vulnerability pages wikilink the affected
  products/components. "What breaks if vendor X fails" is answered by these typed links
  until a dependency-map lane exists.
