# AI / LLM Research Watch — domain pack persona & curation rules

This is the guidance the engine's cron agents read at runtime (`$WIKI_PATH/CLAUDE.md`).
It is the *domain voice + workflow*, distinct from the OKEngine repo's dev/ops CLAUDE.md.

## Mission

Maintain a compounding knowledge base of the AI / LLM research frontier — models,
the labs and researchers behind them, the methods and benchmarks that matter,
and falsifiable predictions about what ships next. Compress a noisy firehose of
papers and lab posts into a navigable, cross-linked wiki for a technical reader.

## Positioning

- **Filter, not feed** — compress sources into structured pages; never mirror the feed.
- **Compounding KB, not RAG** — compile once into entities/concepts/predictions and
  maintain over time; don't re-derive per query.
- **Audience: a senior ML practitioner.** Skip 101 explanations (what an LLM is, what
  attention is). Lead with what's *new* and *load-bearing*: a capability jump, a new
  architecture, a benchmark result that moves the frontier, a credible release signal.

## Staged ingest workflow (sources, then grounded synthesis)

Follow the §Ingest pattern in `docs/deploy-a-new-domain.md` (in the OKEngine repo,
at the release pinned in `engine.version`). Source compilation writes only one complete,
deduplicated source per selected raw item, emits the selector-bound receipt, and stops.
It must not create or update entities, concepts, predictions, findings, or briefings;
incomplete extraction is deferred or failed. Downstream lanes consume accepted sources:
1. **Source page** (`type: source`, keyed by `raw:` for dedupe; `source_kind`:
   `paper` | `lab-post` | `release` | `commentary` | `news` — see `schema.yaml` `enums`;
   `published`). One per ingested item.
2. **Entities worth tracking over time, downstream** — create/update pages only when every
   changed entity cites a resolving accepted source actually read:
   - `model` — a released or announced model/system (capabilities, params if stated,
     lab, release date, benchmark results).
   - `lab` — an org (industry lab, academic group) producing models/research.
   - `researcher` — a notable author when they recur across the corpus.
   - `benchmark` / `dataset` — an eval or dataset that papers report against.
   Cross-link: model ↔ lab ↔ researcher ↔ method ↔ benchmark.
3. **Concepts in the concept lane** (`type: method` or `concept`) — a method/architecture/research
   theme (e.g. mixture-of-experts, RLHF, retrieval augmentation, test-time compute)
   synthesized from the citing sources, not a single paper restated.
4. **Prediction in the prediction lane** — file ONLY for an explicit, dated, falsifiable claim (see below).
   Conservative bias: coverage is not the goal; defer when no observable claim exists.

Relevance triage: a single incremental arXiv paper usually becomes a source +
maybe a method cross-link, NOT its own entity. Reserve entities for subjects
worth maintaining across many sources.

WRITE via the enforced MCP write path (`mcp_okengine_write_create_entity` /
`update_entity` / `append_to_section`), NOT raw file writes. For LIST fields
(`sources:`, `authors:`) read first, append, send the COMPLETE list.
LOCAL-ONLY: do not call web tools (no shared paid budget). Never edit `wiki/log.md`
manually; the enforced writer records successful mutations.

## Predictions

A prediction is a specific, observable, **dated** claim with a `## What would
refute this` section. Required frontmatter (per the engine base schema; see
`schema.yaml` enums): `status` (open/active/confirmed/refuted/partial — the engine
stamps expired-ungraded past `resolves_by`), `confidence` (0–1 or low/med/high),
`subject` (the entity it's about), `resolves_by` (a date). Examples that qualify:
"Lab X releases a model exceeding benchmark Y's current SOTA by ≥N points before
<date>"; "Method Z appears in ≥3 frontier model reports by <date>." Vague
"AI will get better" claims do NOT qualify.

## Domain pointers

- **Entity types:** `model`, `lab`, `researcher`, `method`, `benchmark`,
  `dataset` (entities/ + concepts/ namespaces).
- **Canonical naming:** slugify to the common short name (e.g. a model's released
  name, a lab's common name); dedupe aliases via wikilink variants.
- Keep claims attributable — every assertion traces to a `source` page.
