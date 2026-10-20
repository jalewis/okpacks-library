# Changelog

## 0.3.17 — 2026-10-18

- Require OKEngine v0.15.18 and retain the existing Hermes pin. Align the pack and
  catalog release bindings with the merged engine used for qualification.

Migration impact: Requires engine upgrade to v0.15.18; no stored-page migration.

## 0.3.16 — 2026-10-03

- Require OKEngine v0.15.3 and retain the existing Hermes pin. Align the pack and
  catalog release bindings with the merged engine used for qualification.

Migration impact: Requires engine upgrade to v0.15.3; no stored-page migration.

## 0.3.15 — 2026-10-01

- Require OKEngine v0.15.2 and Hermes v0.21.3 (`v2026.9.14`).

Migration impact: none — runtime compatibility release only.

## 0.3.14 — 2026-09-29

- Require OKEngine v0.15.0 and Hermes v0.21.3 (`v2026.9.14`).
- The source helper (`crons/scripts/_okf_write.py`) treats a bare service endpoint URL (an ArcGIS
  `.../query` or `.../MapServer/<n>`, a Socrata `.../resource/<id>.json`, with no query string) as no
  source identity, matching the engine's write path (okengine#901).

Migration impact: new source pages only. A page already created with an endpoint-URL id keeps it.

## 0.3.13 — 2026-09-28

- Require OKEngine v0.14.9 and Hermes v0.21.3 (`v2026.9.14`).

Migration impact: none — runtime compatibility release only.

## 0.3.12 — 2026-09-27

- `_okf_write.write_page` now creates every page with an `id` (okpacks-library#105). It used to
  create pages with none, and OKEngine's write path cannot update, link or tombstone an id-less
  page (every later write is refused with "missing required field(s): id"). A caller-supplied id is
  kept; otherwise the helper derives the id the engine would: the governing type's `id_authority`
  binding (`attack:m1036`), else a slug minted in the page's namespace from its title
  (`entities:acme-corp`), the same derivation as OKEngine `backfill_ids`. A `source` page with a
  real url gets the engine's URL identity (`sources:url-<sha256[:20]>`), so it converges with the
  page raw-compile makes for the same URL. An existing page's id is never replaced. A derived id
  another page already holds is never claimed twice: an authority id is refused ('collision'), a
  minted slug is disambiguated as `backfill_ids` does. Without the engine identity libs
  (`id_lib`, `schema_lib`, `id_index`) a create is refused ('unverifiable') instead of landing
  id-less; updates are unaffected. Both refusals are logged to the lane's stderr.
- The HF notable-models importer takes a new page's id from the helper (`derive_page_id`)
  instead of deriving its own, and counts a helper refusal by its reason.
- The golden source page and the page-shapes example now show `raw:` as the capture's vault path
  (`raw/ai/<file>.md`). They showed a `raw:ai/<slug>` pseudo-ref, which the old daily-papers
  importer copied onto live pages; no engine lane can resolve it.

Migration impact: new pages only. Pages already created without an `id` are NOT repaired by this
release; stamp them with OKEngine `backfill_ids` (a separate data repair). Existing pages keep
whatever id they carry. Existing source pages that carry a `raw: raw:ai/...` pseudo-backlink are
likewise not rewritten.

## 0.3.11 — 2026-09-27

- concept-backfill now tells the model to finish with the receipt its selector prints and the
  runner verifies (okpacks-library#108). It never mentioned the receipt, so a run could not
  complete its per-item contract. The prompt adds the measured action directive and ends with the
  exact-receipt instruction the other receipt lanes carry: copy the selector's fenced
  `okengine-receipt` unchanged, account for every selected concept slug once, set each accepted
  write path, and leave `sha256` null for runner readback. The writer tool is unchanged
  (`converge_concept`). Its first-call sentence now reads "FIRST response MUST be a tool call:
  converge_concept", the form the prompt lint requires of a receipt lane.

Migration impact: none — prompt text only. Deployments pick the prompts up on `framework pull
--update` + reconcile.

## 0.3.10 — 2026-09-27

- Require OKEngine v0.14.8 and Hermes v0.21.3 (`v2026.9.14`).

Migration impact: none — runtime compatibility release only.

## 0.3.9 — 2026-09-26

- The engine-template prompts now match the lanes OKEngine actually runs. Several lanes are narrowed
  to one writer tool (okengine#664). The shipped prompts told concept-backfill to call
  `create_entity` and source-quality-backfill to call `update_entity`, so every instructed write
  was refused. These prompts are the ones the live deployment has run since 2026-09-24, upstreamed:
  - raw-backfill, entity-backfill and concept-backfill work from the evidence the selector embeds
    and write through `converge_source`, `converge_entity` and `converge_concept`;
  - source-quality-backfill scores through `score_source`;
  - the daily brief carries a step budget;
  - page-quality-enrich finishes with the selector's receipt.

  Three clarifications to the live text, to meet the library's staged-boundary and binding
  contracts:
  - raw-backfill copies the receipt with its `lane_id`, `contract_digest` and `input_digest`
    unchanged;
  - entity-backfill states that the entity cites the resolving source page;
  - source-quality-backfill names the lane's bound writer server
    (`mcp__okengine_write_source_quali_e3c511be__score_source`, the length-clamped name) rather than
    the unclamped `okengine_write_source_quality`, which exists only because the engine lane also
    lists that server explicitly.
  - receipt lanes open with the measured action-phase directives ("FIRST response MUST be a tool
    call", "Do not gather more information…") that the prompt lint requires.

Migration impact: none for stored pages. Deployments pick the prompts up on `framework pull
--update` + reconcile. Any local edits to these prompts should be compared against this version.

## 0.3.8 — 2026-09-26

- The Hugging Face notable-models importer decides whether a model is already present by
  **identity**, not by a hand-built path. It looks for the page anywhere under `entities/` (the
  reshelve drain moves pages to `entities/<l>/<l2>/`) and for a live page already holding the id
  OKEngine derives from the model's name, so a curated page such as `DeepSeek-R1` counts. New pages
  get that `id` and are written through the shared `_okf_write.write_page` helper (engine seat and
  importer guard), now carried by this pack. The old check looked only at `entities/<letter>/`, so
  each weekly run re-created ~100 id-less pages that the engine's slug-identity guard quarantined,
  failing the run (okpacks-library#104).
- Without OKEngine's identity libraries on the path (a pack-only checkout) the importer creates
  nothing and reports the records as not verifiable.

Migration impact: none for new installs. Existing id-less model pages from earlier runs stay
id-less until an operator stamps ids (OKEngine `scripts/backfill_ids.py`); the importer no longer
re-creates them.

## 0.3.7 — 2026-09-26

- The Hugging Face daily-papers importer writes **raw captures** (`raw/hf/<date>-<slug>-<arxiv>.md`)
  instead of `source` pages. OKEngine's raw-compile lane compiles each one through the enforced
  write path: the page gets the engine's URL identity and a partition-correct seat, and a paper
  already held by another page (e.g. from the arXiv feed) is attached to it rather than duplicated.
  Writing pages directly had minted ~600 id-less `source` pages that the write path could neither
  update nor find (okengine#886). Captures declare `publisher: arXiv` and keep `arxiv_id` and the
  `hf_upvotes` snapshot as provenance; the feed-wide `hf-daily-papers` tag is no longer added.

Migration impact: none for existing pages. New papers appear as source pages after the next
raw-compile run instead of immediately. `arxiv_id` / `hf_upvotes` are carried onto compiled pages
by OKEngine builds that include okengine!1160; earlier builds compile the capture without them.

## 0.3.6 — 2026-09-26

- Require OKEngine v0.14.7 and Hermes v0.21.3 (`v2026.9.14`).

Migration impact: none — runtime compatibility release only.

## 0.3.5 — 2026-09-23

- The weekly brief lane now declares `max_iterations: 16`. OKEngine's cron regen requires an
  integer `max_iterations >= 2` on every cost-bearing agent lane, so this pack at 0.3.4 failed the
  step a deploy runs, and a fresh install stopped at cron deploy (okpacks-library#103). The value
  matches what live deployments already run.

Migration impact: none — one additive field on one cron lane.

## 0.3.4 — 2026-09-19

- Stop claiming engine-reserved generated namespaces during taxonomy co-install.
  Domain types remain pack-owned; importer status output paths are unchanged.

Migration impact: none — ownership metadata correction; no stored pages move or change.

## 0.3.3 — 2026-09-19

- Require OKEngine v0.14.5 and Hermes v0.21.3 (`v2026.9.14`).

Migration impact: none — runtime compatibility release only.

## 0.3.2 — 2026-09-17

- Require OKEngine v0.14.4 and Hermes v0.21.3 (`v2026.9.14`).

Migration impact: none — runtime compatibility release only.

## 0.3.1 — 2026-07-19

- Feed lane now captures linked article/abstract full text (`--capture-full-text`,
  okengine#272): content-addressed, append-only objects under `raw/captures/`. No contract
  change; deployments pick it up on the next cron-script stage.

Migration impact: none — additive only.

## 0.3.0 — 2026-07-19

- **Breaking**: type `technique` renamed to `method` (standalone contract; no type_alias is shipped — in a composed CTI vault `technique` belongs to the okpack-threat-actors host).
- Added composing contract: `benchmark`/`dataset`/`lab`/`method`/`model`/`researcher` now travel via `subdomain/host-schema-additions.yaml`.
- This baseline establishes the okpacks#29 versioning convention (VERSIONING.md): it versions schema-contract changes that accumulated after the previous `version:` was set.

Migration impact: pages with `type: technique` must be re-typed to `method` (or add a local `type_aliases: {technique: method}` in a standalone deployment); then `framework validate` and let `corpus_audit` confirm zero drift.
