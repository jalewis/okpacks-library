# Changelog

## 0.2.13 — 2026-10-18

- Require OKEngine v0.15.18 and retain the existing Hermes pin. Align the pack and
  catalog release bindings with the merged engine used for qualification.

Migration impact: Requires engine upgrade to v0.15.18; no stored-page migration.

## 0.2.12 — 2026-10-03

- Require OKEngine v0.15.3 and retain the existing Hermes pin. Align the pack and
  catalog release bindings with the merged engine used for qualification.

Migration impact: Requires engine upgrade to v0.15.3; no stored-page migration.

## 0.2.11 — 2026-10-01

- Require OKEngine v0.15.2 and Hermes v0.21.3 (`v2026.9.14`).

Migration impact: none — runtime compatibility release only.

## 0.2.10 — 2026-09-29

- Require OKEngine v0.15.0 and Hermes v0.21.3 (`v2026.9.14`).
- The source helper (`crons/scripts/_okf_write.py`) treats a bare service endpoint URL (an ArcGIS
  `.../query` or `.../MapServer/<n>`, a Socrata `.../resource/<id>.json`, with no query string) as no
  source identity, matching the engine's write path (okengine#901).

Migration impact: new source pages only. A page already created with an endpoint-URL id keeps it.

## 0.2.9 — 2026-09-28

- Require OKEngine v0.14.9 and Hermes v0.21.3 (`v2026.9.14`).

Migration impact: none — runtime compatibility release only.

## 0.2.8 — 2026-09-27

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

Migration impact: new pages only. Pages already created without an `id` are NOT repaired by this
release; stamp them with OKEngine `backfill_ids` (a separate data repair). Existing pages keep
whatever id they carry.

## 0.2.7 — 2026-09-27

- concept-backfill now tells the model to finish with the receipt its selector prints and the
  runner verifies (okpacks-library#108). It never mentioned the receipt, so a run could not
  complete its per-item contract. The prompt adds the measured action directive and ends with the
  exact-receipt instruction the other receipt lanes carry: copy the selector's fenced
  `okengine-receipt` unchanged, account for every selected concept slug once, set each accepted
  write path, and leave `sha256` null for runner readback. The writer tool is unchanged
  (`converge_concept`).
- page-quality-enrich gains the same action directive and finishes with the selector's
  `okengine-receipt`, disposing every selected item exactly once, matching the wording the other
  packs already carry.

Migration impact: none — prompt text only. Deployments pick the prompts up on `framework pull
--update` + reconcile.

## 0.2.6 — 2026-09-27

- concept-backfill and source-quality-backfill now name the writer tool OKEngine actually grants
  each lane (okengine#664). concept-backfill told the model to call `create_entity` and
  source-quality-backfill to call `update_entity`, so every instructed write was refused and
  neither lane could write on a deployment of this pack. concept-backfill now writes through
  `converge_concept`. source-quality-backfill scores through `score_source` (reliability and
  credibility only, no body) and finishes with the selector's receipt. This is the wording the
  ai-research deployment runs and was verified against the live write server (okpacks-library#106).

Migration impact: none for stored pages. Deployments pick the prompts up on `framework pull
--update` + reconcile.

## 0.2.5 — 2026-09-27

- Require OKEngine v0.14.8 and Hermes v0.21.3 (`v2026.9.14`).

Migration impact: none — runtime compatibility release only.

## 0.2.4 — 2026-09-26

- Require OKEngine v0.14.7 and Hermes v0.21.3 (`v2026.9.14`).

Migration impact: none — runtime compatibility release only.

## 0.2.3 — 2026-09-23

- The weekly brief lane now declares `max_iterations: 12`. OKEngine's cron regen requires an
  integer `max_iterations >= 2` on every cost-bearing agent lane, so this pack at 0.2.2 failed the
  step a deploy runs, and a fresh install stopped at cron deploy (okpacks-library#103). The value
  matches what live deployments already run.

Migration impact: none — one additive field on one cron lane.

## 0.2.2 — 2026-09-19

- Require OKEngine v0.14.5 and Hermes v0.21.3 (`v2026.9.14`).

Migration impact: none — runtime compatibility release only.

## 0.2.1 — 2026-09-17

- Require OKEngine v0.14.4 and Hermes v0.21.3 (`v2026.9.14`).

Migration impact: none — runtime compatibility release only.

## 0.2.0 — 2026-07-19

- Emit annual security reports with the core `source_kind: report` vocabulary while retaining
  `source_channel: annual-report`, and add a drain for historic source-kind aliases.

- **Breaking**: type `vendor` renamed to `publisher` (standalone AND composing contract).
- rec-12 (okpacks#60): `report_theme`/`report_category`/`metric_direction`/`metric_unit` now compose via `subdomain/host-schema-additions.yaml`, so bundle vaults enforce them.
- This baseline establishes the okpacks#29 versioning convention (VERSIONING.md): it versions schema-contract changes that accumulated after the previous `version:` was set.

Migration impact: pages with `type: vendor` must be re-typed to `publisher` (the composed okcti deployment performed this migration at its bundle upgrade); then `framework validate` and let `corpus_audit` confirm zero drift.
