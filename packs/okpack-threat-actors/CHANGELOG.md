# Changelog

## 0.2.23 — 2026-10-18

- Require OKEngine v0.15.18 and retain the existing Hermes pin. Align the pack and
  catalog release bindings with the merged engine used for qualification.

Migration impact: Requires engine upgrade to v0.15.18; no stored-page migration.

## 0.2.22 — 2026-10-03

- Require OKEngine v0.15.3 and retain the existing Hermes pin. Align the pack and
  catalog release bindings with the merged engine used for qualification.

Migration impact: Requires engine upgrade to v0.15.3; no stored-page migration.

## 0.2.21 — 2026-10-03

Original cited reporting now overrides a generated actor profile when that named subject is
explicitly the victim and lacks independently supported adversarial identity. Shared writers,
actor roster eligibility, report/news maintenance, and the identity audit reuse the installed
engine source-role guard; authority metadata cannot bypass a source contradiction. Eligible
actors that are themselves victimized or deny one incident remain named mentions, without
implying responsibility. Supported schema actor type aliases are normalized before identity admission. Invalid UTF-8
source scans retain activity and report an error. Entity synthesis keeps victim and attacker
roles distinct.

Migration impact: no schema migration. Existing false actor records need separately reviewed,
authorized correction; this release does not automatically repair stored pages or accusations.

## 0.2.20

Migration impact: no schema migration. Existing false actor records and dependent mentions
require separately reviewed, authorized maintenance; this release does not repair stored data.

Actor news and report mentions now distinguish severity descriptions from named adversaries,
reuse the engine's negative actor-subject guard, and recompute owned activity fields to zero
when a complete scan has no remaining mentions. Unreadable sources retain prior activity
and fail the lane instead of silently clearing it. Retired actors cannot regain activity
through deterministic import/maintenance. Common and short names remain usable in actor
or tracked-operation context.


## 0.2.19 — 2026-10-01

- Require OKEngine v0.15.2 and Hermes v0.21.3 (`v2026.9.14`).

Migration impact: none — runtime compatibility release only.

## 0.2.18 — 2026-10-01

- `actor_news_activity` never stamps a page it could not read or parse. Its reader returns an
  empty body for an unreadable page (moved by a concurrent lane, a permission change), and
  `write_page` replaces the body, so the stamp erased the page's body (APT10 and APT41 on a live
  vault, 2026-10-01). A skipped stamp is logged and heals on the next run.

Migration impact: none. Restore any actor page whose body this lane emptied from a snapshot.

## 0.2.17 — 2026-09-29

- Require OKEngine v0.15.0 and Hermes v0.21.3 (`v2026.9.14`).
- The source helper (`crons/scripts/_okf_write.py`) treats a bare service endpoint URL (an ArcGIS
  `.../query` or `.../MapServer/<n>`, a Socrata `.../resource/<id>.json`, with no query string) as no
  source identity, matching the engine's write path (okengine#901).

Migration impact: new source pages only. A page already created with an endpoint-URL id keeps it.

## 0.2.16 — 2026-09-28

- Require OKEngine v0.14.9 and Hermes v0.21.3 (`v2026.9.14`).

Migration impact: none — runtime compatibility release only.

## 0.2.15 — 2026-09-27

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

## 0.2.14 — 2026-09-27

- concept-backfill now tells the model to finish with the receipt its selector prints and the
  runner verifies (okpacks-library#108). It never mentioned the receipt, so a run could not
  complete its per-item contract. The prompt adds the measured action directive and ends with the
  exact-receipt instruction the other receipt lanes carry: copy the selector's fenced
  `okengine-receipt` unchanged, account for every selected concept slug once, set each accepted
  write path, and leave `sha256` null for runner readback. The writer tool is unchanged
  (`converge_concept`).

Migration impact: none — prompt text only. Deployments pick the prompts up on `framework pull
--update` + reconcile.

## 0.2.13 — 2026-09-27

- raw-backfill, entity-backfill and page-quality-enrich carry the prompts the live okcti deployment
  runs. They were edited in place and never upstreamed, so a pack update would have regressed them
  (okengine#896, okpacks-library#107):
  - raw-backfill and entity-backfill work from the evidence the selector embeds and write through
    `converge_source` / `converge_entity`;
  - entity-backfill keeps the deployment's actor-classification rules (a company, victim or
    product is not an actor because reporting mentions it; `type: actor` needs `actor_type`);
  - page-quality-enrich finishes with the selector's receipt.

  Merged with the library's own changes: the measured action directives the prompt lint requires,
  the receipt fields named, the resolving-source wording, and "do not call any file-read, search,
  or listing tool" (these lanes keep the read toolset). concept-backfill and source-quality-backfill
  already carried the live fixes (#106). The dead `prediction-*` keys stay removed (okengine#562).

Migration impact: none — prompt text only.

## 0.2.12 — 2026-09-27

- concept-backfill and source-quality-backfill now name the writer tool OKEngine actually grants
  each lane (okengine#664). concept-backfill told the model to call `create_entity` and
  source-quality-backfill to call `update_entity`, so every instructed write was refused and
  neither lane could write on a deployment of this pack. concept-backfill now writes through
  `converge_concept`. source-quality-backfill scores through `score_source` (reliability and
  credibility only, no body) and finishes with the selector's receipt. This is the wording the
  ai-research deployment runs and was verified against the live write server (okpacks-library#106).

Migration impact: none for stored pages. Deployments pick the prompts up on `framework pull
--update` + reconcile.

## 0.2.11 — 2026-09-27

- Require OKEngine v0.14.8 and Hermes v0.21.3 (`v2026.9.14`).

Migration impact: none — runtime compatibility release only.

## 0.2.10 — 2026-09-26

- Require OKEngine v0.14.7 and Hermes v0.21.3 (`v2026.9.14`).

Migration impact: none — runtime compatibility release only.

## 0.2.9 — 2026-09-23

- The weekly brief lane now declares `max_iterations: 12`. OKEngine's cron regen requires an
  integer `max_iterations >= 2` on every cost-bearing agent lane, so this pack at 0.2.8 failed the
  step a deploy runs, and a fresh install stopped at cron deploy (okpacks-library#103). The value
  matches what live deployments already run.

Migration impact: none — one additive field on one cron lane.

## 0.2.8 — 2026-09-23

- Actor boards ("Recently active", "Actor movement"): the Total column is now **News total**, a
  new optional `news_total` field stamped by `actor_news_activity.py`: every news item that names
  the actor within its 180-day lookback, from the same matcher as `recent_news`. News can no
  longer exceed Total. The old column showed `total_mentions`, a different lane's count of
  report-tagged pages, and read News > Total on about half the rows. Captions now state both
  windows. `total_mentions` is unchanged and still on the actor profile.

Migration impact: none — additive only. `news_total` appears on each actor the next time the
news-activity lane stamps it.

## 0.2.7 — 2026-09-19

- Require OKEngine v0.14.5 and Hermes v0.21.3 (`v2026.9.14`).

Migration impact: none — runtime compatibility release only.

## 0.2.6 — 2026-09-17

- Require OKEngine v0.14.4 and Hermes v0.21.3 (`v2026.9.14`).

Migration impact: none — runtime compatibility release only.

## 0.2.5 — 2026-08-28

- Rank the Actor cockpit by the validated `date` field, with the actor title as the
  deterministic tie-breaker. The displayed news count remains informational and no longer
  allows noisy or malformed source matches to promote an actor above better-grounded rows.

Migration impact: none. Rebuild the generated cockpit after deployment so its ordering uses the
new ranking contract.

## 0.2.4 — 2026-08-27

- Declare assessed-origin country labels as exact actor-identity exclusions. The enforced write
  path rejects new matches, while the actor-identity audit tombstones legacy country pages without
  rejecting legitimate actor names that merely contain geography.

Migration impact: the deterministic actor-identity audit tombstones live actor pages whose entire
normalized title equals a configured country label. Run the audit with `--apply`, then verify with
`framework validate` and `corpus_audit`.

## 0.2.3 — 2026-08-08

- Add a `Campaigns` board to the adversaries page. Campaigns are first-class entities but nothing
  surfaced them: the page counted them in `Roster pulse` and showed them nowhere. The board lists
  campaign, attributed actor, proposed actor, and last-seen date.
- Columns use the cockpit's `ref_link` rather than `link: true`. The latter links the ROW's page and
  ignores the column's field, which rendered the campaign's own name in three consecutive columns;
  `ref_link` names and links the ACTOR at the other end of the relationship.
- Sorted attributed-first rather than by date. Most campaigns carry no `last_seen`, so a date sort
  ordered them arbitrarily and buried every campaign holding the actor edge a reader comes for.
  Undated campaigns rank last, never hidden.

## 0.2.2 — 2026-07-23

- Add a human-maintained review policy for Cisco Talos primary technical research and
  BleepingComputer/The Hacker News corroborating reporting. Model-assigned source-page grades
  remain ineligible to clear review by themselves.

## 0.2.1 — 2026-07-20

- Harden the `entity-backfill` agent lane prompt to prevent ungrounded fabrication: grounding is
  mandatory (every claim must trace to a digest/vault source; emit no page rather than a fabricated
  one), never invent `source/<vendor>/<slug>` citations or numeric/invented aliases, dedupe on
  attack_id + common aliases, and write only schema-declared fields (no ad-hoc narrative frontmatter).
  Fixes a cohort of hallucinated actor pages (APT35 mislabelled Israeli, invented actors) on composed
  CTI vaults. Enforcement half is okengine#348 (write-path guard rejecting non-existent source refs).

## 0.2.0 — 2026-07-19

## 0.2.0 — 2026-07-19

- Accept direct MITRE ATT&CK records under a strict, auditable authority policy instead of
  automatically sending every imported actor and technique to human review.
- Add a conservative reconciliation lane for existing actor pages with claim-matched primary
  government advisories; news-only and conflicted claims remain review-gated.

- Route deterministic importer merges through the engine importer guard and add a conservative
  drain for legacy free-text `attribution_confidence` values.
- Upgrade the actor-evidence export to contract v2, separating exact claim-specific country-nexus
  citations from publisher-level context and adding stable evidence-origin identifiers without
  asserting source independence or lineage.

- **Breaking**: `tactic` enum re-mapped — `defense-evasion` removed; `defense-impairment` and `stealth` added.
- `source_kind` enum extended with `community-reporting`, `vendor-research`.
- This baseline establishes the okpacks#29 versioning convention (VERSIONING.md): it versions schema-contract changes that accumulated after the previous `version:` was set.

Migration impact: pages carrying `tactic: defense-evasion` must be re-mapped to `defense-impairment` (defensive-tooling tampering) or `stealth` (hiding/obfuscation); `migrations/type-taxonomy-v1.yaml` is the existing path→type re-map artifact for the reshelve tooling. Verify with `framework validate` + the next `corpus_audit`.
