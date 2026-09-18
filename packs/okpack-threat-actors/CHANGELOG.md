# Changelog

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
