# Changelog

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

