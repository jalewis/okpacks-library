# Changelog

## 0.1.13 — 2026-10-18

- Require OKEngine v0.15.18 and retain the existing Hermes pin. Align the pack and
  catalog release bindings with the merged engine used for qualification.

Migration impact: Requires engine upgrade to v0.15.18; no stored-page migration.

## 0.1.12 — 2026-10-03

- Require OKEngine v0.15.3 and retain the existing Hermes pin. Align the pack and
  catalog release bindings with the merged engine used for qualification.

Migration impact: Requires engine upgrade to v0.15.3; no stored-page migration.

## 0.1.11 — 2026-10-01

- Require OKEngine v0.15.2 and Hermes v0.21.3 (`v2026.9.14`).

Migration impact: none — runtime compatibility release only.

## 0.1.10 — 2026-09-29

- Require OKEngine v0.15.0 and Hermes v0.21.3 (`v2026.9.14`).

Migration impact: none — runtime compatibility release only.

## 0.1.9 — 2026-09-28

- Require OKEngine v0.14.9 and Hermes v0.21.3 (`v2026.9.14`).

Migration impact: none — runtime compatibility release only.

## 0.1.8 — 2026-09-27

- concept-backfill now tells the model to finish with the receipt its selector prints and the
  runner verifies (okpacks-library#108). It never mentioned the receipt, so a run could not
  complete its per-item contract. The prompt adds the measured action directive and ends with the
  exact-receipt instruction the other receipt lanes carry: copy the selector's fenced
  `okengine-receipt` unchanged, account for every selected concept slug once, set each accepted
  write path, and leave `sha256` null for runner readback. The writer tool is unchanged
  (`converge_concept`).

Migration impact: none — prompt text only. Deployments pick the prompts up on `framework pull
--update` + reconcile.

## 0.1.7 — 2026-09-27

- Upstream the lane prompts the live deployment of this pack was edited to run, merged with the
  library's own fixes since, so the next pack update does not regress it (okengine#896).
  raw-backfill and entity-backfill work from the evidence the selector embeds: raw-backfill
  writes one source page per selected raw through `converge_source` (identity is the URL, so it
  no longer searches for duplicates) and entity-backfill writes the single best-supported entity
  through `converge_entity`, citing its resolving source. Both keep the measured action
  directives, the staged-boundary rules, and the selector's receipt with the runner-owned
  identity fields unchanged and `sha256` left for readback. page-quality-enrich now disposes
  every selected item and finishes with the selector's receipt. concept-backfill takes the
  deployment's domain wording for the entity-not-concept skip.

Migration impact: none — prompt text only. Deployments pick the prompts up on `framework pull
--update` + reconcile.

## 0.1.6 — 2026-09-27

- concept-backfill and source-quality-backfill now name the writer tool OKEngine actually grants
  each lane (okengine#664). concept-backfill told the model to call `create_entity` and
  source-quality-backfill to call `update_entity`, so every instructed write was refused and
  neither lane could write on a deployment of this pack. concept-backfill now writes through
  `converge_concept`. source-quality-backfill scores through `score_source` (reliability and
  credibility only, no body) and finishes with the selector's receipt. This is the wording the
  ai-research deployment runs and was verified against the live write server (okpacks-library#106).

Migration impact: none for stored pages. Deployments pick the prompts up on `framework pull
--update` + reconcile.

## 0.1.5 — 2026-09-27

- Require OKEngine v0.14.8 and Hermes v0.21.3 (`v2026.9.14`).

Migration impact: none — runtime compatibility release only.

## 0.1.4 — 2026-09-26

- Require OKEngine v0.14.7 and Hermes v0.21.3 (`v2026.9.14`).

Migration impact: none — runtime compatibility release only.

## 0.1.3 — 2026-09-19

- Require OKEngine v0.14.5 and Hermes v0.21.3 (`v2026.9.14`).

Migration impact: none — runtime compatibility release only.

## 0.1.2 — 2026-09-17

- Require OKEngine v0.14.4 and Hermes v0.21.3 (`v2026.9.14`).

Migration impact: none — runtime compatibility release only.

## 0.1.1 — 2026-07-19

- Comment-only contract edits (okpack-sec → okpack-cti references).
- This baseline establishes the okpacks#29 versioning convention (VERSIONING.md): it versions schema-contract changes that accumulated after the previous `version:` was set.

Migration impact: none — additive/compatible only.
