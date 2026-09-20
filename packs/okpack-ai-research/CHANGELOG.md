# Changelog

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
