# Changelog

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
