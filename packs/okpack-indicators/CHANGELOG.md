# Changelog — okpack-indicators

All notable changes to this pack. Format loosely follows [Keep a Changelog].

[Keep a Changelog]: https://keepachangelog.com/

## 0.1.1 — 2026-07-19

- rec-12: `indicator_type`/`infra_type` enums now compose, so bundle vaults enforce them.
- This baseline establishes the okpacks#29 versioning convention (VERSIONING.md): it versions schema-contract changes that accumulated after the previous `version:` was set.

Migration impact: none — additive/compatible only.

## 0.1.0

Initial release (OKEngine v0.10.0) — a composable CTI pack in the okpack-sec bundle family.

### Added
- Atomic indicators (IOCs) + adversary infrastructure — abuse.ch URLhaus seed.
- Owned types + `schema.yaml` contract, STIX/legacy `type_aliases` (in `schema.yaml` and
  `subdomain/host-schema-additions.yaml`, so old names resolve when composed).
- One `no_agent` (zero-token) seed importer + a conformance suite with golden fixtures.
- Persona `CLAUDE.md` + docs; catalogued (`trust: public`).
