# Changelog — okpack-incidents

All notable changes to this pack. Format loosely follows [Keep a Changelog].

[Keep a Changelog]: https://keepachangelog.com/

## 0.1.0

Initial release (OKEngine v0.10.0) — a composable CTI pack in the okpack-sec bundle family.

### Added
- Security incidents + identities — VERIS Community Database seed.
- Owned types + `schema.yaml` contract, STIX/legacy `type_aliases` (in `schema.yaml` and
  `subdomain/host-schema-additions.yaml`, so old names resolve when composed).
- One `no_agent` (zero-token) seed importer + a conformance suite with golden fixtures.
- Persona `CLAUDE.md` + docs; catalogued (`trust: public`).
