# Changelog

## 0.1.2 — 2026-09-17

- Require OKEngine v0.14.4 and Hermes v0.21.3 (`v2026.9.14`).

Migration impact: none — runtime compatibility release only.

## 0.1.1 — 2026-07-19

- VEX/asset-assessment field_enums (`applicability`/`asset_exposure`/`business_criticality`) added standalone (deliberately `compose_exempt` — asset posture is not shared threat-intel).
- `exploitation_status` gained `unknown`; `severity`/`exploitation_status` now compose strictly.
- This baseline establishes the okpacks#29 versioning convention (VERSIONING.md): it versions schema-contract changes that accumulated after the previous `version:` was set.

Migration impact: none — additive/compatible only.
