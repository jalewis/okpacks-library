# Pack versioning & schema migration (okpacks#29)

Every pack carries `version:` in its `pack.yaml`. This document defines what a version bump
means, when one is required, and where migration impact is recorded — so an operator updating
an installed pack can tell, before applying it, whether pages need migration, normalization,
re-indexing, or manual review. The rules are machine-checked by
`scripts/check_version_bumps.py` (run by `validate-all.sh` and CI).

## The schema contract

The parts of a pack that installed vaults and composed bundles depend on:

- `schema.yaml` — the standalone contract (types, required fields, enums, field_enums,
  partitioning, coverage_fields).
- `subdomain/host-schema-additions.yaml` — the composing contract (what travels into a bundle
  vault; see the okengine#281 compose checks).
- For `kind: bundle` packs: the `bundle:` block in `pack.yaml` (host + compose membership).

A change to any of these is a **schema-contract change** and requires a version bump in the
same merge request.

## Bump rules

Pre-1.0 (all packs today), the compatibility boundary is **MINOR** — the standard 0.x semver
convention:

| change | pre-1.0 bump | post-1.0 bump |
|---|---|---|
| **Breaking**: type removed/renamed; enum value removed/renamed; extensible field_enum made strict; new required field on an existing type; namespace/partitioning moved; bundle membership changed; owned namespace changed | **MINOR** | MAJOR |
| **Compatible**: new type; new optional field; new enum value; new field_enum; new lane/cron/extension wiring; cockpit/config changes; content/prompt/doc changes that touch the contract files | **PATCH** | MINOR |
| No contract change (content, prompts, fixtures, scripts, docs only) | PATCH *(optional)* | PATCH |

When one release accumulates both kinds, the breaking rule wins.

## Documenting a release

Every version gets a `## <version> — <date>` section in the pack's `CHANGELOG.md`
(machine-checked). A release whose bump touched the schema contract must state its
**migration impact** in that section — one of:

- `Migration impact: none — additive only.` (new types/fields/enum values; nothing existing
  changes meaning)
- A concrete migration note: which pages/fields are affected, what transforms them (a script,
  a drain lane, or manual steps), and what to verify afterward (`framework validate`,
  `corpus_audit`).

## Migration artifacts

- **Manual steps** live in the CHANGELOG section itself — short, imperative, verifiable.
- **Scripts and data artifacts** ship in `packs/<pack>/migrations/` (precedent:
  `okpack-threat-actors/migrations/type-taxonomy-v1.yaml`, a path→type re-map consumed by the
  reshelve tooling). Name data files `<slug>-v<N>.yaml`; name executable migrations with the
  engine's module contract (`m_<from>_<to>_<slug>.py`, `ID`/`FROM`/`TO`/`apply(pack, dry_run)`
  — see the engine's `migrations/README.md`) keyed on **pack** versions.
- **In an installed vault**, the engine's pack-local hook is `<vault>/.okengine/migrations/`:
  `framework upgrade --apply` executes `m_*.py` modules there with dry-run, snapshot, and
  roll-forward validation. Since **okengine#312**, *pack-version* migrations shipped in
  `packs/<pack>/migrations/` also run automatically on update: `framework pull --update`
  previews the pending span `(installed, incoming]` (surfacing each release's migration-impact
  line) and `--apply-migrations` performs it through the same snapshot / validation-gate /
  auto-rollback runner; `install-domain` over an existing member does the same for the guest's
  migrations under `--apply`.

## Operator update flow

1. `framework pull <pack> --update` (or re-run `install-domain` for a bundle member) — the
   update output previews any pending pack-version migrations and the CHANGELOG span's
   migration-impact lines.
2. Read that span; every schema-touching release states its migration impact.
3. Re-run with `--apply-migrations` (or `install-domain … --apply`) to execute shipped
   `m_*.py` migrations — snapshotted, validated, auto-rolled-back on failure. Apply any
   remaining *manual* steps the CHANGELOG names.
4. `framework validate <pack>` and let the next `corpus_audit` run confirm no drift.

## Enforcement

`scripts/check_version_bumps.py` fails validation when:

- **R1** — a schema-contract file changed after the commit that introduced the current
  `version:` (schema churn without a bump);
- **R2** — the current version has no `CHANGELOG.md` section;
- **R3** — the bump that shipped schema-contract changes has no migration-impact line.

The check reads git history, so CI runs it with `GIT_DEPTH: "0"`; on a truncated clone it
WARNs "undetectable" rather than passing vacuously.
