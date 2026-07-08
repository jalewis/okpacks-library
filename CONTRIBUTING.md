# Contributing a pack to okpacks-library

Thanks for bringing a pack idea. A pack is a small, declarative domain definition;
adding one is a PR that drops `packs/<your-pack>/` into this repo.

## What a contributed pack MUST be

- **A definition, not a deployment.** Ship the config + an **empty** `wiki/`
  scaffold. Do **not** commit compiled knowledge pages, a `.env`, or `.hermes-data/`.
- **Definitions only — no redistribution of source content.** Don't seed the vault
  with pages compiled from copyrighted feeds. Respect each source's license and any
  TLP / sensitivity marking. (See [`NOTICE`](NOTICE).)
- **Safe by default.** `feeds/feeds.opml` ships **empty** (curated sources go in
  `feeds/feeds.opml.example`), so a fresh install makes **zero upstream calls** until an
  operator opts in. Domain crons MAY ship `enabled: true` — but an enabled cron must use a
  `@jitter:*` schedule (expanded to a random minute per install) or an already-jittered
  non-`:00` minute, never a herd-prone fixed schedule (`0 * * * *`). The pack's own
  `validate.py` enforces this (`check_crons_jittered`). Ship a cron `enabled: false` only
  when it genuinely shouldn't run out of the box.
- **A real `pack.yaml`** — `name` / `version` / `trust: public` / `owns` (the **domain**
  types + namespaces it defines). The universal OKF core (types `source` / `concept` /
  `prediction` / `finding` / `dashboard` / `briefing` / `trend`; namespaces `entities` /
  `sources` / `concepts` / `predictions` / `findings` / `briefings` / `trends`) is
  **engine-owned and inherited by every pack** — do **not** declare or own it. To add a
  field to a core type, `extends:` it (additive + optional); a pack must not own or *tighten*
  a core type (`framework compose-preview` flags it). Packs that compose into one vault must
  own **disjoint** *domain* types/namespaces. See the engine's
  `docs/core-types-and-extensions.md`.
- **Permissively licensed** — the pack ships its own `LICENSE`.

## How to build one

1. Scaffold with OKEngine (the current skeleton, in seconds):
   ```sh
   python <okengine>/scripts/framework.py init packs/okpack-<domain> --domain "..."
   ```
2. Fill `schema.yaml` (your **domain** types only — the OKF core types are engine-owned and
   inherited, so don't re-declare them; to add a field to a core type, `extends:` it
   additively + optional — see the engine's `docs/core-types-and-extensions.md`), `CLAUDE.md`
   (persona + ingest workflow), and `feeds/feeds.opml.example` (suggested sources) — see the
   OKEngine [authoring guide](https://github.com/jalewis/okengine/blob/main/docs/authoring-a-pack.md).
3. Drop the deploy-only runtime bits `framework init` adds (`.hermes-data/`) — keep
   the definition. (Scaffolding via OKEngine's `templates/pack/new-pack.sh` skips them.)
4. `cd packs/okpack-<domain> && python3 validate.py` — the pack-local, offline
   gate; must pass.
   > **Note on `_pack_validate_lib.py`.** Each pack vendors a copy of the shared validator
   > library beside its `validate.py`. The **canonical source is
   > [`scripts/pack_validate_lib.py`](scripts/pack_validate_lib.py)** — edit THAT, never a
   > pack-local copy, then run `python3 scripts/sync-validate-lib.py` to re-vendor into every
   > pack. The copies exist so a pulled/deployed pack (just `packs/<name>/`, no repo-root
   > `scripts/`) can still self-validate. `scripts/validate-all.sh` (and CI) runs
   > `sync-validate-lib.py --check` and **fails on drift**. Your `validate.py` adds only
   > pack-specific config/checks (see `okpack-cti` for the rich example).
5. Run the engine's deeper validator (it's strict about real requirements — a
   pinned `engine.version` that matches the engine, a README with a Deploy
   section, a LICENSE, no unrendered `{{tokens}}`, well-shaped crons, …):
   ```sh
   python <okengine>/scripts/framework.py validate packs/okpack-<domain>
   ```
   It must report **0 FAIL** (inert-feeds / seeded-at-deploy WARNs are expected).
   The `engine_version` you pin must equal the engine you validated against.
6. **Register the pack in `catalog.json`** (the machine-readable index
   `framework pull` / `framework list` read — a README row alone leaves your pack
   invisible to the CLI). Append an entry:
   ```json
   {
     "name": "okpack-<domain>",
     "domain": "one-line description",
     "repo": "jalewis/okpacks-library",
     "subdir": "packs/okpack-<domain>",
     "ref": "main",
     "engine_version": "v0.2.0",
     "trust": "public",
     "status": "community",
     "validated_against": "v0.2.0"
   }
   ```
   `engine_version` = the pack's pin; `validated_against` = the engine release it
   passed `framework validate` against (normally the same). For a standalone-repo
   pack, set `repo` to that repo and `subdir` to `""`.
7. Add the human-readable row to [`packs/README.md`](packs/README.md) and the root
   [`README.md`](README.md) to match.
8. Open a PR. CI runs `okpacks validate` (every pack's `validate.py` + the library gate:
   catalog/cross-pack invariants, composition, and quality/fixture coverage) and `okpacks
   conformance`. Run them locally first — `scripts/okpacks bootstrap` does the whole path.

## Before anything ships (the pre-publish gauntlet)

Publishing to the public GitHub snapshot runs `scripts/publish-snapshot.sh`, which is
gated — a pack that fails any gate does not ship:

1. **validate-all** — every pack `framework validate` clean + the readiness bar for its
   catalog status (conformance suite + golden fixture per declared type, herd-safe
   feeds, engine pin).
2. **publish-parity** — the catalog's `engine_version` must equal the PUBLIC engine
   snapshot's release (publish order: engine → library; `PARITY_SKIP=1` only for a
   deliberate exception).
3. **deploy-matrix (offline tier)** — the engine's `scripts/deploy_matrix.py` over this
   library: compose-preview across every combo, and every co-install form applied into
   a fresh scratch host (assertions, idempotent re-apply, teardown). Needs `ENGINE_DIR`.

The matrix's LIVE tier (real docker stacks: pull → deploy.sh → post_deploy_verify →
teardown on success) is not part of the automatic gate — run it for any pack you
touched before requesting a publish:

```
python3 $ENGINE_DIR/scripts/deploy_matrix.py --live <pack-name>
```

Run the whole gauntlet locally any time (it stages to /tmp and never pushes):
`bash scripts/publish-snapshot.sh`.

## Standard / spec packs

A pack can also be a *standard* — shipping its own spec + conformance suite + projectors
alongside the definition. The flagship [`okpack-cti`](packs/okpack-cti) is the model:
`OKF-CTI-SPEC.md` (the normative profile), `conformance/` (validated against the standards'
official libraries), and `projectors/` (STIX 2.1 + OCSF). Such packs are welcome and vendored
like any other — just keep the spec/conformance with the pack and register it normally.
