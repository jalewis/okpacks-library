# okpacks-library — the OKEngine pack library

[![validate packs](https://github.com/jalewis/okpacks-library/actions/workflows/ci.yml/badge.svg)](https://github.com/jalewis/okpacks-library/actions/workflows/ci.yml)
![status: pre-1.0, active](https://img.shields.io/badge/status-pre--1.0%20active-orange)
![license: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)

A community catalog of **[OKEngine](https://github.com/jalewis/okengine) domain
packs** — each a *definition* you deploy to stand up your own agent-maintained
knowledge vault. **okpacks** is short for **Open Knowledge Packs**.

## What's in here (definitions, not vaults)

A pack is the domain layer OKEngine builds a vault from: a `schema.yaml` (types +
rules), a `CLAUDE.md` persona, feed sources, and crons. **This library holds pack
DEFINITIONS only — with empty `wiki/` scaffolds.** You take a definition, point
OKEngine at it, and it grows *your* vault from the sources *you* enable.

> **Why definitions only?** The compiled `wiki/` content is derived from the feeds a
> pack ingests (papers, advisories, news), so redistributing it is a source-licensing
> problem. Definitions are config — share them freely; the knowledge each deployment
> produces belongs to (and is the responsibility of) the operator. See [`NOTICE`](NOTICE).

## Use a pack

OKEngine ships a **`framework` CLI** (`scripts/framework.py` in your engine
checkout) that pulls packs straight from this catalog — no manual copying. It
defaults to **this library**, so the commands below need no extra config.

```sh
git clone https://github.com/jalewis/okengine        # the engine (provides framework)
FW="python okengine/scripts/framework.py"            # framework entrypoint

$FW list                              # browse the catalog (this library by default)
$FW pull okpack-sec ./my-vault        # fetch a pack definition into ./my-vault
$FW validate ./my-vault               # sanity-check before deploying
```

`pull` strips any runtime, checks the pack's `engine.version` pin, runs
`framework validate`, and leaves the pack **inert** (empty active feeds, crons
disabled) — it never deploys or enables anything. Then fill in `.env`, enable the
sources you want, and bring it up per the pack's own README / the OKEngine
[authoring guide](https://github.com/jalewis/okengine/blob/main/docs/authoring-a-pack.md).

### `pull` source forms

| Source | Resolves to |
|---|---|
| `okpack-sec` | a catalog name (via this library's [`catalog.json`](catalog.json)) |
| `okpacks-library:okpack-sec` | the monorepo subdir `packs/okpack-sec` |
| `owner/repo` | a standalone pack repo |
| `owner/repo:packs/okpack-sec` | a subdir of any repo |
| `https://…` / `git@…` | an explicit git URL |

Useful flags: `--ref <branch|tag>`, `--port-offset N` (shift reader/MCP host ports
to avoid collisions), and `--update` (refresh a deployed pack in place — keeps your
`.env`/runtime/content and writes changed definition files as `<file>.upstream` for
a manual merge). Point at a different catalog with `--catalog URL|PATH` or the
`OKENGINE_CATALOG` env var.

### Or scaffold / copy by hand

```sh
$FW init packs/okpack-mydomain --domain "..."        # scaffold a NEW pack from the skeleton
cp -r okpacks-library/packs/okpack-example ../my-vault   # …or copy a catalog pack and edit
```

Each pack pins an `engine.version`; bring it up per the OKEngine authoring guide.

## Catalog

| Pack | Domain | Status |
|---|---|---|
| [`okpack-example`](packs/okpack-example) | generic starter (the skeleton shape) | example |
| [`okpack-ai-research`](packs/okpack-ai-research) | AI / LLM research watch — models, labs, techniques, benchmarks, predictions | community |
| **[`okpack-sec`](packs/okpack-sec)** | security / threat-intel, STIX-aligned — the `OKF-SEC` standard (spec + conformance + STIX/OCSF projectors) | flagship |

okpack-sec is the flagship: a full standard — its own [`OKF-SEC-SPEC.md`](packs/okpack-sec/OKF-SEC-SPEC.md),
a conformance suite, and STIX 2.1 + OCSF projectors — vendored here as the reference pack.

## Running the checks locally

One CLI fronts everything — [`scripts/okpacks`](scripts/okpacks):

```sh
scripts/okpacks bootstrap     # one-shot: venv + dev deps + the FULL CI path (validate + conformance)
scripts/okpacks validate      # per-pack validation + the library gate (offline, fast)
scripts/okpacks library       # catalog + cross-pack invariants only (names, cron IDs, engine pins)
scripts/okpacks conformance    # every pack's conformance suite  (add --strict to fail on degraded)
scripts/okpacks quality       # pack readiness scoring + golden-fixture coverage (by status)
scripts/okpacks probe-feeds   # NETWORK feed health: status/redirects/latency (--json/--md to save a report)
scripts/okpacks changes       # flag a pack contract change missing a CHANGELOG update (vs origin/main)
scripts/okpacks help          # full command list
```

`probe-feeds` and `changes` are the non-offline checks: `probe-feeds` HTTP-probes each pack's
curated `feeds.opml.example` and (optionally) writes a JSON/Markdown health report — run it manually
or on a schedule, it's kept out of `validate` so offline validation stays deterministic. `changes`
is a pre-merge guard that flags a pack whose contract (`schema.yaml`/`pack.yaml`/`CLAUDE.md`/spec/
projectors) changed without a `CHANGELOG.md` update.

`bootstrap` is the new-contributor path: it creates `.venv`, installs
[`requirements-dev.txt`](requirements-dev.txt) (PyYAML + the official standards validators
`stix2` + `py-ocsf-models`), and runs the same checks CI does. Dependencies are declared in
[`requirements.txt`](requirements.txt) (runtime) and `requirements-dev.txt` (adds the conformance
validators). Without the dev deps, conformance runs **degraded** (structural + golden only) and
says so loudly; `--strict` (CI uses it) makes a missing validator fail instead of warn.

`validate` runs each pack's `validate.py`, the vendored-lib sync check, **and** the library gate
([`validate-library.py`](scripts/validate-library.py)) — catalog↔pack consistency plus cross-pack
invariants (unique pack names + cron IDs, engine-pin coherence, dep metadata) that per-pack
validators can't see.

## Contribute

New pack ideas welcome — see [`CONTRIBUTING.md`](CONTRIBUTING.md). In short: scaffold
with OKEngine, fill schema + persona + feeds, ship it **inert** (empty active feeds,
crons disabled), **definitions only** (no compiled content), and open a PR adding
`packs/<your-pack>/`. CI runs each pack's `validate.py`.

## License

Pack definitions: [Apache-2.0](LICENSE) (unless a pack ships its own). Generated vault
content is the operator's responsibility — see [`NOTICE`](NOTICE).
