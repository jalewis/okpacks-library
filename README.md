# okpacks-library — the OKEngine pack library

[![validate packs](https://github.com/jalewis/okpacks-library/actions/workflows/ci.yml/badge.svg)](https://github.com/jalewis/okpacks-library/actions/workflows/ci.yml)
![status: pre-1.0, active](https://img.shields.io/badge/status-pre--1.0%20active-orange)
![license: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)

A community catalog of **[OKEngine](https://github.com/jalewis/okengine) domain
packs** — each a *definition* you deploy to stand up your own agent-maintained
knowledge vault. **okpacks** is short for **Open Knowledge Packs**.

## What's in here (definitions, not vaults)

A pack is the **domain layer** OKEngine builds a vault from: a `schema.yaml` (domain page types +
rules), a `CLAUDE.md` persona, feed sources, and crons. The universal OKF core (`source` / `concept`
/ `finding` types; the `entities` / `sources` / … namespaces) is engine-owned and inherited, so a
pack declares only what's specific to its domain. **The library ships definitions only — with empty
`wiki/` scaffolds**; you point OKEngine at one and it grows *your* vault from the sources *you* enable.

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
$FW pull okpack-cti ./my-vault        # fetch a pack definition into ./my-vault
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
| `okpack-cti` | a catalog name (via this library's [`catalog.json`](catalog.json)) |
| `okpacks-library:okpack-cti` | the monorepo subdir `packs/okpack-cti` |
| `owner/repo` | a standalone pack repo |
| `owner/repo:packs/okpack-cti` | a subdir of any repo |
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
| [`okpack-competitive`](packs/okpack-competitive) | competitive / market intelligence | flagship-generic |
| [`okpack-ai-research`](packs/okpack-ai-research) | AI / LLM research watch — models, labs, methods, benchmarks, predictions | community |
| [`okpack-vendor-risk`](packs/okpack-vendor-risk) | vendor / supply-chain risk — vendors, components, contracts, incidents | community |
| **[`okpack-cti`](packs/okpack-cti)** | **security / threat-intel BUNDLE** (STIX-aligned) — composes the six CTI packs below | bundle |
| [`okpack-threat-actors`](packs/okpack-threat-actors) | adversary graph — actor/campaign/malware/tool/technique from ATT&CK + MISP + CERT/vendor reporting; ships the STIX 2.1 / OCSF projectors | community |
| [`okpack-vuln`](packs/okpack-vuln) | actively-exploited CVEs (the composability seam) — CISA KEV + NVD | community |
| [`okpack-threat-landscape`](packs/okpack-threat-landscape) | annual-report landscape — metrics + publishers, theme trends | community |
| [`okpack-indicators`](packs/okpack-indicators) | atomic IOCs + adversary infrastructure — abuse.ch URLhaus | community |
| [`okpack-detections`](packs/okpack-detections) | detections + ATT&CK mitigations — SigmaHQ (technique-coverage seam) | community |
| [`okpack-incidents`](packs/okpack-incidents) | security incidents + identities — VERIS Community Database | community |

### Composition & bundles

The security packs demonstrate **composition** (OKEngine v0.10.8): each owns a disjoint slice of
types, and the library enforces globally-unique type ownership so any set composes into one vault.
**`okpack-cti` is a bundle** (`kind: bundle`) — it owns nothing and declares a recipe that composes
the six CTI packs. `framework pull okpack-cti` fetches the host (`okpack-threat-actors`) as the base
vault, then `install-domain`s the rest onto it — one command, the full STIX-aligned security KB, with
STIX/legacy type names resolving to the friendly canonical types via each pack's `type_aliases`. See
[`packs/okpack-cti/README.md`](packs/okpack-cti/README.md).

> **Renamed (was `okpack-sec`).** Through v0.10.8 this bundle was published as `okpack-sec`; it was
> renamed to `okpack-cti` because it composes the *cyber-threat-intelligence* packs specifically —
> other security packs (e.g. [`okpack-vendor-risk`](packs/okpack-vendor-risk)) sit outside it. Update
> any `framework pull okpack-sec` to **`framework pull okpack-cti`**; the old name no longer resolves.

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
