# AI / LLM Research Watch — domain pack

Domain pack for running an OKEngine/OKF knowledge vault that watches AI and LLM
research. It pulls public RSS/Atom feeds, stages raw items, and uses the engine's
curation lanes to compile them into source, entity, concept, prediction, and
dashboard pages.

This pack is already domain-filled. It pins its target OKEngine release and Hermes tag
in `engine.version`.

**It runs out of the box** but makes zero upstream calls until you add feeds (crons
enabled + jittered, feed list empty). See [§Useful by default](#useful-by-default-herd-safe-by-design).

## What it builds

- A compounding AI/LLM research wiki for a senior ML practitioner.
- `source` pages for ingested papers, lab posts, and commentary.
- Long-lived `model`, `lab`, `researcher`, `benchmark`, `dataset`, `technique`,
  and `concept` pages.
- Conservative, dated `prediction` pages only when there is a falsifiable claim.
- A weekly dashboard brief generated from the current hot set.

See `wiki/examples/page-shapes.md` for example page shapes.

## Useful by default, herd-safe by design

The pack **runs out of the box** but stays inert toward upstreams until you add feeds —
crons ship enabled, the feed list ships empty, so a fresh install makes **zero upstream
calls** until you populate `feeds/feeds.opml`:

- **Crons ship enabled, jittered.** `crons/domain-crons.json` carries `@jitter:*`
  schedules expanded to a **random minute** per install by `framework init`/`pull`, so
  deployments don't synchronize once feeds are live.
- **No active sources yet.** `feeds/feeds.opml` is empty (`feed-fetch` no-ops cleanly
  until you fill it); the 16 suggested AI-research feeds live in `feeds/feeds.opml.example`.

`validate.py` enforces the herd-safe invariant (an enabled cron must use a `@jitter:*`
sentinel or a non-:00 minute — a committed round schedule fails the check).

### Going live: populate the feed list

> **⚠️ Populating feeds turns on LLM spend.** Empty feeds = ~free (ingest crons are
> wake-gated). Once feeds flow, the agent compiles each item 24/7 — cost scales with
> feed volume; `$0` on a local/free model, real money on a paid API. Add a few feeds
> first, watch your provider dashboard, and **set a budget cap at your provider** (no
> built-in spend limit). Estimates + controls: the engine's
> [`docs/operating-cost.md`](https://github.com/jalewis/okengine/blob/main/docs/operating-cost.md).

The crons are already running, so this one step turns ingest on: review
`feeds/feeds.opml.example`, copy the `<outline>` entries you want into `feeds/feeds.opml`,
and re-probe first: `python3 validate.py --probe` (suggested feeds last probed live
2026-06-16). To retune cadence, edit the schedules in `crons/domain-crons.json` (keep a
non-:00 minute).

## Requirements

- Docker Compose.
- An OKEngine checkout compatible with the release pinned in `engine.version`.
- API key for at least one configured model provider in `.env`.
- A UID/GID that can write this pack directory from containers. The compose file
  defaults to `10000:10000`; adjust if your host uses a different runtime user.

This repository does not vendor OKEngine. Clone or unpack OKEngine separately,
then set `ENGINE_DIR` to that checkout:

```sh
export ENGINE_DIR=/absolute/path/to/OKEngine
```

The engine repo contains the full domain-pack spec and deployment details in
`docs/deploy-a-new-domain.md`. This README only covers the pack-specific path.

## Quickstart

**Get this pack** (skip if you already have it checked out): it's published in the
[okpacks-library](https://github.com/jalewis/okpacks-library) catalog — pull it into a
fresh vault dir with the engine's `framework` CLI, which checks the `engine.version`
pin, validates, and leaves the pack **inert** (empty active feeds, crons disabled):

```sh
python <okengine>/scripts/framework.py pull okpack-ai-research ./okpack-ai-research   # defaults to this catalog
cd ./okpack-ai-research
```

Then, from the pack dir:

1. Copy the environment template and fill in the values you use:

   ```sh
   cp .env.example .env
   ```

2. Export the engine path and runtime user:

   ```sh
   export ENGINE_DIR=/absolute/path/to/OKEngine
   export HERMES_UID=10000
   export HERMES_GID=10000
   ```

3. Build the engine gateway image from the engine checkout:

   ```sh
   bash "$ENGINE_DIR/scripts/build-engine-image.sh"
   ```

4. Start the pack services:

   ```sh
   ENGINE_DIR="$ENGINE_DIR" docker compose up -d
   ```

5. Deploy pack cron scripts and jobs into the engine runtime:

   ```sh
   CRON_PACK_DIR="$(pwd)" bash "$ENGINE_DIR/scripts/deploy-cron-scripts.sh"
   CRON_PACK_DIR="$(pwd)" bash "$ENGINE_DIR/scripts/deploy-cron-plus-jobs.sh"
   ```

6. Open the reader service:

   ```text
   http://localhost:9300
   ```

The MCP service listens on `http://localhost:8830`. `OKENGINE_MCP_TOKEN` ships **blank**
(loopback needs no token); generate and set a real token (e.g. `openssl rand -hex 32`)
before exposing it (`OKENGINE_BIND=0.0.0.0`) — never expose it with a shared/default token.

> **Default ports.** This pack ships a `port_offset: 100` (declared in `pack.yaml`),
> so it publishes the reader on **9300** and MCP on **8830** by default — chosen to
> run alongside other local stacks (e.g. one on 9200/8730). `framework pull` applies
> the offset automatically; a plain `git clone` + `docker compose up` also lands here.

> **Local-first networking.** The reader (9300) and MCP (8830) host ports bind to
> **127.0.0.1** by default — reachable only from this machine. To expose them on the
> LAN, set `OKENGINE_BIND=0.0.0.0` in `.env` (a deliberate choice) **and** set a real
> `OKENGINE_MCP_TOKEN` / `OKENGINE_READER_PASSWORD` first.

> **Search readiness.** The reader's keyword search (9300) works as soon as the
> service is up. The MCP `search` tool returns *semantic* (vector) results only once
> the engine has built and embedded its qmd index over the vault; until then it falls
> back to keyword (BM25). Index build/refresh is an engine concern — see the engine's
> `docs/kb-tooling.md`.

## Ingest flow

The feed-fetch cron in `crons/domain-crons.json` ships disabled; once you enable it
(see [§Enabling the cron fleet](#enabling-the-cron-fleet)) it calls
`crons/scripts/okpack_ai_research_feed_fetch.py`, which wraps the engine's
deployed `feed_fetch.py` helper and writes new raw markdown items under
`raw/ai/`.

Two no_agent crons seed the vault directly (ZERO LLM tokens), both bounded + curated
(reference catalogs, not feed mirrors) and CREATE-if-absent (they never overwrite an
agent-curated page — the ingest agent enriches the seeds from sources):

- `crons/scripts/okpack_ai_research_hf_import.py` — `model` pages for a **bounded top-N of
  notable Hugging Face models** (sorted by likes, the frontier signal).
- `crons/scripts/okpack_ai_research_hf_papers_import.py` — `source`/paper pages from
  **Hugging Face Daily Papers** (upvote-curated; the live successor to Papers With Code).

A per-paper *arXiv* importer is deliberately NOT shipped — that firehose stays in the
RSS→agent lane above; the HF surfaces above are the bounded, high-signal slices.

The engine's standard backfill/drain lanes then use the prompts in
`crons/engine-template-prompts.json` to compile raw items into `wiki/` through
the MCP write path. The important lane for fresh feed items is `raw-backfill`.
It creates one `source` page per raw item, updates long-lived entities and
concepts when warranted, and only files predictions for explicit dated claims.

`CLAUDE.md` is the domain contract those agents read at runtime. It defines the
voice, triage rules, and prediction standards. The pack intentionally tells
agents to stay local-only during curation: use staged feed/source content, not
live web search.

## Validation

The pack ships an offline, dependency-light gate (parse + cross-consistency +
the safe-default invariant):

```sh
python3 validate.py            # parse + cross-consistency checks (offline)
python3 validate.py --fix      # repair the feeds.opml.example count comment if it drifted
python3 validate.py --probe    # HTTP-probe the suggested feeds in feeds.opml.example (network)
```

The pack also ships a conformance suite (run in CI by `scripts/conformance-all.sh`):

```sh
python3 conformance/test_pages.py      # golden pages conform to schema (required fields + enums)
python3 conformance/test_importers.py  # the Hugging Face importer's transforms + minted-page conformance
```

For the deeper, engine-aware checks (pin matches the engine, README deploy
section, LICENSE, well-shaped crons), run the engine's validator against this
pack dir:

```sh
python3 "$ENGINE_DIR/scripts/framework.py" validate .
```

## Layout

The pack dir **is** the OKF vault. Engine mechanics (deploy steps, the full
domain-pack spec) live in `docs/deploy-a-new-domain.md` in the OKEngine repo
(at the release pinned in `engine.version`); the pack-specific orientation is here.

| Path | Holds |
|------|-------|
| `schema.yaml` | OKF type contract: page types, partitioning, hot/warm/cold tiers, write permissions. |
| `CLAUDE.md` | Domain persona + ingest/curation workflow the cron agents read at runtime. |
| `feeds/feeds.opml` | ACTIVE RSS/Atom sources — **empty by default** (safe; opt in to enable). |
| `feeds/feeds.opml.example` | 16 suggested AI-research sources, grouped by source type; copy entries into `feeds.opml` to opt in. |
| `crons/` | `domain-crons.json` (pack cron defs, **enabled + jittered**), `engine-template-prompts.json` (drain-lane prompts), `scripts/` (feed-fetch wrapper + the Hugging Face model & daily-papers importers). |
| `validate.py` | offline parse + cross-consistency + safe-default gate (run in CI). |
| `conformance/` | golden page-shapes + the importer test suite (run by `scripts/conformance-all.sh`). |
| `wiki/entities/` | `model` / `lab` / `researcher` / `benchmark` / `dataset` pages (by-letter shards). |
| `wiki/concepts/` | `technique` / `concept` pages — methods, architectures, research themes. |
| `wiki/sources/` | `source` pages, one per ingested item (by-date shards). |
| `wiki/predictions/` | falsifiable, dated `prediction` pages. |
| `wiki/dashboards/` | generated digests (e.g. the weekly brief); excluded from OKF processing. |
| `wiki/operational/` | engine-internal operational pages; excluded from OKF processing. (The derived `wiki/HOT.md` load-set and `wiki/log.md` run log live at the `wiki/` root.) |
| `raw/` | feed-fetch staging (pack root, outside `wiki/`); the ingest cron compiles it into `wiki/`. Runtime-generated. |
| `.hermes-data/` | engine runtime state mounted at `/opt/data` (deployed cron scripts, feed state). Not committed. |

## Troubleshooting

- `docker compose` cannot find `../engine`: set `ENGINE_DIR` to your OKEngine
  checkout. The `../engine` path is only a local default.
- Containers start but cannot write runtime state: set `HERMES_UID` and
  `HERMES_GID` to a user/group with write access to this directory.
- Feeds are fetched but the wiki stays empty: confirm the engine backfill/drain
  jobs were deployed and that `raw-backfill` is enabled in the engine cron
  configuration.
- Weekly briefs are empty: build or refresh `wiki/HOT.md` through the engine
  hot-set job before the weekly brief runs.
