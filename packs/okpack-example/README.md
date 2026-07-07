# okpack-example — example knowledge vault

Agent-curated example knowledge vault for the OKEngine framework — ingests open feeds into a compounding, cross-linked knowledge graph.

Pinned to engine **okengine v0.8.0** (see `engine.version`).

- **Domain voice + ingest/curation workflow:** `CLAUDE.md` (read at runtime by the cron agents).
- **Machine-readable contract:** `schema.yaml` (page types, partitioning, hot-set, permissions, review, tier).

> **Ops.** Pin per-lane models in `<deploy>/.okengine/cron-models.json`; cron hours run in the
> gateway TZ (engine default UTC — set `TZ` in `.env`).

## Layout

```
schema.yaml              domain contract the engine reads (types, partitioning, perms, tier)
CLAUDE.md                persona + ingest/curation rules the cron agents follow
engine.version           engine pin (okengine v0.8.0)
feeds/feeds.opml         ACTIVE sources — EMPTY by default (safe; opt in to enable)
feeds/feeds.opml.example suggested sources (copy entries to opt in)
crons/                   domain cron defs (enabled + jittered) + ingest-lane prompts + scripts
docker-compose.yml       gateway + okengine-reader + okengine-mcp
.env.example             secrets & delivery (copy to .env; never commit)
validate.py              offline parse + cross-consistency checks (run in CI)
wiki/                    the vault (THE product) — populated by ingest
raw/                     runtime: feed_fetch output (gitignored)
```

## Useful by default, herd-safe by design

**The pack runs out of the box but stays inert toward upstreams until you add feeds.**
Crons ship enabled; the feed list ships empty, so a fresh install makes **zero upstream
calls** until you populate `feeds/feeds.opml`:

- **Crons ship enabled, jittered.** `crons/domain-crons.json` carries `@jitter:*`
  schedules expanded to a **random minute** per install by `framework init`/`pull`, so
  deployments don't synchronize once feeds are live.
- **No active sources yet.** `feeds/feeds.opml` is empty (`feed-fetch` no-ops cleanly
  until you fill it); suggestions live in `feeds/feeds.opml.example`.

`validate.py` enforces the herd-safe invariant (an enabled cron must use a `@jitter:*`
sentinel or a non-:00 minute — a committed round schedule fails CI).

### Going live: populate the feed list

> **⚠️ Populating feeds turns on LLM spend.** Empty feeds = ~free (ingest crons are
> wake-gated). Once feeds flow the agent compiles each item 24/7 — `$0` on a
> local/free model, real money on a paid API. Set a budget cap at your provider (no
> built-in spend limit). See the engine's `docs/operating-cost.md`.

The crons are already running, so this one step turns ingest on: review
`feeds/feeds.opml.example`, copy the `<outline>` entries you want into `feeds/feeds.opml`,
and re-probe first: `python3 validate.py --probe`. To retune cadence, edit the
`@jitter:*` (or concrete) schedules in `crons/domain-crons.json` (keep a non-:00 minute).

## Deploy (local)

### Get this pack

Published in the [okpacks-library](https://github.com/jalewis/okpacks-library) catalog.
Pull it into a fresh vault dir with the engine's `framework` CLI — it checks the
`engine.version` pin, validates, and leaves the pack **inert** (nothing deployed or
running; the active feed list is empty):

```sh
python <okengine>/scripts/framework.py pull okpack-example ./okpack-example   # defaults to this catalog
cd ./okpack-example
```

Already reading this from a checked-out pack dir? Skip the pull — that dir is your vault.

### Bring it up

The pack directory **is** the vault. Set `ENGINE_DIR` to your engine checkout, then:

```sh
export HERMES_UID=10000 HERMES_GID=10000        # must match the engine's hermes user (owns the mounted vault)
bash $ENGINE_DIR/scripts/build-engine-image.sh  # builds the gateway image (hermes-agent)
ENGINE_DIR=$ENGINE_DIR docker compose up -d      # builds reader+mcp, runs all three
CRON_PACK_DIR=$(pwd) bash $ENGINE_DIR/scripts/deploy-cron-scripts.sh
CRON_PACK_DIR=$(pwd) bash $ENGINE_DIR/scripts/deploy-cron-plus-jobs.sh
```

Copy `.env.example` → `.env` first (delivery tokens + at least one model provider key).
Full procedure: `docs/deploy-a-new-domain.md` §2 in the engine repo; the domain-pack
spec is §1.

### Services & ports

Host ports are offset by **+0** to avoid colliding with other packs on this host.

| Service | Container | Host port → internal | Role |
|---------|-----------|----------------------|------|
| `gateway` | `okpack-example-gateway` | `network_mode: host` | Hermes agent runtime + delivery |
| `okengine-reader` | `okpack-example-reader` | `9200 → 9200` | search/read index over the vault (`:ro`) |
| `okengine-mcp` | `okpack-example-mcp` | `8730 → 8730` | enforced MCP write/query surface (`WIKI_PATH=/opt/vault`) |

> **Search readiness.** The reader's keyword search (above) works as soon as the
> service is up. The MCP `search` tool returns *semantic* (vector) results only once
> the engine has built and embedded its qmd index over the vault; until then it falls
> back to keyword (BM25). Index build/refresh is an engine concern — see the engine's
> `docs/kb-tooling.md`.

## Validate

```sh
python3 validate.py            # parse + cross-consistency checks (offline)
python3 validate.py --fix      # repair the feeds.opml.example count comment if it drifted
python3 validate.py --probe    # HTTP-probe the suggested feeds in feeds.opml.example (network)
```
