# okpack-threat-landscape — Threat-Landscape / Annual-Report Intelligence

A public **example pack** for OKEngine: it turns the annual security-report firehose (DBIR, M-Trends,
threat-landscape + industry/market surveys) into a landscape knowledge graph — which **vendors** say
what, which **themes** are rising or fading year-over-year, and which **metrics** the field converges or
disagrees on. The landscape complement to [`okpack-threat-actors`](../okpack-threat-actors) (actors) and
[`okpack-vuln`](../okpack-vuln) (exploited CVEs); the three **compose** into a full CTI stack.

Pinned to engine **okengine v0.10.8** (see `engine.version`).

## What makes it a showcase

- **Cross-report theme emergence** (`theme_trends.py`, no_agent) — counts reports per theme per year →
  rising/fading `trend` pages. "AI-security coverage went 3→6 reports 2024→2025" is a measurable
  landscape shift computed with zero model spend. Sample rising themes on the real corpus: AI-security,
  cloud, OT/ICS, supply-chain, vuln-management.
- **Vendor coverage map** (`vendor_index.py`, no_agent) — a `vendor` page per publisher: how many
  reports, which themes, which years — the "who says what about what" map.
- **Full-text ingest** (`annual_reports_import.py`) of the awesome-annual-security-reports corpus (MIT,
  all categories), themed + actor-linked when composed with the actor pack. Default: public GitHub;
  operator override `ANNUAL_REPORTS_DIR` for a local checkout. See [`docs/data-sources.md`](docs/data-sources.md).
- **Composes disjoint** — owns `metric` + `publisher`; links to actors/CVEs it doesn't own.

Deliberately excludes the actor/vuln-specific material (those live in the sibling packs) and keeps the
market/survey/landscape reports the actor pack skips.

## Layout

```
schema.yaml              domain contract the engine reads (types, partitioning, perms, tier)
CLAUDE.md                persona + ingest/curation rules the cron agents follow
engine.version           engine pin (okengine v0.10.8)
feeds/feeds.opml         ACTIVE sources — EMPTY by default (safe; opt in to enable)
feeds/feeds.opml.example suggested sources (copy entries to opt in)
crons/                   domain cron defs (enabled + jittered) + ingest-lane prompts + scripts
docker-compose.yml       gateway + okengine-reader + okengine-mcp
.env.example             secrets & delivery (copy to .env; never commit)
validate.py              offline parse + cross-consistency checks (run in CI)
wiki/                    the vault (THE product) — populated by ingest
raw/                     runtime: feed_fetch output (gitignored)
```

## Customizing your vault — the levers

Five files control what this vault becomes. Edit these (not the engine):

| Lever | Controls | Edit to… |
|---|---|---|
| `schema.yaml` | the **contract** — page `types` + required fields, partitioning, hot-set, permissions, review, tier | add/rename your domain's page types and their required fields |
| `CLAUDE.md` | the **persona + ingest/curation workflow** the cron agents follow at runtime | set the voice, the source-scoring rubric, what's worth an entity, the cross-linking rules |
| `feeds/feeds.opml` | the **active** RSS/Atom sources (empty by default) | enable ingest — copy entries from `feeds/feeds.opml.example` |
| `crons/domain-crons.json` | the pack's **own** cron jobs (e.g. feed-fetch, daily brief; enabled + `@jitter:*` by default) | retune cadence (keep a non-:00 minute); populate feeds.opml to activate ingest |
| `crons/engine-template-prompts.json` | the **prompts** for the engine-driven ingest lanes (raw→source/entity/concept, scoring, classification, enrichment, prediction grading) | tune how each lane curates for your domain |

After editing, run `python3 validate.py` (offline) and `framework validate` (the
engine's deeper check) before deploy.

## Useful by default, herd-safe by design

**This pack runs out of the box** but makes zero upstream calls until you add feeds —
crons ship enabled, the feed list ships empty, so a fresh install can't become a
synchronized thundering herd against upstreams:

- **Crons ship enabled, jittered.** `crons/domain-crons.json` carries `@jitter:*`
  schedules; `framework init`/`pull` expanded them to a **random minute** per install, so
  deployments don't synchronize once feeds are live.
- **No active sources yet.** `feeds/feeds.opml` is empty (`feed-fetch` no-ops cleanly
  until you fill it); suggestions live in `feeds/feeds.opml.example`.

`validate.py` enforces the herd-safe invariant (an enabled cron must use a `@jitter:*`
sentinel or a non-:00 minute — a committed round schedule fails CI).

### Going live: populate the feed list

> **⚠️ Populating feeds turns on LLM spend.** Empty feeds = ~free (ingest crons are
> wake-gated). Once feeds flow, the agent compiles each item 24/7, so cost scales with
> feed volume — `$0` on a local/free model, real money on a paid API. Add a few feeds
> first, watch your provider dashboard, and **set a budget cap at your provider**
> (there is no built-in spend limit). See the engine's `docs/operating-cost.md` for the
> per-day/week/month estimates and how to control them.

The crons are already running, so this one step turns ingest on: review
`feeds/feeds.opml.example`, copy the `<outline>` entries you want into `feeds/feeds.opml`,
and re-probe first: `python3 validate.py --probe`. To retune cadence, edit the schedules
in `crons/domain-crons.json` (keep a non-:00 minute, or a `@jitter:*` sentinel).

## Deploy (local)

The pack directory **is** the vault. The **cron-plus** scheduler the engine's whole
cron fleet runs on is installed **per-pack** into `.hermes-data/plugins/cron-plus`
by `deploy.sh` (`scripts/install-cron-plus.sh`, at the manifest-pinned commit) and
enabled in the seeded `config.yaml` — no separate host install. Without it the cron
fleet never schedules (ingest, index/health/tier refresh, every repair drain stay
dormant), so `deploy.sh` sets it up before the gateway starts.

Copy `.env.example` → `.env` first (delivery tokens + at least one model provider
key). Then, **from the pack dir**, one command does the whole bring-up:

```sh
bash $ENGINE_DIR/scripts/deploy.sh              # validate -> seed runtime -> build (if needed) -> compose up -> crons
```

`deploy.sh` runs the steps in the right order so the seed-before-compose step can't
be skipped (a fresh `git clone` has no `.hermes-data/`). Flags: `--rebuild`,
`--skip-build`, `--skip-validate`, `--no-crons`, `--fix-perms`.

> The gateway runs as `HERMES_UID`, which **defaults to your own uid** (`$(id -u)`), so a
> pack you cloned as yourself is writable out of the box — no `chown`. Pin a **fixed** uid
> (and `sudo chown -R <uid> .`) only for a vault you'll move between hosts or operate as
> several users; otherwise deploy stops before compose with a permission message.

The equivalent manual steps:

```sh
# HERMES_UID/HERMES_GID default to your uid (you own the clone) — nothing to export.
# Only for a portable/shared vault: export a fixed uid AND `sudo chown -R <uid> .` first.
bash $ENGINE_DIR/scripts/build-engine-image.sh  # builds the gateway image (hermes-agent)
bash $ENGINE_DIR/scripts/ensure-runtime.sh      # seed .hermes-data/config.yaml (fresh clone has none) — MUST run before compose
ENGINE_DIR=$ENGINE_DIR docker compose up -d      # builds reader+mcp, runs all three
CRON_PACK_DIR=$(pwd) bash $ENGINE_DIR/scripts/deploy-cron-scripts.sh
CRON_PACK_DIR=$(pwd) bash $ENGINE_DIR/scripts/deploy-cron-plus-jobs.sh
```
Full procedure: `docs/deploy-a-new-domain.md` §2 in the engine repo; the domain-pack
spec is §1.

### Services & ports

All three services share a per-pack bridge (the compose default network); only the reader
publishes a host port, offset by **+220** to avoid colliding with other packs
(okengine#138).

| Service | Container | Host port → internal | Role |
|---------|-----------|----------------------|------|
| `gateway` | `okpack-threat-landscape-gateway` | none (bridge; reaches `okengine-mcp` by service name) | Hermes agent runtime + delivery |
| `okengine-reader` | `okpack-threat-landscape-reader` | `9420 → 9200` | search/read index over the vault (`:ro`) |
| `okengine-mcp` | `okpack-threat-landscape-mcp` | none by default (`8950 → 8730` only if exposed to external agents) | enforced MCP write/query surface (`WIKI_PATH=/opt/vault`) |

## Validate

```sh
python3 validate.py            # parse + cross-consistency checks (offline)
python3 validate.py --fix      # repair the feeds.opml.example count comment if it drifted
python3 validate.py --probe    # HTTP-probe the suggested feeds in feeds.opml.example (network)
```
