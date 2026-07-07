# okpack-competitive — competitive / market intelligence

An agent-curated **competitive-intelligence vault** for the OKEngine framework: it ingests public
signals about a tracked market and compiles them into a compounding, cross-linked graph of
**competitors, products, segments, deals, and signals** — so a strategist can answer "what is each
rival doing, where's the whitespace, and what's next?" from the vault instead of the feed.


> **Deploy notes.** The pack ships **inert**: `.okengine/` (extension enablement, per-lane model
> routing) is deploy-time runtime, gitignored — enabling the extensions below is a deploy step, not
> committed state. Agent lanes default to the deployment's slowest model: pin per-lane models in
> `<deploy>/.okengine/cron-models.json` (see `CUSTOMIZING.md`). Cron `schedule.expr` hours run in
> the gateway's TZ (engine default UTC — set `TZ` in `.env` for local-time schedules).

## Quickstart: try a sample market

Three ready-to-run kits under [`examples/markets/`](examples/markets) — observability,
data-infrastructure, developer-tools — each with a **verified** `feeds.opml` and a
contract-conformant `watchlist.yaml`. Copy one in and deploy to see the pack working before
building your own market.

## Method-only — your secrets stay out of the pack

This pack ships the competitive-intel **structure and method** and **no proprietary content**. The
three things that are actually sensitive are **deployment config**, not pack files:

| Sensitive | Where it lives | In the pack? |
|---|---|---|
| **Watchlist** — who/what you track | `config/competitive-watchlist.yaml` (gitignored) | only `config/competitive-watchlist.example.yaml` (placeholders) |
| **Feeds** — your sources | `feeds/feeds.opml` (gitignored) | only `feeds/feeds.opml.example` |
| **Tuned axes / heuristics** | config + your own prompts | generic examples only |
| **Vault content** — the actual analysis | the runtime vault | never |

So you can share this pack (or keep it private) without leaking *which* competitors you watch, *which*
sources you read, or *what* you've concluded. (This is the engine⇄pack boundary applied at the pack
level — the same discipline that keeps domain knowledge out of the engine.)

## Install

```bash
# from your OKEngine checkout
python scripts/framework.py pull okpack-competitive ../my-competitive-brain
cd ../my-competitive-brain
cp config/competitive-watchlist.example.yaml config/competitive-watchlist.yaml   # fill with YOUR targets
cp feeds/feeds.opml.example feeds/feeds.opml             # fill with YOUR sources
# recommended extensions:
python <engine>/scripts/framework.py extensions enable . okengine.competitive-analytics
python <engine>/scripts/framework.py extensions enable . okengine.frontier-watch
python <engine>/scripts/framework.py extensions enable . okengine.predictions
```

## Customizing

See **[CUSTOMIZING.md](CUSTOMIZING.md)** — watchlist, feeds, schema fields/types, persona, crons, model routing, and how competitor discovery works (organic today; auto-discovery sketched).

## Types

`competitor` · `product` · `segment` · `deal` · `signal` (see `schema.yaml`; aliases: company/vendor/
rival → competitor, market/category → segment, funding/acquisition → deal).

## Recommended extensions

- **`okengine.competitive-analytics`** — competitor quadrants, battle-cards, acquirer signals (reads
  `WATCHLIST_PATH`).
- **`okengine.frontier-watch`** — segment whitespace.
- **`okengine.predictions`** — calibrated competitive forecasts.
- **`okengine.lacuna`** / **`okengine.grounding`** — structural-gap discovery + claim grounding.

## Status

`library` — the **flagship generic pack**: the competitive-intelligence METHOD for any tracked market, with all identity (who you track, which feeds, how you score) supplied at deploy time. Method-only in content AND public by placement. **Validated against a live market** (observability sample kit, engine v0.8.0, 2026-07-01): feeds→raw (144 articles)→sources (55)→entities (11)→daily brief, all through the enforced write path. The lane fleet is still the minimal starter (feed-fetch + daily brief) — extension lanes (quadrants, battle-cards, discover-competitors) activate with okengine.competitive-analytics.
