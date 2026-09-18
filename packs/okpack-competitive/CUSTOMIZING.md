# Customizing okpack-competitive

This pack ships the competitive-intel **method** (types, persona, lanes). You supply the **targets and
lens** (who you track, what sources, which axes) as deployment config. This guide goes surface by
surface, lightest first.

> **Layering rule.** Engine (extensions) → Pack (schema + persona + crons) → Deployment (watchlist +
> feeds + secrets, all gitignored). Your *who/what/how-we-read* lives in the deployment layer, so the
> pack stays shareable and free of proprietary data.

---

> **Shortcut:** `examples/markets/` ships three verified sample kits (feeds + watchlist) — copy one to skip the blank-page problem, then customize.

## 0. TL;DR — the 3 files that do 90%

| File | What it controls | Code? |
|---|---|---|
| `config/competitive-watchlist.yaml` | who you track + the quadrant axes | no |
| `feeds/feeds.opml` | which sources are ingested | no |
| `.hermes-data/config.yaml` (model) | which model does synthesis vs bulk | no |

Everything below is optional depth.

---

## 1. The watchlist — your landscape + analytic lens

`config/competitive-watchlist.yaml` (copy from `config/competitive-watchlist.example.yaml`; it's
gitignored). `okengine.competitive-analytics` reads it via `WATCHLIST_PATH` (defaults to this path).

### 1a. Minimal — one segment

```yaml
segments:
  core-platform:
    label: "Core platform"
    competitors: [acme, globex, initech]      # entity slugs under wiki/entities/
    axes: {x: "feature breadth", y: "price"}
```

### 1b. Multiple segments, different axes per segment

The **axes are the strategic frame** — change them and every quadrant re-plots.

```yaml
segments:
  core-platform:
    label: "Core platform"
    competitors: [acme, globex, initech]
    axes: {x: "feature breadth", y: "price"}
  developer-tooling:
    label: "Developer tooling"
    competitors: [acme, vercel-like, railway-like]
    axes: {x: "integration depth", y: "time-to-value"}
  enterprise:
    label: "Enterprise / regulated"
    competitors: [globex, umbrella, soylent]
    axes: {x: "compliance coverage", y: "total cost of ownership"}

watch_signals: [pricing, launch, funding, hire, partnership, acquisition]
```

### 1c. Benchmarking *yourself* against rivals

Add your own company as an entity and include it in a segment — quadrants then show where *you* sit.

```yaml
segments:
  core-platform:
    label: "Core platform"
    competitors: [my-company, acme, globex]   # my-company = entities/m/my-company.md
    axes: {x: "feature breadth", y: "price"}
```

A competitor slug that has no `entities/<slug>.md` yet is **not an error** — the quadrant lane flags it
as a coverage gap ("position unavailable pending data") rather than fabricating a placement.

---

## 2. Feeds — what gets ingested

`feeds/feeds.opml` (gitignored; copy from `feeds.opml.example`). Standard OPML with `xmlUrl`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<opml version="2.0"><head><title>competitive feeds</title></head><body>
  <outline title="Acme blog"        xmlUrl="https://acme.example/blog/rss"/>
  <outline title="Funding wire"     xmlUrl="https://news.example/funding/feed"/>
  <outline title="Product launches" xmlUrl="https://launches.example/rss"/>
  <outline title="Acme careers"     xmlUrl="https://acme.example/jobs.rss"/>  <!-- hiring signals -->
</body></opml>
```

Tips:
- **Hiring feeds** are strong leading signals (a competitor staffing a "Head of FedRAMP" telegraphs a
  market move). Add competitor job boards.
- Group by intent (blogs / funding / launches / analysts / hiring) — the persona scores them differently.
- A feed with nothing new yields a thin `source` page (provenance) and no new entities — that's by design.

---

## 3. Schema — types & fields (`schema.yaml`)

Ships: `competitor`, `product`, `segment`, `deal`, `signal` (+ aliases `company/vendor/rival→competitor`,
`market/category→segment`, `funding/acquisition→deal`, `move→signal`).

### 3a. Add fields to a type

Give `competitor` the structured fields you actually compare on:

```yaml
types:
  competitor:
    required: [type]
    fields: [hq_region, founded, employee_count, funding_total, pricing_model, target_market, parent_org]
```

### 3b. Add a new domain type

```yaml
types:
  analyst-report:                       # e.g. a Gartner/Forrester placement
    required: [type, analyst, published]
    owner: okpack-competitive
  customer-win:                         # a tracked deal win/loss
    required: [type, competitor, outcome]
    owner: okpack-competitive
```

### 3c. Tighten the type set (reject typos)

By default the format is **open** (`strict_types: false`) — an unknown `type:` is flagged as drift but
accepted. To reject anything outside your declared set:

```yaml
strict_types: true
```

### 3d. More aliases

```yaml
type_aliases:
  startup: competitor
  incumbent: competitor
  m-and-a: deal
  price-change: signal
```

---

## 4. Persona — how *we* read the market (`CLAUDE.md`)

This is the analyst voice the cron agents read. Customize:

### 4a. Mission + audience

```markdown
## Mission
Maintain a competitive vault for the dev-tools CI/CD market: track Acme, Globex, and the
open-source challengers; answer "who is winning enterprise, where is the pricing pressure, and
who is about to move upmarket?" for our product + GTM leads.

## Positioning
- **Audience:** our PM + competitive-enablement team. Assume they know the category — capture the
  *decision-relevant delta* (the new price, the headcount change, the deal terms), not 101 framing.
```

### 4b. Source-scoring rubric (what's a credible signal)

```markdown
## Source scoring
- **Tier A (act on it):** the competitor's own pricing page, SEC/Companies-House filing, official
  changelog, signed customer case study.
- **Tier B (corroborate):** reputable trade press, analyst notes.
- **Tier C (rumor):** social posts, anonymized leaks → record as `signal` with `confidence: low`,
  never into a factual field.
Reflect the tier in `confidence` on anything you derive.
```

### 4c. What counts as a `signal`

```markdown
## Signals worth recording
Pricing changes, GA launches, key exec/eng hires, partnerships, funding/M&A, certification wins
(SOC2/FedRAMP), and notable churn. One dated `signal` per move, tied to a `competitor` + a `source`.
Skip vanity PR with no strategic delta.
```

---

## 5. Lanes — extensions & crons

### 5a. Enable the analytic extensions

```bash
ENGINE=<your okengine checkout>
python "$ENGINE/scripts/framework.py" extensions enable . okengine.competitive-analytics  # quadrants, battle-cards, acquirer signals
python "$ENGINE/scripts/framework.py" extensions enable . okengine.frontier-watch         # whitespace
python "$ENGINE/scripts/framework.py" extensions enable . okengine.predictions            # calibrated forecasts
python "$ENGINE/scripts/framework.py" extensions enable . okengine.grounding              # claim↔source checks
```

### 5b. Customize the daily brief (`crons/engine-template-prompts.json`)

```jsonc
// the engine-template lane: you own the PROMPT
"Daily competitive brief. Read wiki/HOT.md, then write wiki/briefings/<YYYY-MM-DD>.md (type: dashboard).
 Lead with: (1) any pricing/packaging change, (2) launches that shift a quadrant, (3) funding/M&A,
 (4) notable hires. 3-5 items, each 2-3 sentences with [[wikilinks]] to the competitor + its source.
 Flag anything that should move a competitor on its quadrant. LOCAL-ONLY."
```

### 5c. Schedules (`crons/domain-crons.json`)

```jsonc
{ "name": "okpack-competitive-feed-fetch",
  "schedule": {"kind": "cron", "expr": "0 */4 * * *"},   // every 4h
  "script": "/opt/data/scripts/okpack_competitive_feed_fetch.py", "no_agent": true }
```

---

## 6. Models — route synthesis vs bulk (`.hermes-data/config.yaml`, `cron-models.json`)

Verified in testing: **quadrant/brief/prediction synthesis needs a capable model** (a weak local model
wrote to the wrong path and malformed tables). Bulk ingest can be cheaper.

```yaml
# .hermes-data/config.yaml
model:
  default: <strong-synthesis-model>
  provider: <...>
  base_url: <...>
```

```jsonc
// cron-models.json — per-lane overrides
{ "okengine.competitive-analytics:competitor-quadrants": "@strong",
  "raw-backfill": "@cheap",
  "entity-backfill": "@mid" }
```

---

## 7. Deployment knobs (`.env`)

```bash
OKENGINE_BIND=127.0.0.1          # loopback (default) or 0.0.0.0 to expose
OKENGINE_READER_PASSWORD=...      # REQUIRED to expose a private vault off loopback
OKENGINE_TRUST=private           # private vault → reader refuses unauthenticated network exposure
# port_offset is in pack.yaml (300 → reader 9500 / mcp 9030) to avoid host collisions
```

---

## 8. "Add my company and find competitors automatically?"

**Not yet — the watchlist is curated by you.** But you are not stuck hand-listing everything:

### 8a. Organic discovery (works today)
The ingest pipeline creates a `competitor`/company entity for **every company that appears in your
feeds**. So if your `feeds.opml` covers your space, competitors **accumulate as entity pages on their
own**. The workflow:

1. Add broad sources to `feeds.opml` (category news, funding wires, "alternatives to X" roundups).
2. Let ingest run — browse `wiki/entities/` (or the reader) for the company pages that show up.
3. **Promote** the relevant ones into `config/competitive-watchlist.yaml` to bring them into the
   quadrants/battle-cards.

So discovery happens via *coverage*, and curation (the watchlist) stays a deliberate human choice —
which is usually what you want for a strategic comparison set.

### 8b. Automatic discovery (BUILT — `discover-competitors`)
`okengine.competitive-analytics` ships a deterministic **`discover-competitors`** op (no LLM). It
surfaces companies the vault already knows that **aren't on your watchlist**, ranked by evidence, into
`dashboards/competitive/discovery.md` with a ready-to-paste watchlist snippet — you approve the real
ones. It **proposes**, never fabricates a position or auto-edits the watchlist.

Signals: **co-occurrence** (cited in the same `source` pages as your home company / tracked
competitors), **segment match** (its `segment` is one you watch), **prominence** (source count).
Set the optional anchor in the watchlist:

```yaml
home: my-company        # your company's entity slug (anchors co-occurrence)
segments: { ... }
```

Run it (weekly by schedule, or on demand):

```bash
# enable competitive-analytics, then it runs Wed 05:00; to run now:
cron-plus.sh run <discover-competitors job id>   # or: python .../discover_competitors.py
```

Empty result just means add broader `feeds/feeds.opml` and let ingest create more company entities,
then re-run. Knobs: `DISCOVERY_TYPES`, `DISCOVERY_TOP`, `DISCOVERY_MIN_SCORE`.
