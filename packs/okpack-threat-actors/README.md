# okpack-threat-actors — Threat-Actor / Adversary Tracking

[![validate pack](https://github.com/REPLACE_OWNER/okpack-threat-actors/actions/workflows/validate.yml/badge.svg)](https://github.com/REPLACE_OWNER/okpack-threat-actors/actions/workflows/validate.yml)

A public **example pack** for OKEngine: it builds a compounding, cross-linked adversary graph
from **open** cyber-threat intelligence — threat actors, their campaigns, malware, tools, and
MITRE ATT&CK techniques — and reconciles the vendor **alias chaos** (APT29 = Cozy Bear = Midnight
Blizzard = NOBELIUM = The Dukes) into **one canonical entity per actor**.

Pinned to engine **okengine v0.10.1** (see `engine.version`).

## What makes it a good OKEngine showcase

Threat intel is natively a knowledge graph, so it demonstrates the things a knowledge engine
does that a chatbot/RAG can't:

- **Alias reconciliation from ground truth.** The bulk importers seed each actor page with its
  full synonym set, so one canonical `entities/apt29.md` carries every vendor's name — the
  screenshot-able win RAG can't reproduce.
- **Rarity-weighted actor↔actor correlation.** `actor_correlation.py` links actors by *shared
  tradecraft*, but weights each shared technique/tool by inverse frequency (idf) — so a shared
  rare custom backdoor scores high and shared Cobalt Strike ≈ 0. Output is low-trust,
  evidence-cited `related_actors` **leads**, not attribution claims. (Honest caveat: well-documented
  actors have denser ATT&CK mappings, so correlation skews toward the famous — a lead to verify,
  not a verdict.)
- **Signature-TTP profiling** (`signature_ttps.py`) — the inverse: each actor's *rarest* techniques
  (used by few others) = its distinctive detection-engineering signal + a `distinctiveness_score`.
- **RaaS-affiliate vs same-group disambiguation** (`shared_tooling.py`) — classifies malware as
  proprietary / shared / commodity by how many actors use it (mimikatz = commodity, discounted;
  a rare custom implant = proprietary), then links actors sharing *proprietary* tooling — the honest
  fix for correlation's false-merge risk (sharing a RaaS platform ≠ being the same crew).
- **Browse by kind.** `technique` pages live in their own `techniques/` namespace, and the reader's
  `display_groups` splits the mixed `entities/` namespace into browsable groups — **Threat actors**,
  Campaigns, Malware & tools — so you get a page of *just actors* instead of everything jumbled. Plus a
  generated `dashboards/top-actors-by-activity.md` ranking actors by recent reporting. (A per-tactic
  ATT&CK-matrix view would need a reader feature that doesn't exist yet — `display_groups` is label→types,
  not a by-field grid.)
- **Composability.** This pack owns `actor`/`campaign`/`malware`/`tool`/`technique` and *links* to
  CVEs it doesn't own (`[[cve/...]]` dangles standalone, resolves when composed with a vuln pack) —
  the multipack model on a domain where composition is obviously meaningful.

## Data sources & ingest lanes

| Lane | Source | Notes |
|---|---|---|
| `attack_import.py` ⭐ | MITRE ATT&CK STIX (Enterprise + Mobile + ICS) | The graph seed — 170+ actors, 700+ techniques, 800+ malware/tools, campaigns, mitigations, with aliases + relationships. `no_agent`, **zero LLM tokens**. |
| `misp_galaxy_import.py` | MISP threat-actor galaxy | The alias engine — unions ~800 more actors + synonyms onto the ATT&CK seed. `no_agent`. |
| `actor_correlation.py` | the seeded graph | Rarity-weighted correlation (above). `no_agent`. |
| `feed_fetch` | public CTI RSS (see `feeds/feeds.opml.example`) | Ongoing signal — CISA/NCSC, vendor research (Talos, Unit 42, Mandiant, MSTIC…), incident analysis (DFIR Report, Red Canary). All 18 probed live. |
| `aptnotes_import.py` | APTnotes (github.com/aptnotes/data) | **Historical seed** — ~689 public vendor APT reports (2006+) as source pages, titles auto-linked to actor aliases (`no_agent`, zero-token, idempotent). |
| `annual_reports_import.py` | awesome-annual-security-reports (MIT) | Full-**text** annual threat reports (threat categories only), actor-linked. Default: public GitHub; operator override `ANNUAL_REPORTS_DIR` for a local checkout. See [`docs/data-sources.md`](docs/data-sources.md). |
| `thaicert_import.py` | ETDA Threat Actor Encyclopedia | **Historical seed, disabled by default** (manual one-time run; ETDA's cadence slowed after ~2021). |

**Attribution discipline** is built in: attribution is contested, so the ingest prompts treat vendor
attribution as a *claim* (not fact), stamp a categorical `attribution_confidence`, and keep
`needs_review: true` — and any change to `attribution_confidence` queues the page for review.

**Lanes & model routing:** the full cron fleet (which lanes are `no_agent`/zero-token vs. agent, and
which agent lanes are light *extraction* vs. heavy *synthesis*) and how to run different lanes on
different models/hosts (`.okengine/model-profiles.yaml` + `cron-models.json`) are documented in
[`docs/lanes-and-models.md`](docs/lanes-and-models.md) — e.g. route the high-volume `raw-backfill` to a
lighter 9B model while the briefs keep 27B.

**Recommended extensions** (opt-in, spend model budget): `okengine.dedupe` (reconcile a news-derived
alias into the ATT&CK canonical), `okengine.lacuna` (coverage whitespace), `okengine.predictions`
(campaign-resurgence / TTP-adoption forecasts).

**Licensing:** ATT&CK (MITRE ATT&CK Terms of Use, attribution required), MISP galaxy (CC-BY), ETDA
(free with credit) — every imported page stamps its `sources:` for provenance.

> License notes and per-source attribution are the operator's responsibility if you publish the vault.

- **Domain voice + ingest/curation workflow:** `CLAUDE.md` (read at runtime by the cron agents).
- **Machine-readable contract:** `schema.yaml` (page types, partitioning, hot-set, permissions, review, tier).

## Layout

```
schema.yaml              domain contract the engine reads (types, partitioning, perms, tier)
CLAUDE.md                persona + ingest/curation rules the cron agents follow
engine.version           engine pin (okengine v0.10.1)
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
publishes a host port, offset by **+230** to avoid colliding with other packs
(okengine#138).

| Service | Container | Host port → internal | Role |
|---------|-----------|----------------------|------|
| `gateway` | `okpack-threat-actors-gateway` | none (bridge; reaches `okengine-mcp` by service name) | Hermes agent runtime + delivery |
| `okengine-reader` | `okpack-threat-actors-reader` | `9430 → 9200` | search/read index over the vault (`:ro`) |
| `okengine-mcp` | `okpack-threat-actors-mcp` | none by default (`8960 → 8730` only if exposed to external agents) | enforced MCP write/query surface (`WIKI_PATH=/opt/vault`) |

## Validate

```sh
python3 validate.py            # parse + cross-consistency checks (offline)
python3 validate.py --fix      # repair the feeds.opml.example count comment if it drifted
python3 validate.py --probe    # HTTP-probe the suggested feeds in feeds.opml.example (network)
```
