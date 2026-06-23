# okpack-sec — security knowledge vault

> The canonical home for okpack-sec is **[`okpacks-library/packs/okpack-sec`](.)** (this directory).
> It was previously a standalone pack; it now lives and is maintained here in the okpacks-library catalog.

A public, agent-curated **security knowledge pack** for the OKEngine framework. Cron
agents ingest open threat-intel feeds and compile them into a durable, cross-linked
graph of hosts, IOCs, threat actors, malware, campaigns, ATT&CK techniques,
vulnerabilities, and detections — so a defender can answer *who, what, how, and what
to watch* from the vault instead of re-reading the feed.

**Day one, for free: the authoritative catalogs.** On a fresh deploy the pack's
token-free importers seed the canonical security taxonomy — **the full MITRE ATT&CK
matrix (~700 techniques + ~170 named threat-actor groups, with aliases) and the CISA
KEV catalog**, plus NVD CVSS/CWE enrichment. These are `no_agent` (deterministic
structured-data → markdown, **zero LLM tokens**), enabled by default, and refresh on a
schedule. See [§Authoritative catalogs](#authoritative-catalogs-seeded-free) below.

**Feed-derived *content*, by contrast, is not pre-built.** The news/analysis layer —
`source` pages and the intel the agent compiles from them — starts empty and **compounds
only once you populate `feeds.opml`** (which turns on LLM spend; see *Useful by default*).
So a fresh vault ships the *frameworks* populated and the *intel* empty.

Pinned to engine **okengine v0.2.0** (see `engine.version`).

- **Domain voice + ingest/curation workflow:** `CLAUDE.md` (read at runtime by the cron agents).
- **Machine-readable contract:** `schema.yaml` (page types, partitioning, hot-set, permissions, review, tier).
- **Audience:** SOC analysts, threat hunters, CTI teams, detection engineers.

## The okf-sec spec

This repo also hosts **okf-sec** — the security profile of the Open Knowledge Format (OKF). It
defines how a security knowledge vault is structured so each page can **project to STIX 2.1, MITRE
ATT&CK, and (v0.2) OCSF** — a superset store with lossy-but-valid export. okpack-sec is its
**reference implementation**.

- **Spec:** [`OKF-SEC-SPEC.md`](OKF-SEC-SPEC.md) — types, relationship vocabulary, field dictionary,
  enums, projection contract, governance. Current version **v0.2** (tag `okf-sec-v0.2`).
- **Machine contract:** [`schema.yaml`](schema.yaml) — pins `okf_sec_version`.
- **Projector + conformance:** [`projectors/stix.py`](projectors/stix.py) +
  [`conformance/`](conformance/) — all 18 types proven against the official OASIS `stix2` validator (CI-enforced).
- **Changelog:** [`CHANGELOG.md`](CHANGELOG.md) · governance/versioning in spec §12 · License: Apache-2.0.

> A dedicated `okf` standards repo is a distant contingency, not a current need (spec §11).

## Layout

```
schema.yaml              domain contract the engine reads (types, partitioning, perms, tier)
OKF-SEC-SPEC.md          the okf-sec spec (this pack is its reference implementation)
projectors/ conformance/ STIX 2.1 projector + conformance suite (proves valid projection)
CHANGELOG.md             okf-sec spec changelog
CLAUDE.md                persona + ingest/curation rules the cron agents follow
engine.version           engine pin (okengine v0.2.0)
feeds/feeds.opml         ACTIVE sources — EMPTY by default (safe; opt in to enable)
feeds/feeds.opml.example curated 19-feed suggestion list (copy entries to opt in)
crons/
  domain-crons.json      domain cron defs (feed-fetch + daily threat-brief)
  engine-template-prompts.json   ingest-lane prompts the engine drives (backfill/enrich/grade)
  scripts/               pack feed-fetch wrapper, co-deployed to the engine cron host
docker-compose.yml       gateway + okengine-reader + okengine-mcp
.env.example             secrets & delivery (copy to .env; never commit)
wiki/                    the vault (THE product) — populated by ingest:
  sources/    entities/  concepts/  predictions/  briefings/  findings/  dashboards/  operational/
raw/                     ingest drop zones (content gitignored): clippings/ (your reports), sec/ (feeds) — see raw/README.md
```

`wiki/findings/` is **human-authored only** — analysts write findings via git; the MCP
write path refuses agent writes there (`schema.yaml` `permissions.findings`).

## Authoritative catalogs (seeded free)

Five `no_agent` importers seed the canonical reference data **deterministically —
structured source → markdown, zero LLM tokens** — so they ship **enabled by default**
and cost nothing to run. They populate the frameworks the feed-ingested pages then link
to (a news mention of `Evil Corp` resolves to the canonical `intrusion-set` via its
aliases; a CVE mention picks up authoritative CVSS).

| Importer | Cron | Pulls | Seeds |
|---|---|---|---|
| `okpack-sec-attack-import` | weekly | MITRE ATT&CK Enterprise STIX | ~700 `attack-pattern` (techniques) **+ ~170 `intrusion-set` (named threat-actor groups, with aliases)** + ~44 `course-of-action` (mitigations) |
| `okpack-sec-tgc-import` | weekly | ThaiCERT/ETDA Threat Group Cards (MISP galaxy) | **enriches matched `intrusion-set`** (country, motivation, sectors, +aliases) **and adds ~340 groups** not in ATT&CK — alias-deduped, ~514 actors total |
| `okpack-sec-tgc-tools-import` | weekly | ThaiCERT/ETDA Threat Group Cards — Tools (MISP galaxy) | **enriches matched `malware`/`tool`** (sub-type, +aliases) **and adds ~2,200 families/tools** — alias-deduped (Malware→`malware`, Tools/Exploits→`tool`) |
| `okpack-sec-kev-import` | daily | CISA KEV JSON | flags `vulnerability` pages **actively-exploited** (the highest-priority defender signal); stubs new KEV CVEs |
| `okpack-sec-nvd-import` | daily | NVD API 2.0 (**bounded**: recent window) | authoritative CVSS + CWE on `vulnerability` pages; stubs only HIGH/CRITICAL. Full sync opt-in via `NVD_API_KEY` |

All are **idempotent and non-destructive** — they refresh their own frontmatter and
never clobber agent-added sections. Because they're token-free, they're outside the LLM
cost story entirely and stay enabled even with `feeds.opml` empty. (Implementation:
[okpacks-library#16](https://github.com/jalewis/okpacks-library/issues/16),
[#17](https://github.com/jalewis/okpacks-library/issues/17).)

## Useful by default, herd-safe by design

**The pack runs out of the box — but stays inert toward upstream publishers until you add
feeds.** A fresh install schedules everything (maintenance, the ingest loop, the daily
brief) yet makes **zero upstream calls**, because the feed list is empty. The single step
to go live is populating `feeds/feeds.opml`.

- **Crons ship enabled, with per-install jittered schedules.** `feed-fetch` and the brief
  carry a `@jitter:*` schedule that `framework init`/`pull` expands to a **random minute**
  per install — so once feeds are live, thousands of deployments don't hit the same
  publishers on the same minute (no synchronized thundering herd).
- **`feeds/feeds.opml` ships empty.** `feed-fetch` runs on schedule and cleanly no-ops
  (`no feeds configured`) until you populate it — zero upstream traffic in the meantime.
  The curated 19-feed suggestion list lives in `feeds/feeds.opml.example`.

`validate.py` enforces the herd-safe invariant in CI: an enabled cron must use a `@jitter:*`
sentinel (or an already-jittered non-:00 minute) — a committed round-number schedule fails
the build.

### Going live: populate the feed list

> **⚠️ Populating feeds turns on LLM spend.** With feeds empty the pack is ~free
> (ingest crons are wake-gated — no feeds, nothing to compile). Once feeds flow, the
> agent compiles each item continuously, 24/7. Rough order of magnitude for the full
> 19-feed list: **~750 LLM calls/day (~23k/month)**, plus a one-time backfill spike
> (~280 items) when you first add them. Your bill = those calls × your model's price —
> **`$0` on local Ollama or a free tier**, real money on a paid API. Start with a few
> feeds, watch your provider dashboard, and **set a hard budget cap at your provider**
> (OKEngine has no built-in spend limit). Full breakdown + how to cut it:
> [engine `docs/operating-cost.md`](https://github.com/jalewis/okengine/blob/main/docs/operating-cost.md).

The suggested sources — government/advisories (CISA, NCSC, SANS ISC), vendor research
labs (Talos, Unit 42, Mandiant, …), and incident-report/practitioner/news (DFIR Report,
Krebs, BleepingComputer, …) — are in `feeds/feeds.opml.example`. The crons are already
running, so this one step turns ingest on:

1. Copy the `<outline>` entries you want from `feeds/feeds.opml.example` into
   `feeds/feeds.opml`. Per-source Admiralty `reliability`/`credibility` and `tlp` are
   assigned **at ingest time** (see `CLAUDE.md`), not in the OPML.
2. Re-probe first to drop dead feeds: `python3 validate.py --probe`.

That's it — the already-enabled `feed-fetch` picks them up on its next (jittered) tick and
the ingest lane starts compiling them into the vault.

### Adding your own reports (manual ingestion)

Feeds aren't the only input — **the ingest lane compiles any file you drop into `raw/`**. To ingest
a report your team wrote (or one you found):

1. Drop a **markdown/text** file into **`raw/clippings/`** — the curated, highest-priority zone (it
   jumps ahead of bulk feeds). Add light frontmatter so it's scored well: `title`, `url`,
   `published`, `source`.
2. The ingest crons are already running, so the next `raw-backfill` pass compiles it into
   `wiki/sources/` + entities — Admiralty-scored, defanged, cross-linked, same as a feed item.

Drop-zone conventions: [`raw/README.md`](raw/README.md).

### The domain cron fleet (enabled by default)

Both domain crons ship **enabled** with a `@jitter:*` schedule that was expanded to a
concrete **random minute** when you ran `framework init`/`pull` — so you don't have to
touch them. Retune the cadence/hour in `crons/domain-crons.json` only if you want to (keep
a non-:00 minute):

| Cron | Default schedule | What it does |
|------|------------------|--------------|
| `okpack-sec-feed-fetch` | `@jitter:2h` → every 2h at a random minute | Pure script — pulls the OPML into `raw/sec/` for the ingest lane (no agent). No-ops until `feeds.opml` is populated. |
| `okpack-sec-threat-brief` | `@jitter:daily` → once daily, random minute @ 13:00 UTC | Writes `wiki/briefings/<YYYY-MM-DD>.md` — the 3–5 most significant developments, terse, cross-linked. Retune the hour for your timezone. |

`crons/engine-template-prompts.json` supplies the engine-driven ingest-lane prompts
(raw → source/entity/concept compile, Admiralty scoring, type classification, thin-page
enrichment, and prediction grading/regrading/watch). All ingest crons are **local-only**
(no web tools — shared paid budget).

## Deploy (local)

> **Prerequisite:** the engine must already be installed on the host per the engine repo's
> `INSTALL.md` — including the **cron-plus** scheduler plugin (`~/.hermes/plugins/cron-plus`, a
> pinned, separately-installed dependency, not vendored or pulled in by `docker compose up`). The
> `deploy-cron-plus-jobs.sh` step below loads job definitions *onto* cron-plus; **without the plugin
> installed the cron fleet never schedules** — the deploy succeeds silently while feeds, the
> threat-brief, and the whole ingest lane stay dormant.

### Get this pack

Published in the [okpacks-library](https://github.com/jalewis/okpacks-library) catalog.
Pull it into a fresh vault dir with the engine's `framework` CLI — it checks the
`engine.version` pin, validates, and leaves the pack **inert** (empty active feeds,
crons disabled):

```sh
python <okengine>/scripts/framework.py pull okpack-sec ./okpack-sec   # defaults to this catalog
cd ./okpack-sec
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

Ports are offset by **+200** to avoid colliding with other packs on this host.

| Service | Container | Host port → internal | Role |
|---------|-----------|----------------------|------|
| `gateway` | `okpack-sec-gateway` | `network_mode: host` | Hermes agent runtime + delivery |
| `okengine-reader` | `okpack-sec-reader` | `9400 → 9200` | search/read index over the vault (`:ro`) |
| `okengine-mcp` | `okpack-sec-mcp` | `8930 → 8730` | enforced MCP write/query surface (`WIKI_PATH=/opt/vault`) |

> **Search readiness.** The reader's keyword search (above) works as soon as the
> service is up. The MCP `search` tool returns *semantic* (vector) results only once
> the engine has built and embedded its qmd index over the vault; until then it falls
> back to keyword (BM25). Index build/refresh is an engine concern — see the engine's
> `docs/kb-tooling.md`.
