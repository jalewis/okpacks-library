# Cron lanes & per-lane model routing

The pack's work runs as scheduled **cron lanes** (the cron-plus scheduler). Two kinds matter for cost:

- **`no_agent` (zero-token)** — pure Python scripts. No model spend. Ever. Run them as often as you like.
- **agent lanes** — an LLM does the work. These *spend* on the model, and they're where a lighter model
  (below) buys throughput.

## The fleet

### Ingest — `no_agent`, zero-token
| Lane | Source |
|---|---|
| `attack_import.py` | MITRE ATT&CK STIX → actors/campaigns/malware/tools/techniques/mitigations |
| `misp_galaxy_import.py` | MISP threat-actor galaxy → alias enrichment |
| `aptnotes_import.py` | APTnotes → historical vendor reports |
| `annual_reports_import.py` | awesome-annual-security-reports → full-text reports |
| `feed_fetch` | public CTI RSS → `raw/` |

### Analysis — `no_agent`, zero-token
| Lane | Output |
|---|---|
| `actor_correlation.py` | rarity-weighted actor↔actor leads (`related_actors`) |
| `signature_ttps.py` | per-actor signature techniques + `distinctiveness_score` |
| `shared_tooling.py` | malware/tool proprietary vs commodity classification |
| `actor_activity.py` | recent-activity ranking + `recent_reports`/`activity_tier` (feeds the cockpit watchlist) |
| `cti_dashboards.py` | actors-by-sector · tactic-coverage · exploited-CVEs · top-tooling dashboards |

### Compile & curate — **agent lanes** (engine-template; the pack supplies the prompt)
| Lane | Job | Weight |
|---|---|---|
| `raw-backfill` | compile `raw/` → `source` pages (extraction + linking) | **light** (extraction) |
| `source-quality-backfill` | score sources by a rubric | **light** |
| `schema-classify-drain` | pick a canonical `type` | **light** |
| `entity-backfill` | create/deepen actor/malware/campaign pages | **synthesis** |
| `concept-backfill` | write CTI concept pages | **synthesis** |
| `page-quality-enrich` | append analysis to thin pages | **synthesis** |
| `trends-refresh` | directional trend pages | **synthesis** |
| `daily-brief` / `weekly-brief` | intelligence synthesis | **synthesis** |

(Plus engine `no_agent` maintenance: reshelve, tier-refresh, corpus-indexer, backlinks-refresh, build-hot-set,
kb-health/project-stats dashboards.)

## Per-lane model routing (okengine#151)

By default every agent lane uses `config.yaml`'s `model`. To run different lanes on **different models or
even different ollama hosts**, use two deployment-tier files (both under `<deploy>/.okengine/`):

**1. Define named profiles** — `model-profiles.yaml`:
```yaml
profiles:
  bulk:      {provider: custom, base_url: http://<fast-host>:11436/v1, model: qwen3.5:9b}
  reasoning: {provider: custom, base_url: http://<big-host>:11436/v1, model: qwen3.5:27b, ollama_num_ctx: 65536}
```

**2. Pin lanes to a profile** — `cron-models.json` (`{job_name: model}`; keys must be real lane names):
```json
{ "raw-backfill": "@bulk", "source-quality-backfill": "@bulk", "schema-classify-drain": "@bulk" }
```

**3. Redeploy the jobs** — `deploy-cron-plus-jobs.sh` expands each `@bulk` into the concrete
`model`/`provider`/`base_url` on that job.

Rules:
- Lanes **not** listed use `config.yaml`'s default `model`.
- `@name` must match a defined profile — a typo/stale ref **fails the deploy** (never silently falls back).
- A **bare** model string (`qwen3.5:9b`, no `@`) is a literal, passed through unchanged.

### Which lanes suit a lighter model?
| Route to a **lighter/faster** model (e.g. 9B) | Keep on the **stronger** model (e.g. 27B) |
|---|---|
| `raw-backfill` — highest-volume, it's *extraction* not synthesis | `entity-backfill` / `concept-backfill` — writing real pages |
| `source-quality-backfill` — rubric scoring | `daily-brief` / `weekly-brief` — intelligence synthesis |
| `schema-classify-drain` — pick a type | `trends-refresh`, `page-quality-enrich` |

Routing the high-volume mechanical lanes to a lighter model on a **different host** does double duty: it
drains the ingest backlog faster **and** takes that load off the box your synthesis lanes need.

### Notes
- These files are **operator/deployment tier** — they name your specific hosts, so they live in the
  deployment's `.okengine/`, not in the shipped pack (model routing is per-infra).
- `provider: custom` **disables model "thinking" by default** — reasoning models (qwen3.x…) otherwise spend
  the whole output budget on `<think>` and return empty content, which the agent loop reads as a failure.
- `ollama_num_ctx` sets the context window per profile.
- See the engine's `docs/model-selection.md` and `scripts/model_profiles.py` for the full spec.
