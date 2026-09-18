# Data sources

All public. The importer is `no_agent` / zero-token — it fetches structured open data and writes pages;
the model-spending agent lanes (trend/metric synthesis, briefs) run afterward on what's seeded.

## Primary: annual reports

| Source | Where | Lane | Notes |
|---|---|---|---|
| **awesome-annual-security-reports** | [`jacobdjwilson/awesome-annual-security-reports`](https://github.com/jacobdjwilson/awesome-annual-security-reports) (MIT) | `annual_reports_import.py` | Full-**text** annual reports, ALL categories, stamped with an inferred `report_theme` + `vendor`. **Default: public GitHub.** Operator override: `ANNUAL_REPORTS_DIR=/path/to/local/checkout` (faster/offline). Env `ANNUAL_REPORTS_YEARS`, `_LIMIT`, `_INCLUDE`. |

`theme_trends.py` and `vendor_index.py` are pure no_agent analyses over those seeded pages (no external
source). Optional ongoing RSS lives in [`feeds/feeds.opml.example`](../feeds/feeds.opml.example).

## Composition

This pack owns `metric` + `publisher` and links to data it does **not** own:

- **actors** — when composed with [`okpack-threat-actors`](https://github.com/…/okpack-threat-actors),
  report text is matched to actor aliases → `[[actor]]` links (no-op standalone).
- **CVEs** — reports referencing CVEs can link `[[cve/…]]`, resolving against
  [`okpack-vuln`](https://github.com/…/okpack-vuln) when composed.

Compose all three (`framework compose-preview okpack-threat-actors okpack-vuln okpack-threat-landscape`)
for the full actor + vulnerability + landscape stack — disjoint ownership, verified SAFE.

## Licensing

awesome-annual-security-reports is MIT; imported pages stamp `sources:` (vendor + the corpus) for
provenance. Respect each underlying report's own terms — the corpus links back to original authors.
