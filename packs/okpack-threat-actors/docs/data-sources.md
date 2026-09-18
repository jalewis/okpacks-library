# Data sources

Every source this pack draws from is **public**. The bulk importers (`crons/scripts/*_import.py`) are
`no_agent` / zero-token — they fetch structured open data and write pages directly; the model-spending
agent lanes only run afterward, on what's been seeded. Pointers below so you can verify, pin, or mirror
each source.

## Bulk importers (structured, zero-token)

| Source | Where | Lane | What it seeds |
|---|---|---|---|
| **MITRE ATT&CK** | [`mitre-attack/attack-stix-data`](https://github.com/mitre-attack/attack-stix-data) | `attack_import.py` | actors, campaigns, malware, tools, techniques, mitigations + relationships + aliases (Enterprise+Mobile+ICS). Env `ATTACK_STIX_BASE`, `ATTACK_DOMAINS`. |
| **MISP threat-actor galaxy** | [`MISP/misp-galaxy`](https://github.com/MISP/misp-galaxy) | `misp_galaxy_import.py` | actor alias unions + galaxy-only actors. Env `MISP_GALAXY_URL`. |
| **Microsoft actor naming** | [`microsoft/mstic`](https://github.com/microsoft/mstic) (MIT) | `msft_import.py` | the cross-vendor "Rosetta Stone" — Microsoft weather-suffix names ↔ Other names, unioned onto actor aliases. Env `MSFT_MAP_URL`. |
| **APTnotes** | [`aptnotes/data`](https://github.com/aptnotes/data) | `aptnotes_import.py` | ~689 historical vendor APT reports (2006+) as source pages, titles linked to actors. Env `APTNOTES_URL`. |
| **awesome-annual-security-reports** | [`jacobdjwilson/awesome-annual-security-reports`](https://github.com/jacobdjwilson/awesome-annual-security-reports) | `annual_reports_import.py` | full-TEXT annual threat reports (threat categories only). **Default: public GitHub.** Operator override: `ANNUAL_REPORTS_DIR=/path/to/local/checkout` for a machine that already has the repo (faster/offline). Env `ANNUAL_REPORTS_YEARS`, `_LIMIT`, `_INCLUDE`. |
| **ThaiCERT / ETDA** | [apt.etda.or.th](https://apt.etda.or.th) | `thaicert_import.py` | historical alias breadth. **Disabled by default** (manual `THAICERT_SRC=…`); cadence slowed after ~2021. |
| **CISA KEV** (compose seam) | [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | *(okpack-vuln)* | actively-exploited CVEs — owned by the composable `okpack-vuln` pack; this pack's `[[cve/…]]` links resolve there. |

## Ongoing signal (RSS)

`feed_fetch` pulls the public CTI feeds listed in [`feeds/feeds.opml.example`](../feeds/feeds.opml.example)
(CISA/NCSC, Talos, Unit 42, Mandiant, MSTIC, DFIR Report, Red Canary…) — recent posts only. RSS is
forward-only; use the APTnotes + annual-reports importers for history.

## Operator overrides & adding sources

- **Local mirror of a source** — the annual-reports lane reads `ANNUAL_REPORTS_DIR` if set; the others
  take a URL env (`*_URL` / `*_BASE`) you can point at a mirror or a pinned commit.
- **More history** — for a specific WordPress vendor blog, its `/wp-json/wp/v2/posts?per_page=100&page=N`
  exposes the full archive; a sitemap (`/sitemap.xml`) enumerates every post URL. Not shipped as a lane
  (per-blog, ToS-sensitive) — add one modeled on `aptnotes_import.py` if you need a particular archive.
- **Licensing** — respect each source's terms: ATT&CK (MITRE ATT&CK Terms of Use, attribution),
  MISP galaxy (CC-BY), APTnotes (CC0), awesome-annual-security-reports (MIT), ETDA (free with credit),
  CISA KEV (US-Gov public domain). Imported pages stamp `sources:` for provenance.
