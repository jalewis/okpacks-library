# Sample markets

Seven ready-to-run market kits — each a verified `feeds.opml` (all URLs curl-checked at commit
time) + a contract-conformant `watchlist.yaml` + a one-paragraph brief on why the market makes a
good vault. Use one as-is to see the pack working, or as the shape to copy for YOUR market.
Three are tech, four are deliberately NOT — the method is domain-agnostic.

| Market | Feeds | Why it demos well |
|---|---|---|
| [`energy-drinks/`](energy-drinks) | 4 | the NEW-ENTRANT kit: incumbents vs challenger wave, home-anchored discovery |
| [`pharma/`](pharma) | 6 | the densest deal flow: M&A, licensing, FDA approvals, patent cliffs |
| [`retail/`](retail) | 3 | earnings/pricing-war driven; the least "tech" kit |
| [`food-beverage/`](food-beverage) | 3 | brand launches + the energy-drink share war |
| [`observability/`](observability) | 8 | dense vendor newsrooms, frequent M&A/pricing moves |
| [`data-infrastructure/`](data-infrastructure) | 5 | funding/M&A flow + the open-formats fight |
| [`developer-tools/`](developer-tools) | 6 | high release cadence, AI-feature arms race |

Feeds rot: re-verify URLs before relying on a kit (a 404'd feed just ingests nothing — check
`raw/market/` fills after feed-fetch).
