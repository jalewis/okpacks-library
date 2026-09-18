# Sample market: observability
Monitoring/APM/telemetry platforms — a dense, well-fed market: every major vendor runs an RSS
newsroom, M&A and pricing moves are frequent, and the OSS-vs-platform axis gives the quadrant
lanes real tension. Good first market to validate a deployment against.
Setup: copy `feeds.opml` → `feeds/feeds.opml`, `watchlist.yaml` → `config/competitive-watchlist.yaml`, deploy.

Note from the first live validation: the trade feed (The New Stack) is BROAD tech — expect
general AI/cloud items alongside observability until you fill in the `pack_config.scope`
template in `schema.yaml` (the ingest relevance boundary) or trim the feed list to vendor
newsrooms only.
