## Installed domain: indicators & infrastructure (the observable layer)

This vault also tracks **atomic indicators of compromise** and the **adversary infrastructure**
behind them. `indicator` pages (namespace `indicators/`, date-bucketed) are seeded `no_agent` from
abuse.ch URLhaus — one page per malicious URL/domain/IP/hash, carrying the `value`, `indicator_type`,
and the `threat`/`malware_family` it belongs to. `infrastructure` pages (an ASN, hosting provider,
or C2 cluster) live in `entities/` and are what indicators resolve to.

When curating actors/campaigns/malware, link the indicators they use as `[[<indicator-id>]]` and the
infrastructure they operate as `[[<host>]]`; each gains an automatic backlink to the adversary that
uses it. Indicators are ATOMIC — keep them thin (the value + provenance), and never assert an
indicator is malicious unless a source says so. Promote a recurring host to an `infrastructure` page
only when it is worth tracking across many indicators.
