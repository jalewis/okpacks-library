## Installed domain: exploited-vulnerability (CVE) tracking

This vault also tracks **actively-exploited vulnerabilities**. `cve` pages (namespace `cves/`) are seeded
`no_agent` from the CISA KEV catalog — one canonical page per CVE. When curating actors/campaigns/malware,
link the CVEs they exploit as `[[cve/CVE-YYYY-NNNNN]]`; the link resolves to the KEV page and the CVE
gains an automatic backlink to every exploiter. Do not assert a CVE is exploited unless a source says so.
