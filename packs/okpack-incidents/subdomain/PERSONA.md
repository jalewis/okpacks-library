## Installed domain: security incidents & identities (the event layer)

This vault also tracks **security incidents** and the **identities** they involve. `incident` pages
(namespace `security-incidents/`, year-bucketed) are seeded `no_agent` from the open VERIS Community Database —
one page per breach/intrusion, carrying the victim, the action categories (hacking/malware/misuse/…),
the actor kind, and the year. `identity` pages (victim organizations, agencies, persons) live in
`entities/`. When curating, link an incident to the actor that caused it ([[<actor>]]), the CVEs it
exploited ([[cve/…]]), and the victim identity — so the vault binds adversaries and vulnerabilities to
real outcomes. Report only what a source states; VERIS records are structured claims, not verdicts.
