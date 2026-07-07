# okpack-sec — the security bundle (STIX-aligned CTI pack family)

> **okpack-sec is now a pack _bundle_ (okengine#181), not a monolith.** It owns no types and
> ships no schema — it declares a **recipe** of focused, composable packs that together reproduce
> the full STIX-aligned security vault. One command installs the whole family.

A public **pack bundle** for the OKEngine framework. Instead of one large pack owning 14 security
types, the security domain is now a family of focused packs that each own a slice and compose into
one vault — easier to reuse, extend, and reason about. `okpack-sec` is the convenience installer
that recomposes them.

## What it installs

`framework pull okpack-sec` resolves the recipe in [`pack.yaml`](pack.yaml): it pulls the **host**
pack as the base vault, then `framework install-domain --apply`s each **compose** pack onto it.

| Pack | Owns | Seed |
|------|------|------|
| **okpack-threat-actors** (host) | actor, campaign, malware, tool, technique | MITRE ATT&CK + MISP galaxy + APTnotes + annual reports |
| **okpack-vuln** | cve | CISA KEV + NVD (CVSS/CWE) |
| **okpack-threat-landscape** | metric, publisher | annual-report intelligence |
| **okpack-indicators** | indicator, infrastructure | abuse.ch URLhaus |
| **okpack-detections** | detection, course-of-action | SigmaHQ ruleset + ATT&CK mitigations |
| **okpack-incidents** | incident, identity | VERIS Community Database |

The composition root (**okpack-threat-actors**) also ships the STIX 2.1 + OCSF **projectors**
(`projectors/stix.py`, `projectors/ocsf.py`) — export the composed vault to STIX/OCSF.

## Install

```bash
framework pull okpack-sec          # resolves the recipe: host + install-domain each compose pack
```

You get one vault (reader `9400` / mcp `8930`, the historic sec ports) whose type set covers all 14
security SDOs and whose `type_aliases` resolve the **STIX/legacy names** onto the friendly canonical
types — a page authored `type: threat-actor` reads as `actor`, `attack-pattern` as `technique`,
`vulnerability` as `cve`, `mitigation` as `course-of-action`, `organization` as `identity`, and so on
(the runtime backfill is the engine's `schema_type_drain`).

## Why a bundle

- **Composability** — each pack is independently useful and installable; the library enforces
  globally-unique type ownership, which a 14-type monolith blocked.
- **One-command parity** — the bundle preserves "pull okpack-sec → get the full security vault".
- **Extensibility** — add a pack to the `compose:` list to grow the vault; no monolith to fork.

## Type ↔ pack map (STIX/legacy → canonical → owner)

| STIX / legacy | canonical | owned by |
|---------------|-----------|----------|
| threat-actor, intrusion-set, group, apt | actor | okpack-threat-actors |
| attack-pattern | technique | okpack-threat-actors |
| software, product | tool | okpack-threat-actors |
| ransomware | malware | okpack-threat-actors |
| vulnerability, vuln | cve | okpack-vuln |
| ioc | indicator | okpack-indicators |
| host | infrastructure | okpack-indicators |
| mitigation | course-of-action | okpack-detections |
| organization, company, person, agency | identity | okpack-incidents |
| — | metric, publisher | okpack-threat-landscape |

See [`CHANGELOG.md`](CHANGELOG.md) for the monolith → bundle migration. The pre-bundle monolith
(its schema, importers, and conformance suite) remains in git history.
