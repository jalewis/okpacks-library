# Installing okpack-vendor-risk ALONGSIDE another pack (taxonomy-augmenting shape)

okpack-vendor-risk co-installs in the taxonomy-augmenting shape (engine
`docs/authoring-a-pack.md` §8): its value is vendor/dependency entity coverage +
lanes over shared namespaces, not a knowledge subtree. Same trust boundary required.

Automated:

```
framework install-domain <deployment> <pack-dir>          # dry-run plan
framework install-domain <deployment> <pack-dir> --apply
```

What the installer does (and the rules it applies):

1. **Types** — merges `subdomain/host-schema-additions.yaml` into the host schema.
   Only the four introduced types ship (vendor/component/contract/location);
   `product`/`vulnerability`/`incident` are deliberately absent — the host (or a
   co-installed okpack-cti / okpack-competitive) supplies them authoritatively,
   and a host lacking them still accepts the pages via strict_types: false.
2. **Namespaces** — `contracts/` and `incidents/` land in the HOST schema with
   their partitioning defs, the contracts write-deny permission, and tier
   entries; the wiki dirs are created. (Verified live: an agent `contract`
   create rejects "namespace 'contracts' is not agent-writable".)
3. **Completeness rules** — merges the rules scoped to this pack's own types
   (incident/vendor/component/contract); anything targeting a host-shared type is
   reported for deliberate operator merge.
4. **Feeds** — none ship active (feeds.opml is empty by design); nothing merges
   until the operator enables sources.
5. **Persona** — appends `subdomain/PERSONA.md` under the `## Installed domain:`
   marker.

Verify (the probes are the contract):

- a `type: vendor` page missing `name` REJECTS at the write path; host pages
  are untouched;
- a `type: contract` create by the agent REJECTS (operator-authored register);
- the completeness audit evaluates the merged incident/vendor rules;
- with `okengine.actor-risk-ranking` enabled + a vendor-ontology target config
  (see `config/actor-risk-targets.yaml.example`), `dashboards/actor-risk/`
  ranks vendor pages.

Single-source rule: `subdomain/host-schema-additions.yaml` is derived from this
pack's `schema.yaml`; regenerate on any type change (additions ⊆ standalone must
hold — `framework validate` checks it).
