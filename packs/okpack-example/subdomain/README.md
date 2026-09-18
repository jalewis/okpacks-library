# okpack-example — the two co-install forms, demonstrated

A mode-neutral pack (engine `docs/authoring-a-pack.md` §8) works BOTH ways: standalone
(its own instance, `framework init`) and installed ALONGSIDE another pack in one vault
(same trust boundary). This directory is the teaching copy of the two co-install shapes;
the real in-library reference is `okpack-cti/subdomain/` (taxonomy-augmenting).

| form | file here | what lands in the host | when to use |
|---|---|---|---|
| **subtree** (walk-up sub-domain) | `schema.yaml` | `wiki/<slug>/schema.yaml` + its namespace dirs; pages under the subtree validate against the SUBTREE contract (nearest schema governs) | the pack's value is its own knowledge world (doctrine, playbooks, org state) that LINKS the host's entities |
| **taxonomy-augmenting** | `host-schema-additions.yaml` | new types merged into the HOST root schema (host wins on collisions); pages live in the host's namespaces | the pack's value is entity-world coverage + lanes over shared namespaces |

Naming standard: a subtree installs under the pack's DOMAIN slug — never an ad-hoc name.

Install (automated — dry-run first, `--apply` writes; this pack ships BOTH forms for
teaching, so `--shape` is required; a real pack usually ships the one that fits it):

```
framework install-domain <deployment> <pack-dir> --shape subtree   # or: taxonomy
framework install-domain <deployment> <pack-dir> --shape subtree --apply
```

What the installer does either way: collision preflight on what actually lands (refuses
on FAIL), key-based merges only (type / namespace / rule id / job name / lane script /
feed xmlUrl / persona marker — re-runs and resumed partial installs apply only what's
missing), surgical comment-preserving edits, and it appends `PERSONA.md` under the
`## Installed domain:` marker. Engine-template prompts NEVER auto-merge — shared lanes
(daily-brief, trends, prediction-*) are the host's decision; a pack lane worth keeping
distinct ships as a PREFIXED domain cron job. Verify after with the deployment's weekly
`deployment-validate` lane (run it once by hand and require PASS).

Single-source rule: both forms are DERIVED from this pack's main `schema.yaml`
(subdomain types ⊆ standalone types, identical `required`) — `framework validate`
enforces it, and WARNs when a subtree schema declares types without
`partitioning.namespaces` (no dirs created, no namespace enforcement). Hygiene rules
that keep both modes open: host-reusable entity annotations, namespaced shared-surface
writes (`raw/<stream>`), id-keyed configs.
