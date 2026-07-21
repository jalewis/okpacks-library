# Installing okpack-ai-research ALONGSIDE another pack (taxonomy-augmenting shape)

Per the engine's mode-neutral checklist (docs/authoring-a-pack.md §8). Same trust
boundary required. Run the engine's coinstall_preflight FIRST — it gates type, alias,
namespace, cron, prompt-key, config, feed, raw-stream, and dashboard collisions.

1. Types: merge `subdomain/host-schema-additions.yaml` into the host schema (host wins
   on collision; host-reusable types listed in the file are NOT added).
2. Feeds: merge OPML outlines, dedupe by xmlUrl.
3. Crons: append this pack's prefixed domain jobs + non-colliding engine-template prompts
   (prompt-key collisions: HOST WINS); regenerate via deploy-cron-plus-jobs.
4. Configs: id-keyed merge only (rules by rule id; watchlists by segment key) — never
   overwrite a file.
5. Persona: append as a marked `## Installed domain:` section.
6. Verify: added type validates in host entities/; reused types unchanged under the host
   contract; lanes pack-prefixed in cron-plus list; this pack's raw stream fills
   independently. Then run deployment-validate.
