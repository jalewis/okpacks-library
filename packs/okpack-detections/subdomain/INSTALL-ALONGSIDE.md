# Installing okpack-detections alongside a host pack

Use the engine's governed domain installer; do not copy schema fragments by hand:

```sh
framework install-domain <deployment> <pack-dir>
framework install-domain <deployment> <pack-dir> --apply
```

The dry run reports type, namespace, policy, cron, and persona changes before
anything is written. Installation requires a compatible trust boundary and
disjoint ownership. After applying, run `framework validate <deployment>`, the
pack's conformance tests, and deployment validation. The authoritative additive
schema is `host-schema-additions.yaml`; keep it a subset of the standalone
`schema.yaml` contract.

