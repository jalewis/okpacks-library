#!/usr/bin/env bash
# okengine#281 — composed-vault INTEGRATION test.
#
# Static validation checks each pack (and the bundle recipe) in ISOLATION. This test actually
# ASSEMBLES the okpack-cti bundle the way a deployment does — copy the host as the base vault, then
# `install-domain --apply` each guest onto it — and asserts the composed schema PRESERVES every
# guest's declared contribution: the `types` / `field_enums` / `enums` / `coverage_fields` from each
# guest's `subdomain/host-schema-additions.yaml` must all survive into the composed schema. That is
# the enum/type-travel invariant static validation can't see — the class that shipped as rec 12
# (guest field_enums silently not composing -> corpus_audit UNDETECTABLE). It also asserts the shared
# support script `_okf_write.py` is byte-identical across the packs that ship it (a drift there blocks
# a clean sequential compose).
#
# Requires ENGINE_DIR (an engine checkout; CI clones it, same as validate-all.sh).
set -euo pipefail
ENGINE_DIR="${ENGINE_DIR:?set ENGINE_DIR to an engine checkout}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUNDLE="$ROOT/packs/okpack-cti"
[ -f "$BUNDLE/pack.yaml" ] || { echo "no okpack-cti bundle present — skipping"; exit 0; }
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

HOST=$(python3 -c "import yaml;print(yaml.safe_load(open('$BUNDLE/pack.yaml'))['bundle']['host'])")
GUESTS=$(python3 -c "import yaml;print(' '.join(yaml.safe_load(open('$BUNDLE/pack.yaml'))['bundle']['compose']))")
echo "==> composing okpack-cti: host=$HOST guests=[$GUESTS]"
cp -r "$ROOT/packs/$HOST" "$WORK/host"
for g in $GUESTS; do
  echo "==> install-domain $g"
  ENGINE_DIR="$ENGINE_DIR" python3 "$ENGINE_DIR/scripts/framework_install_domain.py" \
    "$WORK/host" "$ROOT/packs/$g" --apply
done

echo "==> assert the composed schema preserves every guest's declared contribution"
COMPOSED="$WORK/host/schema.yaml" GUESTS="$GUESTS" PACKS="$ROOT/packs" python3 - <<'PY'
import os, sys, yaml
composed = yaml.safe_load(open(os.environ["COMPOSED"])) or {}
packs = os.environ["PACKS"]
def keys(d): return set(d) if isinstance(d, dict) else set()
c_types, c_fe, c_en = keys(composed.get("types")), keys(composed.get("field_enums")), keys(composed.get("enums"))
c_cov = {(str(c.get("type")), str(c.get("field")))
         for c in (composed.get("coverage_fields") or []) if isinstance(c, dict)}
fails = []
for g in os.environ["GUESTS"].split():
    p = f"{packs}/{g}/subdomain/host-schema-additions.yaml"
    if not os.path.isfile(p):
        continue
    add = yaml.safe_load(open(p)) or {}
    for t in keys(add.get("types")):
        if t not in c_types: fails.append(f"{g}: type '{t}' dropped in composition")
    for f in keys(add.get("field_enums")):
        if f not in c_fe: fails.append(f"{g}: field_enum '{f}' dropped in composition")
    for e in keys(add.get("enums")):
        if e not in c_en: fails.append(f"{g}: enum '{e}' dropped in composition")
    for cov in (add.get("coverage_fields") or []):
        if isinstance(cov, dict) and (str(cov.get("type")), str(cov.get("field"))) not in c_cov:
            fails.append(f"{g}: coverage_field {cov.get('type')}.{cov.get('field')} dropped")
if fails:
    print("FAIL — composition dropped guest contributions (okengine#281, the rec-12 class):")
    for f in fails: print("   -", f)
    sys.exit(1)
print("   OK — every guest's declared types/field_enums/enums/coverage_fields survive composition")
PY

echo "==> assert no guest SILENTLY OMITS a standalone enum-bound field from composition (okpacks#60)"
# The check above only proves DECLARED contributions travel — it passes vacuously if a guest declares
# nothing (exactly the rec-12 miss for detections/threat-landscape). This is the complementary detector:
# every field_enum a guest binds in its OWN standalone schema.yaml must reach the composed schema, unless
# the HOST already owns that field_enum (e.g. source_kind). A guest that forgets to carry one into
# host-schema-additions.yaml fails HERE instead of going unenforced in the deployed bundle.
COMPOSED="$WORK/host/schema.yaml" HOST="$HOST" GUESTS="$GUESTS" PACKS="$ROOT/packs" python3 - <<'PY'
import os, sys, yaml
def load(path):
    return (yaml.safe_load(open(path)) or {}) if os.path.isfile(path) else {}
def fe_keys(path):
    fe = load(path).get("field_enums")
    return set(fe) if isinstance(fe, dict) else set()
packs = os.environ["PACKS"]
composed_fe = fe_keys(os.environ["COMPOSED"])
host_fe = fe_keys(f"{packs}/{os.environ['HOST']}/schema.yaml")   # host-owned field_enums are exempt
fails = []
for g in os.environ["GUESTS"].split():
    standalone_fe = fe_keys(f"{packs}/{g}/schema.yaml")
    add = load(f"{packs}/{g}/subdomain/host-schema-additions.yaml")
    # `compose_exempt_field_enums` is the pack author's EXPLICIT "standalone-only, deliberately not in the
    # bundle" list (e.g. okpack-vuln's VEX/asset-assessment fields) — a documented decision, not a silent
    # omission. Everything else standalone-and-not-host-owned MUST compose.
    exempt = set(add.get("compose_exempt_field_enums") or [])
    for f in sorted(standalone_fe - host_fe - exempt):
        if f not in composed_fe:
            fails.append(f"{g}: standalone field_enum '{f}' has NO composing declaration "
                         f"(add it to {g}/subdomain/host-schema-additions.yaml, "
                         f"or list it under compose_exempt_field_enums if it's deliberately standalone-only)")
if fails:
    print("FAIL — a guest silently omits a standalone enum-bound field from composition (okpacks#60):")
    for f in fails: print("   -", f)
    sys.exit(1)
print("   OK — every guest's standalone (non-host-owned) field_enums have a composing declaration")
PY

echo "==> assert shared-support _okf_write.py is identical across the packs that ship it"
HOST="$HOST" GUESTS="$GUESTS" PACKS="$ROOT/packs" python3 - <<'PY'
import hashlib, os, sys
packs = os.environ["PACKS"]
by_hash = {}
for g in [os.environ["HOST"], *os.environ["GUESTS"].split()]:
    p = f"{packs}/{g}/crons/scripts/_okf_write.py"
    if os.path.isfile(p):
        by_hash.setdefault(hashlib.md5(open(p, "rb").read()).hexdigest(), []).append(g)
if len(by_hash) > 1:
    print("FAIL — shared _okf_write.py has DRIFTED across composable packs (blocks a clean compose):")
    for h, gs in by_hash.items(): print(f"   - {h[:12]}: {gs}")
    sys.exit(1)
n = sum(len(v) for v in by_hash.values())
print(f"   OK — _okf_write.py identical across the {n} pack(s) that ship it")
PY

echo "==> exercise the real engine extension composer on the assembled bundle"
HOST_DIR="$WORK/host" ENGINE_DIR="$ENGINE_DIR" python3 - <<'PY'
import importlib.util, os, pathlib, sys
engine = pathlib.Path(os.environ["ENGINE_DIR"])
sys.path.insert(0, str(engine / "scripts"))
import extension_compose
host = pathlib.Path(os.environ["HOST_DIR"])
ids, id_errors = extension_compose.effective_ids(host)
jobs, job_errors = extension_compose.extension_jobs(host)
errors = [*id_errors, *job_errors]
if errors:
    raise SystemExit("extension composition failed: " + "; ".join(errors))
required = {"okengine.contradictions", "okengine.timeline"}
missing = required - set(ids)
if missing:
    raise SystemExit(f"core default-on extensions missing from assembled bundle: {sorted(missing)}")
job_exts = {str(job.get("extension")) for job in jobs}
if not required <= job_exts:
    raise SystemExit(f"core extension jobs missing: {sorted(required - job_exts)}")
print(f"   OK — actual extension sources composed; {len(ids)} effective / {len(jobs)} jobs")
PY

echo "==> run deployment-validation + corpus-audit detectors over the composed fixture"
# Stage the exact script layout those in-gateway detectors consume. This is not a mock of their
# predicates: the production modules execute against the real assembled host and current engine
# schema/extension sources. We limit deployment_validate to its schema + partition checks because
# pins, auth, ownership and a running cron fleet require a live container and are covered by the
# engine smoke job.
mkdir -p "$WORK/data/scripts" "$WORK/data/config" "$WORK/host/wiki/entities/a"
cp "$ENGINE_DIR"/scripts/*.py "$WORK/data/scripts/"
cp "$ENGINE_DIR"/scripts/cron/{schema_lib.py,hardening_lib.py,id_lib.py,id_index.py} "$WORK/data/scripts/"
cp "$ENGINE_DIR/config/base-schema.yaml" "$WORK/data/config/base-schema.yaml"
cat > "$WORK/host/wiki/entities/a/integration-actor.md" <<'EOF'
---
type: actor
id: actor:integration-probe
name: Integration Probe
---

# Integration Probe
EOF
HOST_DIR="$WORK/host" DATA_DIR="$WORK/data" ENGINE_DIR="$ENGINE_DIR" python3 - <<'PY'
import importlib.util, os, pathlib, sys, yaml
host = pathlib.Path(os.environ["HOST_DIR"])
data = pathlib.Path(os.environ["DATA_DIR"])
engine = pathlib.Path(os.environ["ENGINE_DIR"])
os.environ["WIKI_PATH"] = str(host)
os.environ["OKENGINE_DATA"] = str(data)
os.environ["OKENGINE_BASE_SCHEMA"] = str(data / "config" / "base-schema.yaml")
sys.path[:0] = [str(data / "scripts"), str(engine / "scripts"), str(engine / "scripts" / "cron")]

import extension_compose
composed, compose_errors = extension_compose.composed_schema(host)
if compose_errors:
    raise SystemExit("composed schema failed: " + "; ".join(compose_errors))
artifact = host / ".okengine" / "composed-schema.yaml"
artifact.parent.mkdir(parents=True, exist_ok=True)
artifact.write_text(yaml.safe_dump(composed, sort_keys=False), encoding="utf-8")

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module

dv = load("bundle_deployment_validate", engine / "scripts" / "cron" / "deployment_validate.py")
dv.VAULT, dv.DATA = host, data
dv.F.clear(); dv.check_schema(); dv.check_partition_dups()
fails = [row for row in dv.F if row[0] == "FAIL"]
if fails:
    raise SystemExit(f"clean composed fixture failed deployment validation: {fails}")

ca = load("bundle_corpus_audit", engine / "scripts" / "cron" / "corpus_audit.py")
state = ca.audit(host)
if state["parse_errors"] or state["off_taxonomy"]:
    raise SystemExit(f"clean composed fixture failed corpus audit: "
                     f"parse={state['parse_errors']} off_taxonomy={dict(state['off_taxonomy'])}")
print("   OK — clean assembled fixture passes schema/partition/type consistency")

# Detector sensitivity is part of the contract: prove the same production checks turn red for each
# seam regression instead of merely returning green on one happy fixture.
bad_artifact = dict(composed)
bad_artifact["integration_divergence_probe"] = True
artifact.write_text(yaml.safe_dump(bad_artifact, sort_keys=False), encoding="utf-8")
dv.F.clear(); dv.check_schema()
if not any(level == "FAIL" and "DIVERGES" in message for level, _area, message in dv.F):
    raise SystemExit("deployment validator failed to detect composed-schema divergence")
artifact.write_text(yaml.safe_dump(composed, sort_keys=False), encoding="utf-8")

partitioning = (yaml.safe_load((host / "schema.yaml").read_text()) or {}).get("partitioning", {})
namespaces = partitioning.get("namespaces") or {}
partitioned = next((name for name, cfg in namespaces.items()
                    if (cfg or {}).get("strategy", "flat") != "flat"), None)
if not partitioned:
    raise SystemExit("assembled bundle declares no partitioned namespace; duplicate-path check undetectable")
base = host / "wiki" / partitioned
(base / "integration-dup.md").write_text("---\ntype: actor\nid: actor:dup-a\n---\n", encoding="utf-8")
(base / "x").mkdir(parents=True, exist_ok=True)
(base / "x" / "integration-dup.md").write_text(
    "---\ntype: actor\nid: actor:dup-b\n---\n", encoding="utf-8")
dv.F.clear(); dv.check_partition_dups()
if not any(level == "FAIL" and area == "partition-dups" for level, area, _message in dv.F):
    raise SystemExit("deployment validator failed to detect partition misfiling/duplicate slug")

bad = host / "wiki" / "entities" / "a" / "off-taxonomy.md"
bad.write_text("---\ntype: definitely-not-a-real-type\nid: bad:probe\n---\n", encoding="utf-8")
state = ca.audit(host)
if "definitely-not-a-real-type" not in state["off_taxonomy"]:
    raise SystemExit("corpus audit failed to detect off-taxonomy fixture type")
print("   OK — detectors reject schema divergence, partition misfiling, and type drift")
PY

echo "bundle-compose-check: PASS"
