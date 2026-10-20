#!/usr/bin/env python3
"""Check pack cron prompts against the jobs they will actually be attached to (okengine#562).

Packs write prompts in two places, and both are keyed by a job name that lives somewhere
else — in the ENGINE. Nothing in this repo could see whether those keys still resolve, so a
key kept working right up until the engine renamed or moved the lane, and then quietly
stopped meaning anything.

Two checks, both requiring an engine checkout:

1. **Every `engine-template-prompts.json` key names a live engine-template job.**
   A key that resolves to nothing is not inert. On the single-pack path
   (`cron_pack_split.merge`) it is silently dropped, so the pack's tuned prompt never
   reaches the lane and the deployment runs the engine default while the pack source says
   otherwise. On the N-way path (`merge_packs`) the same key is a hard ERROR, and a
   non-empty error list means do not deploy — so a stale key makes the pack uncomposable.
   That is how the `prediction-*` lanes were found: 21 dead keys across 7 packs, left
   behind when forecasting migrated out of the engine fleet into the first-party
   `okengine.predictions` extension, where jobs are named `okengine.predictions:grade`.

2. **Every MCP write tool named in a prompt matches the writer that job binds.**
   `bind_contract_writers` routes a CONTRACTED model lane to a per-lane server
   (`okengine-write-<slug>`) and leaves everything else on the generic `okengine-write`;
   Hermes then publishes it as `mcp__<server>__<tool>` with non-word characters mapped to
   `_`. A prompt naming the other one still WORKS — the model resolves tools from the tool
   list, not from prose — so nothing surfaces it. It is a prompt lying about what it will
   call, which is worth catching precisely because no runtime signal ever will.

Requires ENGINE_DIR. Without it this cannot check anything, so it says so and — under CI —
fails, rather than reporting a pass it did not earn.
"""
from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import re
import sys

import yaml

TOOL_RE = re.compile(r"mcp__(okengine_write[a-z0-9_]*?)__([a-z_]+)")


def sanitize(value: str) -> str:
    """Hermes's MCP name contract: mcp__<server>__<tool>, non-word characters -> _."""
    return re.sub(r"[^A-Za-z0-9_]", "_", value)


def engine_writer_name(engine_dir: pathlib.Path):
    """The engine's own cron_pack_split.contract_writer_name, loaded from the checkout.

    This used to be a mirrored copy of the rule. A mirror agrees with itself while disagreeing
    with the engine: okengine#840 bounded the derived name so no MCP tool name clamps, and the
    copy went on certifying names the engine no longer produced. ENGINE_DIR is already required,
    so read the rule from the engine the prompts will actually run against.
    """
    path = engine_dir / "scripts" / "cron_pack_split.py"
    spec = importlib.util.spec_from_file_location("okengine_cron_pack_split", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.contract_writer_name


def expected_writer(job: dict, writer_name) -> str:
    """cron_pack_split.bind_contract_writers: contracted model lanes get their own server."""
    if not job.get("no_agent") and isinstance(job.get("output_contract"), dict):
        return writer_name(str(job.get("name") or ""))
    return "okengine-write"


def prompt_text(value) -> str:
    """A prompt is a bare string or {"prompt": ..., "output_contract": ...}."""
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return str(value.get("prompt") or "")
    return ""


def load_jobs(path: pathlib.Path) -> list[dict]:
    doc = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(doc, dict) and "jobs" in doc:
        return doc["jobs"]
    return doc if isinstance(doc, list) else []


def engine_facts(engine_dir: pathlib.Path) -> tuple[dict[str, dict], set[str]]:
    jobs = {j["name"]: j for j in load_jobs(engine_dir / "config" / "engine-crons.json")}
    tiers = yaml.safe_load((engine_dir / "config" / "cron-tiers.yaml").read_text(encoding="utf-8"))
    template = {n for n in (tiers.get("engine-template") or []) if isinstance(n, str)}
    return jobs, template


def check(packs_root: pathlib.Path, engine_dir: pathlib.Path) -> tuple[list[str], int, int]:
    engine_jobs, template_lanes = engine_facts(engine_dir)
    if not engine_jobs or not template_lanes:
        return ([f"engine checkout at {engine_dir} yielded no jobs/tiers — "
                 "UNDETECTABLE, not a pass"], 0, 0)
    try:
        writer_name = engine_writer_name(engine_dir)
    except Exception as exc:  # any load failure leaves the binding rule unknown
        return ([f"cannot load contract_writer_name from {engine_dir}/scripts/cron_pack_split.py "
                 f"({exc}) — UNDETECTABLE, not a pass"], 0, 0)

    failures: list[str] = []
    packs = prompts_seen = 0

    for prompts_path in sorted(packs_root.glob("*/crons/engine-template-prompts.json")):
        pack = prompts_path.parts[-3]
        packs += 1
        doc = json.loads(prompts_path.read_text(encoding="utf-8"))
        for lane, value in sorted(doc.items()):
            prompts_seen += 1
            job = engine_jobs.get(lane)
            if job is None or lane not in template_lanes:
                failures.append(
                    f"{pack}/{lane}: prompt for a job the engine does not ship as "
                    "engine-template — dropped on the single-pack path, a hard compose "
                    "error on the N-way path (did the lane move to an extension?)")
                continue
            want = sanitize(expected_writer(job, writer_name))
            for got, tool in TOOL_RE.findall(prompt_text(value)):
                if got != want:
                    failures.append(
                        f"{pack}/{lane}: prompt names mcp__{got}__{tool} but the lane binds "
                        f"mcp__{want}__{tool}")

    for domain_path in sorted(packs_root.glob("*/crons/domain-crons.json")):
        pack = domain_path.parts[-3]
        for job in load_jobs(domain_path):
            prompts_seen += 1
            want = sanitize(expected_writer(job, writer_name))
            for got, tool in TOOL_RE.findall(prompt_text(job.get("prompt"))):
                if got != want:
                    failures.append(
                        f"{pack}/{job.get('name')}: prompt names mcp__{got}__{tool} but the "
                        f"job binds mcp__{want}__{tool}")

        failures.extend(selector_failures(domain_path, load_jobs(domain_path), writer_name))

    return failures, packs, prompts_seen


def selector_failures(domain_path: pathlib.Path, jobs: list[dict], writer_name) -> list[str]:
    """A lane's selector script prints its instructions into the digest the model reads, so a
    writer tool it names is prompt text too -- just emitted at runtime, where the JSON checks above
    never look. In a sibling pack repo, five selectors kept naming pre-#840 writers after every
    JSON prompt had been corrected. A script shared by several jobs may name the writer of any of them.
    """
    pack = domain_path.parts[-3]
    by_script: dict[pathlib.Path, list[dict]] = {}
    for job in jobs:
        script = job.get("script") if isinstance(job, dict) else None
        if isinstance(script, str) and script:
            by_script.setdefault(domain_path.parent / "scripts" / pathlib.Path(script).name,
                                 []).append(job)
    out = []
    for path, users in sorted(by_script.items()):
        if not path.is_file():
            continue                  # a missing selector is the script-existence check's verdict
        wants = {sanitize(expected_writer(job, writer_name)) for job in users}
        for got, tool in TOOL_RE.findall(path.read_text(encoding="utf-8", errors="replace")):
            if got not in wants:
                out.append(f"{pack}/{path.name}: selector names mcp__{got}__{tool} but its "
                           f"job(s) bind {sorted('mcp__' + w + '__' + tool for w in wants)}")
    return out


def main(argv: list[str]) -> int:
    packs_root = pathlib.Path(argv[0]) if argv else pathlib.Path("packs")
    engine = os.environ.get("ENGINE_DIR") or os.environ.get("OKENGINE_DIR")
    if not engine or not (pathlib.Path(engine) / "config" / "engine-crons.json").is_file():
        # Silence is never success: say which state this is, and fail where it is required.
        print("prompt-bindings: SKIPPED — no ENGINE_DIR checkout, so prompt keys and writer "
              "bindings are UNDETECTABLE from this repo alone (set ENGINE_DIR=<engine checkout>)")
        if os.environ.get("CI"):
            print("prompt-bindings: FAIL — this is a required check in CI and it could not run")
            return 1
        return 0

    failures, packs, prompts = check(packs_root, pathlib.Path(engine))
    print(f"prompt-bindings: {prompts} prompt(s) across {packs} pack(s) checked "
          f"against {engine}")
    if not packs or not prompts:
        for f in failures:              # an early return carries its reason; never swallow it
            print(f"prompt-bindings: FAIL — {f}")
        print(f"prompt-bindings: FAIL — examined nothing under {packs_root} "
              "(did the layout move?). UNDETECTABLE, not a pass")
        return 1
    if failures:
        print("\n  FAIL:")
        for f in failures:
            print(f"    ✗ {f}")
        print(f"\n{len(failures)} prompt binding defect(s)")
        return 1
    print("prompt-bindings: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
