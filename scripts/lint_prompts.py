#!/usr/bin/env python3
"""Lint engine-template prompts for contract defect classes we have EVIDENCE for.

Three classes, deliberately no more. Speculative rules would put us back to rewriting
prose on a hunch, which is what this lint exists to replace.

ENFORCED (fails the gate)
  receipt instruction on lanes whose runner verifies a receipt (library#108).
    The runner verifies a fenced okengine-receipt iff the lane's output_contract says
    completion: per-selected-item, and the lane's selector prints the receipt the model
    must copy. Neither fact is in the prompt, so a prompt-text check cannot see a prompt
    that never mentions the receipt: every pack's concept-backfill (and five packs'
    page-quality-enrich) shipped that way. This check derives the requirement from the
    ENGINE (engine-crons.json + the selector source under ENGINE_DIR), not from the
    prompt. A per-item lane whose selector prints no receipt is REPORTED, not failed: the
    prompt has nothing to copy, and the fix is in the engine (okengine#799). Without
    ENGINE_DIR the check says it is UNDETECTABLE and, under CI, fails.

  action-phase directive on receipt-producing lanes.
    A lane that reads-then-writes and is not told to act once grounded resolves the
    ambiguity toward reconnaissance: the inference host measured tool selection at
    0/5 with "Take the next action to record it", and 5/5 after adding "Do not gather
    more information. Take the action that records it now." Reproduced independently
    at 3-4/5 -> 5/5 on two local models.

REPORTED ONLY (does not fail — see okengine#469)
  asking the model to echo a value the system already computed (sha256 of a page the
  write tool just wrote; contract_digest / input_digest printed by the selector).
    This is a real defect and the shared design rule says remove it. It CANNOT be
    fixed from the pack side alone: run_receipts._readback requires write["sha256"]
    and _matches_runner_identity requires the digests, so stripping them from prompts
    before the verifier changes would break receipt validation outright. Tracked in
    okengine#469; this reports so the class stays visible rather than rediscovered.

Prompt values come in two shapes: a bare string, or {"prompt": ..., "output_contract": ...}.
Handling only the first silently skips packs -- it hid okpack-example from the first scan.
"""
from __future__ import annotations

import json
import os
import pathlib
import sys

ACTION_MARK = "do not gather more information"
FIRST_MARK = "FIRST response MUST be a tool call"
ECHO_MARKS = ("sha256", "contract_digest", "input_digest")

# Lanes that must dispose selected items via a fenced receipt -- the read-then-write
# shape the action directive applies to.
RECEIPT_MARKERS = ("okengine-receipt", "per-selected-item")


def prompt_text(value) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return value.get("prompt") or ""
    return ""


RECEIPT_FENCE = "okengine-receipt"
# How an engine selector prints the receipt: a literal fence, or the shared helper.
SELECTOR_RECEIPT_MARKS = (RECEIPT_FENCE, "print_receipt_template(")


def engine_receipt_facts(engine_dir: pathlib.Path) -> dict[str, dict]:
    """Per engine lane: whether the runner verifies a receipt, and whether its selector prints one.

    Mirrors the runner's own condition (cron-plus _verify_receipt: completion ==
    per-selected-item) rather than a hand-kept list, so a lane that gains a receipt
    contract is covered the day the engine ships it.
    """
    doc = json.loads((engine_dir / "config" / "engine-crons.json").read_text(encoding="utf-8"))
    jobs = doc.get("jobs", []) if isinstance(doc, dict) else doc
    facts: dict[str, dict] = {}
    for job in jobs if isinstance(jobs, list) else []:
        if not isinstance(job, dict) or not isinstance(job.get("name"), str):
            continue
        script = job.get("script")
        selector = (engine_dir / "scripts" / "cron" / pathlib.Path(script).name
                    if isinstance(script, str) and script else None)
        source = None
        if selector is not None and selector.is_file():
            source = selector.read_text(encoding="utf-8", errors="replace")
        facts[job["name"]] = {
            "contract": job.get("output_contract"),
            "selector": selector.name if selector else None,
            "prints_receipt": (None if source is None
                               else any(m in source for m in SELECTOR_RECEIPT_MARKS)),
        }
    return facts


def receipt_findings(pack: str, lane: str, value, text: str,
                     facts: dict[str, dict]) -> tuple[list[str], list[str]]:
    """(failures, reported) for one prompt against the engine's receipt contract."""
    fact = facts.get(lane)
    if fact is None:
        return [], []                    # unknown key: check_prompt_bindings' verdict
    contract = value.get("output_contract") if isinstance(value, dict) else None
    if not isinstance(contract, dict):
        contract = fact["contract"]
    if not isinstance(contract, dict) or contract.get("completion") != "per-selected-item":
        return [], []                    # the runner verifies no receipt for this lane
    if fact["prints_receipt"] is None:
        return ([f"{pack}/{lane}: per-item lane but its selector "
                 f"{fact['selector'] or '(none declared)'} is unreadable under ENGINE_DIR — "
                 "receipt requirement UNDETECTABLE, not a pass"], [])
    if not fact["prints_receipt"]:
        return [], [f"{pack}/{lane}: runner verifies a receipt its selector "
                    f"{fact['selector']} never prints (engine-side, okengine#799)"]
    if RECEIPT_FENCE not in text:
        return ([f"{pack}/{lane}: selector {fact['selector']} prints an {RECEIPT_FENCE} the "
                 "runner verifies, but the prompt never tells the model to return it "
                 "(add the exact-receipt instruction — library#108)"], [])
    return [], []


def load_engine_facts() -> tuple[dict[str, dict] | None, str]:
    engine = os.environ.get("ENGINE_DIR") or os.environ.get("OKENGINE_DIR")
    if not engine or not (pathlib.Path(engine) / "config" / "engine-crons.json").is_file():
        return None, ("receipt-requirement check SKIPPED — no ENGINE_DIR checkout, so which "
                      "lanes owe a receipt is UNDETECTABLE (set ENGINE_DIR=<engine checkout>)")
    facts = engine_receipt_facts(pathlib.Path(engine))
    if not facts:
        return None, f"engine checkout at {engine} yielded no jobs — UNDETECTABLE, not a pass"
    return facts, f"receipt requirements derived from {engine}"


def main(argv: list[str]) -> int:
    root = pathlib.Path(argv[0]) if argv else pathlib.Path("packs")
    failures: list[str] = []
    reported: list[str] = []
    checked = 0
    facts, engine_note = load_engine_facts()
    if facts is None and os.environ.get("CI"):
        failures.append(f"{engine_note} — required in CI")

    for path in sorted(root.glob("*/crons/engine-template-prompts.json")):
        pack = path.parts[-3]
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            failures.append(f"{pack}: cannot read prompts ({exc})")
            continue
        for lane, value in sorted(doc.items()):
            text = prompt_text(value)
            if not text:
                continue
            checked += 1
            if facts is not None:
                lane_failures, lane_reported = receipt_findings(pack, lane, value, text, facts)
                failures.extend(lane_failures)
                reported.extend(lane_reported)
            if not any(m in text for m in RECEIPT_MARKERS):
                continue                       # not a receipt-disposing lane
            if ACTION_MARK not in text.lower():
                failures.append(
                    f"{pack}/{lane}: receipt lane has no action-phase directive "
                    f"(add: 'do not gather more information ...')")
            if FIRST_MARK not in text:
                failures.append(
                    f"{pack}/{lane}: receipt lane does not require a tool call first")
            echoed = [m for m in ECHO_MARKS if m in text]
            if echoed:
                reported.append(f"{pack}/{lane}: asks the model to echo {', '.join(echoed)}")

    print(f"prompt-lint: {checked} prompt(s) checked; {engine_note}")
    if reported:
        print(f"\n  KNOWN (okengine#469 / okengine#799 — engine-side, not failing here):")
        for r in reported:
            print(f"    · {r}")
    if failures:
        print(f"\n  FAIL:")
        for f in failures:
            print(f"    ✗ {f}")
        print(f"\n{len(failures)} prompt defect(s)")
        return 1
    print("\nprompt-lint: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
