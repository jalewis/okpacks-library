#!/usr/bin/env python3
"""Lint engine-template prompts for contract defect classes we have EVIDENCE for.

Two classes, deliberately no more. Speculative rules would put us back to rewriting
prose on a hunch, which is what this lint exists to replace.

ENFORCED (fails the gate)
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


def main(argv: list[str]) -> int:
    root = pathlib.Path(argv[0]) if argv else pathlib.Path("packs")
    failures: list[str] = []
    reported: list[str] = []
    checked = 0

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

    print(f"prompt-lint: {checked} prompt(s) checked")
    if reported:
        print(f"\n  KNOWN (okengine#469 — blocked on the verifier, not failing here):")
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
