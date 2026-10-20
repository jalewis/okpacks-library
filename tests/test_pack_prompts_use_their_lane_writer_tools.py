"""A pack's engine-template prompt may only direct its lane to writer tools the engine grants it.

OKEngine narrows some engine lanes to a single writer tool (okengine#664: `ACTOR_TOOLS`, e.g.
concept-backfill -> converge_concept, source-quality-backfill -> score_source). The pack supplies
those lanes' prompts. Every library pack still told concept-backfill to call `create_entity` and
source-quality-backfill to call `update_entity`, so every instructed write was refused. The live
ai-research deployment had working prompts for months, edited in place and never upstreamed, so the
next pack update would have regressed it (found 2026-09-26, okengine#896).

The engine's allowlist is read from ENGINE_DIR source (a literal dict, parsed with ast, so no
engine runtime deps are needed). Tool names inside a prohibition ("never call update_entity")
are not instructions and are ignored.
"""
from __future__ import annotations

import ast
import json
import os
import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
ENGINE = os.environ.get("ENGINE_DIR") or os.environ.get("OKENGINE_DIR")
AUTH = Path(ENGINE) / "src" / "okengine" / "write_services" / "authorization.py" if ENGINE else None

pytestmark = pytest.mark.skipif(not (AUTH and AUTH.is_file()),
                                reason="no ENGINE_DIR checkout — lane tool contract UNDETECTABLE")

# Writer tools every engine write server can expose besides the lane-specific ones.
GENERIC_WRITER_TOOLS = {"create_entity", "update_entity", "patch_entity", "append_to_section",
                        "converge_entity", "tombstone_entity", "flag_for_review",
                        "record_machine_review"}

_PROHIBITION = re.compile(r"(?i)\b(?:never|do not|don't|must not|MUST NOT)\b[^.;\n]*")


def actor_tools() -> dict[str, set[str]]:
    tree = ast.parse(AUTH.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.AnnAssign) and getattr(node.target, "id", "") == "ACTOR_TOOLS":
            return {k: set(v) for k, v in ast.literal_eval(node.value).items()}
    raise AssertionError(f"ACTOR_TOOLS not found in {AUTH} — contract UNDETECTABLE")


def named_tools(prompt: str, tools: set[str]) -> set[str]:
    """Writer tools a prompt instructs the lane to use (bare or as mcp__<server>__<tool>)."""
    text = _PROHIBITION.sub(" ", prompt)
    rx = re.compile(r"(?<![A-Za-z0-9])(" + "|".join(sorted(tools, key=len, reverse=True))
                    + r")(?![A-Za-z0-9_])")
    return set(rx.findall(text))


def violations(prompts: dict, lanes: dict[str, set[str]]) -> dict[str, list[str]]:
    tools = GENERIC_WRITER_TOOLS | set().union(*lanes.values())
    out = {}
    for lane, prompt in prompts.items():
        allowed = lanes.get(f"cron:{lane}")
        if allowed is None:
            continue
        text = prompt.get("prompt", "") if isinstance(prompt, dict) else str(prompt)
        bad = sorted(named_tools(text, tools) - allowed)
        if bad:
            out[lane] = bad
    return out


def _packs():
    return sorted(REPO.glob("packs/*/crons/engine-template-prompts.json"))


@pytest.mark.parametrize("path", _packs(), ids=lambda p: p.parts[-3])
def test_prompts_name_only_their_lane_writer_tools(path):
    pack = path.parts[-3]
    found = violations(json.loads(path.read_text(encoding="utf-8")), actor_tools())
    assert not found, (
        f"{pack}: these prompts direct their lane to writer tools the engine denies it — every "
        f"such write is refused: {found}. Name the lane's own tool (OKEngine ACTOR_TOOLS).")


def test_the_scan_catches_a_denied_tool_and_ignores_a_prohibition():
    """NEGATIVE: `\\b` does not separate `__` from a tool name, so an early version of this scan
    passed every pack. Both prompt shapes must be caught; a prohibition must not be."""
    lanes = {"cron:concept-backfill": {"converge_concept"}}
    assert violations({"concept-backfill": "WRITE via mcp__okengine_write_x__create_entity."},
                      lanes) == {"concept-backfill": ["create_entity"]}
    assert violations({"concept-backfill": {"prompt": "then call update_entity"}},
                      lanes) == {"concept-backfill": ["update_entity"]}
    assert violations({"concept-backfill": "Call converge_concept. Never call create_entity."},
                      lanes) == {}
    assert violations({"other-lane": "call create_entity"}, lanes) == {}
