#!/usr/bin/env python3
"""okpack-ai-research — Hugging Face notable-models importer (no_agent, ZERO LLM tokens).

Seeds the AI-research vault with a BOUNDED, high-signal catalog of notable models — the top-N
Hugging Face hub models by likes (DeepSeek-R1, FLUX.1, Llama-3, Whisper, SDXL, …). `sort=likes`
is the signal that tracks the frontier; `downloads` is dominated by old embedding utilities.
Bounded top-N keeps this a curated reference catalog, not a feed mirror — honouring the pack's
"filter, not feed" rule (a per-paper arXiv importer would violate it; that firehose stays in the
RSS→agent lane). Deterministic JSON -> conformant `model` pages; no agent.

Non-destructive: CREATE-if-absent only — an existing model page (agent-enriched, or seeded on an
earlier run) is never overwritten. The hub metrics are an import-time snapshot; the ingest agent
maintains analysis + sources thereafter.

Identity (okpacks-library#104): "absent" is decided by IDENTITY, never by a hand-built path. A model
is present if its page exists ANYWHERE in `entities/` (`okf_migrate.find_page` — the reshelve drain
moves pages under the declared partition) or if a live page already holds the id the engine derives
from its name (a curated `DeepSeek-R1` page counts). New pages are written through the pack's
`_okf_write.write_page` (engine seat + importer guard), which mints that same id: the importer asks
the helper for it (`derive_page_id`) rather than deriving its own (okpacks-library#105). The old path check looked only at
`entities/<letter>/<slug>.md`, so every run re-created ~100 id-less pages beside their reshelved
copies and the engine's slug-identity guard quarantined them and failed the run, week after week.
Without the engine identity libs (a pack-only checkout) nothing is created: identity cannot be
verified, and an unverified create is how the duplicates began.

Usage: okpack_ai_research_hf_import.py [--limit N] [--sort likes|downloads] [--vault DIR] [--dry-run]
Env: WIKI_PATH (default /opt/vault), OKPACK_AI_RESEARCH_HF_LIMIT (default 100).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.parse
import urllib.request
from datetime import date, datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _okf_write  # noqa: E402
from _okf_write import derive_page_id, write_page  # noqa: E402
from okpack_run_report import record_run  # noqa: E402

# Engine identity libs, staged beside pack scripts in production (/opt/data/scripts). Each import is
# separate so one missing lib is reported by name rather than silently disabling the others.
try:
    import okf_migrate
except ImportError:
    okf_migrate = None
try:
    import id_index
except ImportError:
    id_index = None

HF_API ="https://huggingface.co/api/models"

# Hugging Face `pipeline_tag` -> this pack's `modality` enum (schema.yaml). Unmapped/None -> omitted
# (never guessed; the field is extensible so the agent may refine it later).
_MODALITY = {
    "text-generation": "text", "text2text-generation": "text", "fill-mask": "text",
    "question-answering": "text", "summarization": "text", "translation": "text",
    "text-classification": "text", "token-classification": "text", "text-ranking": "text",
    "zero-shot-classification": "text", "table-question-answering": "text",
    "sentence-similarity": "embedding", "feature-extraction": "embedding",
    "text-to-image": "image", "image-to-image": "image", "unconditional-image-generation": "image",
    "image-classification": "vision", "object-detection": "vision", "image-segmentation": "vision",
    "image-to-text": "vision", "depth-estimation": "vision",
    "zero-shot-image-classification": "vision",
    "visual-question-answering": "multimodal", "image-text-to-text": "multimodal",
    "any-to-any": "multimodal", "document-question-answering": "multimodal",
    "automatic-speech-recognition": "speech", "text-to-speech": "speech",
    "audio-classification": "audio", "audio-to-audio": "audio", "text-to-audio": "audio",
    "text-to-video": "video", "video-classification": "video", "image-to-video": "video",
    "reinforcement-learning": "robotics", "robotics": "robotics",
}
_STRICT = False         # set in main() from --strict / OKPACK_STRICT_IMPORT; when on, fetch/parse/
                        # write failures exit nonzero instead of best-effort skip (okpacks-library#16)


def kebab(s: str) -> str:
    s = re.sub(r"[^\w\s-]", "", (s or "").lower())
    return re.sub(r"[\s_]+", "-", s).strip("-") or "x"


def hf_slug(model_id: str) -> str:
    """`org/Model` -> a unique by-letter slug, e.g. 'deepseek-ai/DeepSeek-R1' -> deepseek-ai-deepseek-r1
    (the org prefix keeps two same-named models from different orgs distinct)."""
    return kebab((model_id or "").replace("/", "-"))


def model_records(raw: list) -> list[dict]:
    """Normalize HF API model objects -> page records. Skips private/empty entries."""
    out = []
    for m in raw:
        if not isinstance(m, dict):
            continue
        mid = (m.get("id") or m.get("modelId") or "").strip()
        if not mid or m.get("private"):
            continue
        org = (m.get("author") or (mid.split("/")[0] if "/" in mid else "")).strip()
        created = (m.get("createdAt") or "")[:10]            # 'YYYY-MM-DD' or ''
        out.append({
            "id": mid,
            "title": mid.split("/")[-1],
            "org": org,
            "org_slug": kebab(org) if org else "",
            "modality": _MODALITY.get((m.get("pipeline_tag") or "").strip()),
            "task": (m.get("pipeline_tag") or "").strip(),
            "likes": int(m.get("likes") or 0),
            "library": (m.get("library_name") or "").strip(),
            "released": created if re.match(r"\d{4}-\d{2}-\d{2}", created) else "",
            "url": f"https://huggingface.co/{mid}",
        })
    return out


def _summary(rec: dict) -> str:
    kind = rec["modality"] or "AI"
    s = rec["title"]
    if rec["org"]:
        s += f" ({rec['org']})"
    s += f" is a {kind} model published on the Hugging Face hub"
    if rec["task"]:
        s += f" for {rec['task']}"
    s += f" ({rec['likes']} likes at import). Seeded as a notable-model reference; enrich from sources."
    return s


def model_page(rec: dict, today: str) -> tuple[dict, str]:
    """(frontmatter, body) for a new model page; `id` is added by import_models."""
    fm: dict = {"type": "model", "title": rec["title"], "hf_id": rec["id"]}
    if rec["org_slug"]:
        fm["lab"] = f"[[{rec['org_slug']}]]"
    if rec["modality"]:
        fm["modality"] = rec["modality"]
    fm["release_status"] = "released"
    if rec["released"]:
        fm["released"] = rec["released"]
    if rec["task"]:
        fm["hf_task"] = rec["task"]
    fm["hf_likes"] = rec["likes"]
    if rec["library"]:
        fm["library"] = rec["library"]
    fm["url"] = rec["url"]
    fm["tags"] = ["hf-notable-models"]
    fm["last_updated"] = today
    fm["version"] = 1
    note = ("\n\n> Seeded no_agent from the Hugging Face hub (top models by likes; "
            "okpacks-library#12). Metrics are an import-time snapshot; the ingest agent maintains "
            "analysis + sources on this page.")
    return fm, f"{_summary(rec)}{note}"


def render_model(rec: dict, today: str) -> str:
    import yaml
    fm, body = model_page(rec, today)
    head = yaml.safe_dump(fm, sort_keys=False, allow_unicode=True,
                          default_flow_style=False).rstrip("\n")
    return f"---\n{head}\n---\n{body}\n"


def missing_identity_libs() -> list[str]:
    own = [n for n, m in (("okf_migrate", okf_migrate), ("id_index", id_index)) if m is None]
    return sorted(set(own) | set(_okf_write.missing_identity_libs()))


def import_models(raw: list, vault: Path, today: str, dry_run: bool = False) -> dict:
    counts = {"created": 0, "exists": 0, "total": 0, "unverifiable": 0, "collision": 0}
    records = model_records(raw)
    counts["total"] = len(records)
    missing = missing_identity_libs()
    if missing:
        print(f"hf-import: WARN engine identity lib(s) {', '.join(missing)} not importable — "
              f"cannot tell whether a model page already exists, so creating none",
              file=sys.stderr)
        counts["unverifiable"] = len(records)
        return counts
    idx = id_index.load() or id_index.build(vault, force=True)
    claimed: set[str] = set()
    for rec in records:
        slug = hf_slug(rec["id"])
        fm, body = model_page(rec, today)
        pid, _kind = derive_page_id(vault / "wiki", f"entities/{slug}", fm)
        if (okf_migrate.find_page(vault, "entities", slug) is not None
                or idx.resolve(pid) or pid in claimed):
            counts["exists"] += 1           # never clobber an agent-enriched (or earlier) page
            continue
        try:
            result = write_page(vault / "wiki", f"entities/{slug}", fm, body, dry_run=dry_run)
        except OSError:
            if _STRICT:
                raise
            counts["unverifiable"] += 1
            continue
        if result in ("collision", "unverifiable"):
            counts[result] += 1
            continue
        claimed.add(pid)
        counts["created"] += 1
    return counts


def fetch_models(limit: int, sort: str) -> list:
    q = urllib.parse.urlencode({"sort": sort, "direction": -1, "limit": max(1, min(limit, 1000))})
    req = urllib.request.Request(f"{HF_API}?{q}",
                                 headers={"User-Agent": "okpack-ai-research-hf-import"})
    with urllib.request.urlopen(req, timeout=120) as r:   # noqa: S310 (trusted huggingface.co host)  # nosec B310
        data = json.loads(r.read().decode("utf-8"))
    return data if isinstance(data, list) else []


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Seed notable `model` pages from the Hugging Face hub (no_agent).")
    ap.add_argument("--limit", type=int,
                    default=int(os.environ.get("OKPACK_AI_RESEARCH_HF_LIMIT") or 100))
    ap.add_argument("--sort", default="likes", choices=["likes", "downloads", "trendingScore"])
    ap.add_argument("--vault", default=os.environ.get("WIKI_PATH", "/opt/vault"))
    ap.add_argument("--src", help="local JSON file of HF model objects (testing; skips the network)")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--strict", action="store_true",
                    help="exit nonzero on fetch/parse/write failure instead of best-effort skip "
                         "(also OKPACK_STRICT_IMPORT=1); default is best-effort for scheduled crons")
    args = ap.parse_args(argv)
    global _STRICT
    _STRICT = bool(args.strict or os.environ.get("OKPACK_STRICT_IMPORT"))
    _started = datetime.now(timezone.utc)
    try:
        raw = (json.loads(Path(args.src).read_text(encoding="utf-8")) if args.src
               else fetch_models(args.limit, args.sort))
    except Exception as e:  # noqa: BLE001 — best-effort by default; strict -> nonzero
        print(f"hf-import: {'ERROR' if _STRICT else 'WARN'} could not load models ({e})"
              f"{'' if _STRICT else ' — skipping this run'}", file=sys.stderr)
        record_run(args.vault, "hf-models", _started, "failed" if _STRICT else "degraded",
                   error=str(e), dry_run=getattr(args, "dry_run", False))
        return 1 if _STRICT else 0
    today = date.today().isoformat()
    try:
        c = import_models(raw, Path(args.vault), today, args.dry_run)
    except OSError as e:
        print(f"hf-import: ERROR write failed ({e})", file=sys.stderr)
        record_run(args.vault, "hf-models", _started, "failed",
                   error=str(e), dry_run=getattr(args, "dry_run", False))
        return 1
    print(f"hf-import: {c['total']} HF models (top-{args.limit} by {args.sort}) — "
          f"created {c['created']} model pages, {c['exists']} already present, "
          f"{c['unverifiable']} not verifiable, {c['collision']} name collisions"
          f"{' [dry-run]' if args.dry_run else ''}")
    record_run(args.vault, "hf-models", _started, "success", counts=c, dry_run=args.dry_run)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
