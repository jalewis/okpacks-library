#!/usr/bin/env python3
"""okpack-vuln — EPSS exploit-prediction enrichment (no_agent, ZERO LLM tokens).

EPSS (FIRST.org) publishes a daily probability that each CVE is exploited in the
wild within 30 days. KEV is retrospective ("known exploited"); EPSS is predictive
— the complementary horizon signal. This lane:

  1. stamps `epss_score` / `epss_percentile` / `epss_date` onto EXISTING cve
     pages (no page explosion: the ~280k-row EPSS corpus stays a lookup, pages
     stay the KEV/tracked subset);
  2. writes `dashboards/epss-watch.md` — the top EPSS CVEs NOT in the vault
     (high predicted exploitation, not yet KEV = the front edge), the hottest
     tracked CVEs, and a CWE weakness-class rollup over the tracked set
     (kev_import stamps `cwe:` from the KEV feed).

License: EPSS scores are free for public use with attribution (FIRST.org EPSS).

Env: WIKI_PATH (/opt/vault) · EPSS_URL (default the FIRST daily CSV)
Usage: epss_import.py [--vault DIR] [--dry-run] [--top N]
"""
from __future__ import annotations

import argparse
import csv
import gzip
import io
import json
import os
import re
import sys
import urllib.request
from collections import Counter
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import yaml

EPSS_URL = os.environ.get("EPSS_URL", "https://epss.cyentia.com/epss_scores-current.csv.gz")
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_FM_RE = re.compile(r"\A---[ \t]*\n(.*?\n)---[ \t]*\n?(.*)\Z", re.S)


def _fetch(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "okpack-vuln/epss_import"})
    with urllib.request.urlopen(req, timeout=120) as r:  # noqa: S310 (fixed https host)  # nosec B310
        return r.read()


def parse_epss_csv(raw: bytes) -> tuple[dict[str, tuple[float, float]], str]:
    """Parse the EPSS daily CSV (optionally gzipped) into
    {CVE-id: (score, percentile)} + the feed's score_date.

    Format: a `#model_version:...,score_date:YYYY-MM-DD...` comment line, then
    a `cve,epss,percentile` header, then one row per CVE."""
    if raw[:2] == b"\x1f\x8b":
        raw = gzip.decompress(raw)
    text = raw.decode("utf-8", errors="replace")
    score_date = ""
    lines = []
    for ln in text.splitlines():
        if ln.startswith("#"):
            m = re.search(r"score_date:(\d{4}-\d{2}-\d{2})", ln)
            if m:
                score_date = m.group(1)
            continue
        lines.append(ln)
    out: dict[str, tuple[float, float]] = {}
    for row in csv.DictReader(io.StringIO("\n".join(lines))):
        cid = (row.get("cve") or "").strip().upper()
        if not _CVE_RE.match(cid):
            continue
        try:
            out[cid] = (float(row["epss"]), float(row["percentile"]))
        except (KeyError, TypeError, ValueError):
            continue
    return out, score_date


def stamp_page(text: str, score: float, percentile: float, score_date: str,
               *, change_7d: float | None = None, change_30d: float | None = None,
               threshold_crossed: str | None = None) -> str | None:
    """Return the page text with epss_* frontmatter updated, or None when the
    stored values already match (skip the write — no daily mtime churn)."""
    m = _FM_RE.match(text)
    if not m:
        return None
    try:
        fm = yaml.safe_load(m.group(1))
    except yaml.YAMLError:
        return None
    if not isinstance(fm, dict):
        return None
    new = {"epss_score": round(score, 5), "epss_percentile": round(percentile, 5),
           "epss_date": score_date}
    if change_7d is not None:
        new["epss_change_7d"] = round(change_7d, 5)
    if change_30d is not None:
        new["epss_change_30d"] = round(change_30d, 5)
    if threshold_crossed:
        new["epss_first_threshold_crossed"] = threshold_crossed
    if all(fm.get(k) == v for k, v in new.items()):
        return None
    fm.update(new)
    head = yaml.safe_dump(fm, sort_keys=False, allow_unicode=True).rstrip()
    return f"---\n{head}\n---\n{m.group(2)}"


def _state_path(vault_root: Path) -> Path:
    """Previous-run EPSS snapshot for the risers delta. Lives under the deployment's
    runtime data tree (<vault>/.hermes-data == /opt/data in-gateway); falls back to
    <vault>/.okengine for standalone/host runs. Never inside wiki/ (not content)."""
    for d in (vault_root / ".hermes-data", vault_root / ".okengine"):
        if d.is_dir():
            return d / "epss-state.json"
    d = vault_root / ".okengine"
    d.mkdir(parents=True, exist_ok=True)
    return d / "epss-state.json"


def load_state(path: Path) -> dict[str, float]:
    try:
        d = json.loads(path.read_text(encoding="utf-8"))
        return {str(k): float(v) for k, v in (d.get("scores") or {}).items()}
    except (OSError, ValueError, TypeError, AttributeError):
        return {}


def save_state(path: Path, scores: dict, score_date: str, floor: float = 0.01) -> None:
    """Persist scores >= floor (~30k rows) — enough to compute tomorrow's deltas
    without carrying the full 280k-row corpus."""
    slim = {c: round(s, 5) for c, (s, _p) in scores.items() if s >= floor}
    path.write_text(json.dumps({"score_date": score_date, "floor": floor, "scores": slim},
                               separators=(",", ":")) + "\n", encoding="utf-8")


def save_history(state_path: Path, scores: dict, score_date: str,
                 *, floor: float = 0.01, retain_days: int = 45) -> Path:
    """Retain one immutable-enough daily score projection for movement analysis.

    Re-running the same observation date is idempotent; upstream corrections for
    that date replace its projection while older dates remain available.
    """
    directory = state_path.parent / "epss-history"
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / f"{score_date}.json"
    slim = {c: round(s, 5) for c, (s, _p) in scores.items() if s >= floor}
    target.write_text(json.dumps({"score_date": score_date, "floor": floor, "scores": slim},
                                 separators=(",", ":")) + "\n", encoding="utf-8")
    cutoff = date.fromisoformat(score_date) - timedelta(days=retain_days)
    for path in directory.glob("????-??-??.json"):
        try:
            if date.fromisoformat(path.stem) < cutoff:
                path.unlink()
        except (OSError, ValueError):
            continue
    return target


def load_history_score(state_path: Path, score_date: str, days: int) -> dict[str, float]:
    target = date.fromisoformat(score_date) - timedelta(days=days)
    directory = state_path.parent / "epss-history"
    candidates = []
    for path in directory.glob("????-??-??.json") if directory.is_dir() else []:
        try:
            observed = date.fromisoformat(path.stem)
            if observed <= target:
                candidates.append((observed, path))
        except ValueError:
            continue
    return load_state(max(candidates)[1]) if candidates else {}


def _telemetry(root: Path, started: str, outcome: str, fetched: int, accepted: int,
               checkpoint_in, checkpoint_out, error: str | None = None) -> None:
    try:
        import collection_ledger as ledger
        sid = ledger.source_id("okpack.vuln.epss", "first-epss", "FIRST EPSS")
        ledger.register_sources(root, [{"source_id": sid, "connector_id": "okpack.vuln.epss",
            "label": "FIRST EPSS", "source_kind": "primary", "independent_origin": True}],
            connector_id="okpack.vuln.epss")
        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        ledger.append_attempt(root, {"connector_id": "okpack.vuln.epss", "source_id": sid,
            "started_at": started, "finished_at": now, "outcome": outcome,
            "fetched": fetched, "extracted": fetched, "accepted": accepted,
            "rejected": 0, "deduped": max(0, fetched - accepted), "dead_letter": 0,
            "error_category": error, "checkpoint_in": ledger.checkpoint_digest(checkpoint_in),
            "checkpoint_out": ledger.checkpoint_digest(checkpoint_out),
            "newest_published_at": checkpoint_out.get("score_date") if checkpoint_out else None})
    except (ImportError, OSError, ValueError):
        pass


def select_horizon(scores: dict, tracked_ids: set, prev: dict, score_date: str,
                   top: int, emerging_years: int = 2) -> tuple[list, list]:
    """The two horizon signals over untracked (non-KEV) CVEs — pure, unit-testable.

    A raw top-by-EPSS list is dominated by ancient mass-scanned CVEs (POODLE at
    EPSS 1.0: "will something scan for it" ≈ certain, "does it matter" ≈ no), so:

      emerging — top EPSS among CVEs whose CVE-year falls in the last
                 `emerging_years` calendar years (new AND predicted exploited);
      risers   — largest EPSS delta vs the previous run's snapshot, any age
                 (something CHANGED — the actual front edge). Empty on the
                 baseline run (no snapshot yet).
    """
    year_floor = int(score_date[:4]) - (emerging_years - 1)
    untracked = [(c, s, p) for c, (s, p) in scores.items() if c not in tracked_ids]
    emerging = sorted((t for t in untracked if int(t[0].split("-")[1]) >= year_floor),
                      key=lambda t: -t[1])[:top]
    risers = []
    if prev:
        shown = {c for c, *_ in emerging}          # don't repeat what Emerging already shows
        for c, s, p in untracked:
            delta = s - prev.get(c, 0.0)           # absent from the snapshot = rose from <floor
            if c not in shown and delta >= 0.05 and s >= 0.1:
                risers.append((c, s, p, delta))
        risers = sorted(risers, key=lambda t: -t[3])[:top]
    return emerging, risers


def render_dashboard(score_date: str, emerging: list, risers: list, baseline: bool,
                     tracked: list, cwe_counts: Counter,
                     cwe_samples: dict, tracked_total: int, stamped: int) -> str:
    """dashboards/epss-watch.md — pure render, unit-testable."""
    L = [
        "---",
        "type: dashboard",
        'title: "EPSS watch — predicted exploitation"',
        f"updated: {score_date}",
        "---",
        "",
        f"# EPSS watch — {score_date}",
        "",
        "_EPSS = FIRST.org's daily probability a CVE is exploited in the wild within 30 days._",
        f"_Tracked cve pages: {tracked_total} · stamped this run: {stamped}._",
        "",
        "## Emerging: recent CVEs with high EPSS, NOT yet tracked (not in KEV)",
        "",
        "_Recent CVE-years only — new AND predicted exploited, without a KEV listing.",
        "A row that later lands in KEV validated the prediction._",
        "",
        "| CVE | EPSS | percentile |",
        "|---|---|---|",
    ]
    for cid, s, p in emerging:
        L.append(f"| [{cid}](https://nvd.nist.gov/vuln/detail/{cid}) | {s:.4f} | {p:.4f} |")
    L += [
        "",
        "## Risers: largest EPSS jump since the last run (any age, not tracked)",
        "",
        "_The prediction CHANGED — exploitation likelihood is being revised upward right now._",
        "",
    ]
    if baseline:
        L.append("_(first run — baseline snapshot recorded; risers appear from the next run)_")
    else:
        L += ["| CVE | EPSS | Δ | percentile |", "|---|---|---|---|"]
        for cid, s, p, delta in risers:
            L.append(f"| [{cid}](https://nvd.nist.gov/vuln/detail/{cid}) | {s:.4f} | +{delta:.4f} | {p:.4f} |")
        if not risers:
            L.append("_(no significant risers today)_")
    L += [
        "",
        "## Hottest tracked CVEs by EPSS",
        "",
        "| CVE | EPSS | percentile |",
        "|---|---|---|",
    ]
    for cid, s, p in tracked:
        L.append(f"| [[cves/{cid}]] | {s:.4f} | {p:.4f} |")
    L += [
        "",
        "## Weakness classes across tracked CVEs (CWE)",
        "",
        "_Rollup of the `cwe:` field kev_import stamps from the KEV feed — which weakness",
        "classes actually get exploited._",
        "",
        "| CWE | tracked CVEs | e.g. |",
        "|---|---|---|",
    ]
    for cwe, n in cwe_counts.most_common(15):
        num = cwe.split("-", 1)[1]
        ex = ", ".join(f"[[cves/{c}]]" for c in cwe_samples.get(cwe, [])[:2])
        L.append(f"| [{cwe}](https://cwe.mitre.org/data/definitions/{num}.html) | {n} | {ex} |")
    L += ["", "> Generated no_agent by epss_import.py — EPSS data © FIRST.org (free with attribution)."]
    return "\n".join(L) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--vault", default=os.environ.get("WIKI_PATH", "/opt/vault"))
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--top", type=int, default=25)
    args = ap.parse_args(argv)
    wiki = Path(args.vault) / "wiki"
    cves_dir = wiki / "cves"
    started = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    state_file = _state_path(Path(args.vault))
    prior_checkpoint = {"score_date": "", "scores": load_state(state_file)}

    try:
        scores, score_date = parse_epss_csv(_fetch(EPSS_URL))
    except Exception as e:                            # noqa: BLE001
        _telemetry(state_file.parent / "collection", started, "failure", 0, 0,
                   prior_checkpoint, prior_checkpoint, "upstream-or-parse")
        print(f"ERROR: EPSS fetch/parse failed: {e}", file=sys.stderr)
        return 1
    if not scores:
        print("ERROR: EPSS feed parsed to 0 rows — refusing to stamp", file=sys.stderr)
        return 1

    history_7 = load_history_score(state_file, score_date, 7)
    history_30 = load_history_score(state_file, score_date, 30)
    prior_scores = prior_checkpoint["scores"]
    stamped = skipped = errs = 0
    tracked_scores: list[tuple[str, float, float]] = []
    tracked_ids: set[str] = set()
    cwe_counts: Counter = Counter()
    cwe_samples: dict[str, list[str]] = {}
    if cves_dir.is_dir():
        for p in cves_dir.rglob("*.md"):
            if p.name.startswith(("_", ".", "INDEX")):
                continue
            cid = p.stem.upper()
            if not _CVE_RE.match(cid):
                continue
            try:
                text = p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue  # page moved/deleted by a concurrent lane mid-scan
            tracked_ids.add(cid)
            m = _FM_RE.match(text)
            if m:
                try:
                    fm = yaml.safe_load(m.group(1)) or {}
                except yaml.YAMLError:
                    fm = {}
                for cwe in (fm.get("cwe") or []) if isinstance(fm.get("cwe"), list) else []:
                    cwe_counts[str(cwe).upper()] += 1
                    cwe_samples.setdefault(str(cwe).upper(), []).append(cid)
            if cid not in scores:
                continue
            s, pct = scores[cid]
            tracked_scores.append((cid, s, pct))
            crossed = fm.get("epss_first_threshold_crossed") if m else None
            if not crossed and s >= 0.5 and prior_scores.get(cid, 0.0) < 0.5:
                crossed = score_date
            new_text = stamp_page(text, s, pct, score_date,
                                  change_7d=s - history_7[cid] if cid in history_7 else None,
                                  change_30d=s - history_30[cid] if cid in history_30 else None,
                                  threshold_crossed=crossed)
            if new_text is None:
                skipped += 1
                continue
            if args.dry_run:
                stamped += 1
                continue
            try:
                p.write_text(new_text, encoding="utf-8")
                stamped += 1
            except OSError as e:
                errs += 1
                print(f"WARN: stamp {cid}: {e}", file=sys.stderr)

    prev = load_state(state_file)
    emerging, risers = select_horizon(scores, tracked_ids, prev, score_date, args.top)
    tracked_top = sorted(tracked_scores, key=lambda t: -t[1])[:args.top]
    dash = render_dashboard(score_date, emerging, risers, not prev, tracked_top,
                            cwe_counts, cwe_samples, len(tracked_ids), stamped)
    if not args.dry_run:
        try:
            save_state(state_file, scores, score_date)
            save_history(state_file, scores, score_date)
        except OSError as e:
            print(f"WARN: state save failed ({e}) — risers will re-baseline next run",
                  file=sys.stderr)
        ddir = wiki / "dashboards"
        ddir.mkdir(parents=True, exist_ok=True)
        (ddir / "epss-watch.md").write_text(dash, encoding="utf-8")

    checkpoint = {"score_date": score_date, "tracked": len(tracked_ids)}
    _telemetry(state_file.parent / "collection", started,
               "success" if not errs else "partial", len(scores), stamped,
               prior_checkpoint, checkpoint, "write" if errs else None)

    print(f"epss-import: {score_date} · {len(scores)} scored CVEs in feed · "
          f"{stamped} page(s) stamped, {skipped} unchanged"
          f"{f', {errs} write error(s)' if errs else ''} · dashboards/epss-watch.md")
    print(json.dumps({"wakeAgent": False}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
