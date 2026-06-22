#!/usr/bin/env python3
"""Feed freshness / probe reporting (okpacks-library#24).

Probes each pack's curated `feeds/feeds.opml.example` and reports per-feed health: HTTP status, the
final URL after redirects, latency, and the error reason for anything unreachable. Optionally writes
JSON and/or Markdown artifacts. This is the NETWORK feed-health surface — deliberately separate from
the offline per-pack `validate.py` so normal validation stays deterministic.

Run via `okpacks probe-feeds` (or directly). Exits 0 by default (advisory); `--strict` fails if any
feed is dead (no response). Usage:
    scripts/feed_report.py [--json OUT.json] [--md OUT.md] [--timeout N] [--strict] [pack ...]
"""
import argparse
import json
import time
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
UA = "okpacks-feed-report"


def pack_dirs(selected: list[str]) -> list[Path]:
    dirs = [d for d in sorted((ROOT / "packs").iterdir())
            if d.is_dir() and (d / "feeds" / "feeds.opml.example").exists()]
    return [d for d in dirs if not selected or d.name in selected]


def feeds_of(pd: Path) -> list[str]:
    path = pd / "feeds" / "feeds.opml.example"
    try:
        tree = ET.parse(path)
    except ET.ParseError:
        return []
    return [o.get("xmlUrl") for o in tree.iter("outline") if o.get("xmlUrl")]


def probe(url: str, timeout: float) -> dict:
    t0 = time.monotonic()
    try:
        req = urllib.request.Request(url, method="GET", headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310
            latency = round((time.monotonic() - t0) * 1000)
            final = r.url
            return {"url": url, "status": r.status, "final_url": final,
                    "redirected": final != url, "latency_ms": latency, "error": None}
    except Exception as e:  # noqa: BLE001 — any failure is reported, not raised
        return {"url": url, "status": None, "final_url": None, "redirected": False,
                "latency_ms": round((time.monotonic() - t0) * 1000), "error": str(e)[:200]}


def render_md(report: dict) -> str:
    out = [f"# Feed health report — {report['probed_at']}", ""]
    for pk in report["packs"]:
        s = pk["summary"]
        out.append(f"## {pk['pack']} — {s['ok']} ok · {s['redirect']} redirected · {s['dead']} dead "
                   f"(of {s['total']})")
        out.append("")
        out.append("| status | latency | feed | note |")
        out.append("|---|---|---|---|")
        for f in pk["feeds"]:
            if f["error"]:
                st, note = "✗ dead", f["error"]
            elif f["redirected"]:
                st, note = f"↪ {f['status']}", f"→ {f['final_url']}"
            else:
                st, note = f"✓ {f['status']}", ""
            out.append(f"| {st} | {f['latency_ms']}ms | {f['url']} | {note} |")
        out.append("")
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Probe pack feeds and report health (#24).")
    ap.add_argument("packs", nargs="*", help="limit to these pack names (default: all)")
    ap.add_argument("--json", metavar="FILE", help="write the report as JSON")
    ap.add_argument("--md", metavar="FILE", help="write the report as Markdown")
    ap.add_argument("--timeout", type=float, default=15.0)
    ap.add_argument("--strict", action="store_true", help="exit nonzero if any feed is dead")
    args = ap.parse_args(argv)

    probed_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    report = {"probed_at": probed_at, "packs": []}
    total_dead = 0
    for pd in pack_dirs(args.packs):
        feeds = [probe(u, args.timeout) for u in feeds_of(pd)]
        summ = {"total": len(feeds),
                "ok": sum(1 for f in feeds if f["status"] and not f["redirected"]),
                "redirect": sum(1 for f in feeds if f["redirected"]),
                "dead": sum(1 for f in feeds if f["error"])}
        total_dead += summ["dead"]
        report["packs"].append({"pack": pd.name, "summary": summ, "feeds": feeds})
        print(f"  {pd.name}: {summ['ok']} ok · {summ['redirect']} redirected · "
              f"{summ['dead']} dead (of {summ['total']})")
        for f in feeds:
            if f["error"]:
                print(f"      ✗ {f['url']} — {f['error']}")
            elif f["redirected"]:
                print(f"      ↪ {f['status']} {f['url']} → {f['final_url']}")

    if args.json:
        Path(args.json).write_text(json.dumps(report, indent=2))
        print(f"  wrote {args.json}")
    if args.md:
        Path(args.md).write_text(render_md(report))
        print(f"  wrote {args.md}")

    if args.strict and total_dead:
        print(f"\n{total_dead} dead feed(s) (--strict).")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
