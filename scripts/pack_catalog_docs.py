"""Render and synchronize human-facing pack tables from catalog.json."""

from __future__ import annotations

import json
from pathlib import Path


BEGIN = "<!-- BEGIN GENERATED PACK CATALOG -->"
END = "<!-- END GENERATED PACK CATALOG -->"


def load_catalog(root: Path) -> dict:
    return json.loads((root / "catalog.json").read_text(encoding="utf-8"))


def _cell(value: object) -> str:
    return str(value).replace("|", "\\|").strip()


def render_table(catalog: dict, *, from_packs_dir: bool) -> str:
    lines = [
        "| Pack | Domain | Status |",
        "|---|---|---|",
    ]
    for pack in catalog.get("packs", []):
        missing = [key for key in ("name", "domain", "status", "subdir") if not pack.get(key)]
        if missing:
            name = pack.get("name", "<unnamed>")
            raise ValueError(f"catalog pack {name!r} missing documentation fields: {', '.join(missing)}")
        target = Path(pack["subdir"]).name if from_packs_dir else pack["subdir"]
        lines.append(
            f"| [`{_cell(pack['name'])}`]({_cell(target)}) | "
            f"{_cell(pack['domain'])} | {_cell(pack['status'])} |"
        )
    return "\n".join(lines)


def replace_generated_section(text: str, table: str) -> str:
    if text.count(BEGIN) != 1 or text.count(END) != 1:
        raise ValueError(f"document must contain exactly one {BEGIN!r} / {END!r} marker pair")
    before, remainder = text.split(BEGIN, 1)
    _, after = remainder.split(END, 1)
    return f"{before}{BEGIN}\n{table}\n{END}{after}"


def expected_documents(root: Path, catalog: dict | None = None) -> dict[Path, str]:
    catalog = catalog or load_catalog(root)
    specs = {
        root / "README.md": False,
        root / "packs" / "README.md": True,
    }
    expected: dict[Path, str] = {}
    for path, from_packs_dir in specs.items():
        current = path.read_text(encoding="utf-8")
        table = render_table(catalog, from_packs_dir=from_packs_dir)
        expected[path] = replace_generated_section(current, table)
    return expected


def synchronize(root: Path, *, check: bool) -> list[Path]:
    drifted: list[Path] = []
    for path, expected in expected_documents(root).items():
        if path.read_text(encoding="utf-8") == expected:
            continue
        drifted.append(path)
        if not check:
            path.write_text(expected, encoding="utf-8")
    return drifted
