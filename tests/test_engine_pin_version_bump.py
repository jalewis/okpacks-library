"""Negative fixture for the pack-release requirement in okpacks-library#90."""

import shutil
import subprocess
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "check_version_bumps.py"


def _run(*args: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=cwd, text=True, capture_output=True, check=False)


def test_engine_pin_change_without_pack_version_bump_fails(tmp_path: Path) -> None:
    pack = tmp_path / "packs" / "example"
    pack.mkdir(parents=True)
    (tmp_path / "scripts").mkdir()
    shutil.copy2(SCRIPT, tmp_path / "scripts" / SCRIPT.name)
    (pack / "pack.yaml").write_text("name: example\nversion: 0.1.0\n", encoding="utf-8")
    (pack / "engine.version").write_text(
        "engine: okengine\nversion: v0.13.5\nhermes_pin: v2026.7.7.2\n", encoding="utf-8"
    )
    (pack / "CHANGELOG.md").write_text("# Changelog\n\n## 0.1.0\n\nInitial.\n", encoding="utf-8")
    assert _run("git", "init", "-q", cwd=tmp_path).returncode == 0
    assert _run("git", "add", ".", cwd=tmp_path).returncode == 0
    assert _run(
        "git", "-c", "user.name=Test", "-c", "user.email=test@example.invalid",
        "commit", "-qm", "baseline", cwd=tmp_path,
    ).returncode == 0

    (pack / "engine.version").write_text(
        "engine: okengine\nversion: v0.14.3\nhermes_pin: v2026.9.14\n", encoding="utf-8"
    )
    assert _run("git", "add", str(pack / "engine.version"), cwd=tmp_path).returncode == 0
    assert _run(
        "git", "-c", "user.name=Test", "-c", "user.email=test@example.invalid",
        "commit", "-qm", "change engine requirement without pack release", cwd=tmp_path,
    ).returncode == 0
    result = _run("python3", str(tmp_path / "scripts" / SCRIPT.name), cwd=tmp_path)

    assert result.returncode == 1
    assert "engine.version" in result.stdout
    assert "bump `version:`" in result.stdout
