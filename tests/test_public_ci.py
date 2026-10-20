from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
ENGINE = "${{ github.workspace }}/.okengine-engine"


def _jobs():
    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))
    return workflow["jobs"]


def _engine_jobs():
    """Jobs whose commands need the engine: pack validation and strict conformance."""
    needs = ("scripts/validate-all.sh", "scripts/conformance-all.sh --strict")
    return {name: job for name, job in _jobs().items()
            if any(n in str(step.get("run", "")) for step in job["steps"] for n in needs)}


def test_public_validation_uses_the_catalog_pinned_engine():
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")

    assert "p['engine_version']" in workflow
    assert "repository: jalewis/OKEngine" in workflow
    assert "ref: ${{ steps.engine.outputs.ref }}" in workflow
    assert f"ENGINE_DIR: {ENGINE}" in workflow
    assert f"OKENGINE_DIR: {ENGINE}" in workflow


def test_the_engine_dependent_jobs_are_found():
    assert {"validate", "conformance"} <= set(_engine_jobs())


def test_every_engine_dependent_job_checks_out_the_catalog_pinned_engine():
    # Checked per job: a whole-file string match let `validate` vouch for `conformance`, whose
    # `--strict` run then failed public CI with no engine checkout.
    for name, job in _engine_jobs().items():
        checkouts = [s.get("with", {}) for s in job["steps"]
                     if str(s.get("uses", "")).startswith("actions/checkout")]
        assert any(w.get("repository") == "jalewis/OKEngine"
                   and w.get("ref") == "${{ steps.engine.outputs.ref }}"
                   and w.get("path") == ".okengine-engine" for w in checkouts), \
            f"job {name!r} must check out the catalog-pinned public engine"
        assert any("p['engine_version']" in str(s.get("run", "")) for s in job["steps"]), \
            f"job {name!r} must resolve the engine ref from catalog.json"


def test_strict_conformance_gets_the_engine_dir_and_its_package():
    # Matches the internal conformance job: OKENGINE_DIR for the suites that drive engine
    # scripts, and the engine's src/ on PYTHONPATH for those that import `okengine`.
    job = _jobs()["conformance"]
    step = next(s for s in job["steps"] if "conformance-all.sh --strict" in str(s.get("run", "")))
    env = step.get("env", {})
    assert env.get("OKENGINE_DIR") == ENGINE
    assert env.get("PYTHONPATH") == f"{ENGINE}/src"
