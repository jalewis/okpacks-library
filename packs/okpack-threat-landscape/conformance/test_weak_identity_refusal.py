"""okpacks-library#96 / okengine#647: vendor-index must not mint a second SPELLING of a live page.

This pack carries its OWN byte-identical copy of `_okf_write.py` (the writer is duplicated
across five packs), and `vendor_index` is one of the three producers that was failing. A test
in okpack-threat-actors proves nothing about this copy, so the guarantee is pinned here too.

cron-plus's `slug_identity_guard` quarantines a page a deterministic run creates whose slug is
separator-equivalent to a live one, then FAILS the run. Three importers were dying that way every
Monday over a handful of entities -- `checkpoint` vs `check-point`, `toddycat` vs `toddy-cat`,
`aspxspy` vs `asp-xspy` -- losing the whole run for one or two records.

The fix is NOT to merge them. The engine states the rule in write_services/deduplication: "weak
spelling identity never auto-merges", because `check-point` and `checkpoint` may be different
things and reconciling them is an identity decision. So the writer refuses the create, says so, and
the run dispositions the record and continues.

`id_lib` is the governed identity library -- staged beside these scripts at runtime, absent in a
pack-only checkout. It is stubbed here with its documented contract; the writer imports it BY NAME
rather than re-deriving the rule, which is what keeps writer and guard agreeing.

Standalone: these suites run under plain python in public CI, so no pytest (no fixtures,
parametrize, capsys or monkeypatch) -- tempfile plus plain asserts, like the sibling suites.
"""
import contextlib
import importlib.util
import io
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "crons/scripts"


def _writer():
    """Load _okf_write with a stand-in for the governed identity library."""
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import _identity_standins
    sys.modules["id_lib"] = _identity_standins.id_lib_standin()
    if str(SCRIPTS) not in sys.path:
        sys.path.insert(0, str(SCRIPTS))
    spec = importlib.util.spec_from_file_location("_okf_write_probe", SCRIPTS / "_okf_write.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    _identity_standins.install(module, force=True)   # one consistent identity stand-in (#105)
    # Tolerate the symbol's absence on purpose: with the fix reverted these tests must FAIL on
    # behaviour (a page that should not exist does), not blow up on a missing attribute. A test
    # that errors before its assertions run never proved anything about the defect.
    getattr(module, "_IDENTITY_INDEX", {}).clear()
    return module


def _page(path: Path, title: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"---\ntype: actor\ntitle: {title}\n---\n\nBody\n", encoding="utf-8")


def test_refuses_to_create_a_separator_variant_of_a_live_page(tmp_path):
    writer, vault = _writer(), tmp_path / "wiki"
    _page(vault / "entities/c/h/check-point.md", "Check Point")
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        result = writer.write_page(vault, "entities/c/h/checkpoint.md", {"type": "actor"}, "Body")
    assert result == "collision", result
    assert not (vault / "entities/c/h/checkpoint.md").exists(), "the second spelling was created"
    message = err.getvalue()
    assert "weak-identity collision" in message, message
    assert "check-point" in message and "checkpoint" in message, message
    assert "647" in message, message


def test_does_not_merge_the_two_spellings(tmp_path):
    """Refusing is not merging. The live page must be left exactly as it was -- an importer may not
    fold one identity into another on the strength of punctuation."""
    writer, vault = _writer(), tmp_path / "wiki"
    _page(vault / "entities/t/o/toddy-cat.md", "Toddy Cat")
    before = (vault / "entities/t/o/toddy-cat.md").read_text()
    with contextlib.redirect_stderr(io.StringIO()):
        writer.write_page(vault, "entities/t/o/toddycat.md",
                          {"type": "actor", "title": "ToddyCat"}, "New")
    assert (vault / "entities/t/o/toddy-cat.md").read_text() == before


def test_an_exact_match_still_updates_rather_than_colliding(tmp_path):
    """The negative guard: the refusal must not block ordinary re-import of the SAME page."""
    writer, vault = _writer(), tmp_path / "wiki"
    _page(vault / "entities/c/h/checkpoint.md", "Check Point")
    with contextlib.redirect_stderr(io.StringIO()):
        result = writer.write_page(vault, "entities/c/h/checkpoint.md", {"type": "actor"},
                                   "Updated body")
    assert result == "updated", result
    assert "Updated body" in (vault / "entities/c/h/checkpoint.md").read_text()


def test_a_genuinely_new_page_is_still_created(tmp_path):
    writer, vault = _writer(), tmp_path / "wiki"
    _page(vault / "entities/c/h/checkpoint.md", "Check Point")
    with contextlib.redirect_stderr(io.StringIO()):
        result = writer.write_page(vault, "entities/a/p/apt29.md", {"type": "actor"}, "Body")
    assert result == "created", result
    assert (vault / "entities/a/p/apt29.md").exists()


def test_one_run_cannot_mint_two_spellings_of_the_same_new_entity(tmp_path):
    """The index is updated on write, so the second spelling collides against the first even though
    neither existed when the run started -- the case a pre-run snapshot alone would miss."""
    writer, vault = _writer(), tmp_path / "wiki"
    (vault / "entities").mkdir(parents=True)
    with contextlib.redirect_stderr(io.StringIO()):
        first = writer.write_page(vault, "entities/n/e/new-zealand.md", {"type": "actor"}, "A")
        second = writer.write_page(vault, "entities/n/e/newzealand.md", {"type": "actor"}, "B")
    assert first == "created", first
    assert second == "collision", second
    assert not (vault / "entities/n/e/newzealand.md").exists()


def test_the_writer_uses_the_governed_identity_library_not_its_own_rule(tmp_path):
    """Writer and guard must compute identity the SAME way; a private reimplementation would drift,
    and the drift would only show up as a quarantined page and a failed run."""
    source = (SCRIPTS / "_okf_write.py").read_text(encoding="utf-8")
    assert "import id_lib" in source
    assert "id_lib.slug_identity" in source


if __name__ == "__main__":
    # conformance-all.sh runs this file as a SCRIPT, not under pytest, so the tests must be called
    # here or they are merely defined -- the suite would exit 0 having asserted nothing, and the
    # coverage lane would measure the code under test as unexercised. Each test gets its own
    # temporary directory, standing in for pytest's tmp_path.
    import tempfile

    for case in (
        test_refuses_to_create_a_separator_variant_of_a_live_page,
        test_does_not_merge_the_two_spellings,
        test_an_exact_match_still_updates_rather_than_colliding,
        test_a_genuinely_new_page_is_still_created,
        test_one_run_cannot_mint_two_spellings_of_the_same_new_entity,
        test_the_writer_uses_the_governed_identity_library_not_its_own_rule,
    ):
        with tempfile.TemporaryDirectory() as tmp:
            case(Path(tmp))
    print("ok")
