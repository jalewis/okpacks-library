# okpack-ai-research — conformance

Proves the domain contract in `schema.yaml` is self-consistent and usable. Two layers:

- **`../validate.py`** (offline, run by `scripts/validate-all.sh`): schema/feed/cron
  consistency, including `check_enums_wellformed` — every `field_enums` entry references a
  defined `enum`, and `by_type` targets are real types. It never reads the page tree.
- **`test_pages.py`** (run by `scripts/conformance-all.sh`): the page-VALUE check. Every
  `golden/*.md` page must have a known `type`, all of that type's required fields, and only
  in-vocabulary values for enum-constrained fields. Includes negative tests (a bad enum value
  and a missing required field must be caught) and a coverage test (every schema type has a
  golden page).

`golden/` holds one minimal, interlinked page per type — the canonical shape a generated
page should take. Run locally:

    python3 conformance/test_pages.py     # standalone, nonzero exit on failure
    pytest conformance/test_pages.py       # also pytest-discoverable

Pure stdlib + PyYAML; no network.
