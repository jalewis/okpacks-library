# Conformance

`test_pages.py` proves `schema.yaml` is self-consistent: each `golden/*.md` page (one per owned type
`cve`, plus core `source`/`concept`) has the required fields + only valid enum values, and the checker
self-test confirms it CATCHES bad pages. Run: `python3 conformance/test_pages.py`.
