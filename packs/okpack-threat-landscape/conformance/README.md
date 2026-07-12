# Conformance

`test_pages.py` proves `schema.yaml` is self-consistent: each `golden/*.md` page (one per owned type
`publisher`/`metric`, plus core `source`/`concept`) has required fields + only valid enum values, and the
self-test confirms bad pages are caught. Run: `python3 conformance/test_pages.py`.
