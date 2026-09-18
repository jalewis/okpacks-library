# Conformance

Proves the domain contract in `schema.yaml` is self-consistent and usable.

- `test_pages.py` — every `golden/*.md` page has a known `type`, all its type's required fields,
  and only valid values for enum-constrained fields. One golden page per owned type
  (actor/campaign/malware/tool/technique) plus core `source`/`concept`. Also self-tests that the
  checker CATCHES bad pages (bad enum, missing required).

Run: `python3 conformance/test_pages.py` (standalone, nonzero exit on failure; also pytest-discoverable).
No network — pure frontmatter parsing.
