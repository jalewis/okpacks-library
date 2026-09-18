#!/usr/bin/env python3
"""Conformance for aptnotes_import's actor matcher — which stored reports reach an actor.

The importer links a historical report to an actor by matching the report TITLE against known actor
aliases, behind a minimum alias length (`APTNOTES_MIN_ALIAS`, default 6) meant to stop short
free-text aliases false-matching. That floor also excluded the entire `APT<nn>` / `FIN<n>` /
`UNC<nn>` convention -- APT1 is 4 characters, APT28 and FIN7 are 5 -- which is precisely how
threat-intel reports title themselves.

Measured on a live vault: 1,808 historical sources with ~1.3% linked to any actor, against 91.3%
for the connector-ingested feed. Mandiant's "APT1: Exposing One of China's Cyber Espionage Units",
stored and graded A/1, linked to nothing -- so APT1's country assessment reported `single-source`
on the strength of an aggregator re-publishing MITRE's paragraph.

Length was the wrong instrument for ambiguity. The pair below is the contract: structured IDs link,
short free-text still does not.
"""
import importlib.util
import sys
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / "crons" / "scripts"
sys.path.insert(0, str(SCRIPTS))
spec = importlib.util.spec_from_file_location("aptnotes_import", SCRIPTS / "aptnotes_import.py")
aptnotes = importlib.util.module_from_spec(spec)
spec.loader.exec_module(aptnotes)


class AliasMatcherTests(unittest.TestCase):
    IDX = {
        "APT1": "entities/a/apt1.md",
        "APT28": "entities/a/apt28.md",
        "APT12": "entities/a/apt12.md",
        "FIN7": "entities/f/fin7.md",
        "UNC1706": "entities/u/unc1706.md",
        "G0006": "entities/a/apt1.md",
        "AMD": "entities/r/ransomhouse.md",          # short FREE-TEXT: genuinely ambiguous
        "Comment Crew": "entities/a/apt1.md",        # long free-text: always matched
    }

    def _match(self, title):
        pattern, stems = aptnotes._actor_matcher(self.IDX)
        if pattern is None:
            return set()
        return {stems[m] if m in stems else stems.get(m.upper(), m) for m in pattern.findall(title)}

    def test_the_report_that_started_this_now_links(self):
        """Mandiant's APT1 report: stored, graded A/1, and linked to nothing because its only actor
        identifier is four characters long."""
        hits = self._match("APT1: Exposing One of China's Cyber Espionage Units")
        self.assertIn("apt1", hits)

    def test_a_title_cased_identifier_still_links(self):
        """The stored title is title-cased to "Apt1 Exposing ..." by the import path, so the match
        has to be case-insensitive or the fix does nothing for the very page that motivated it."""
        self.assertIn("apt1", self._match("Apt1 Exposing One Of China's Cyber Espionage Units"))

    def test_structured_ids_below_the_floor_are_admitted(self):
        for title, expected in (("APT28 activity in Q3", "apt28"),
                                ("FIN7 returns to point-of-sale", "fin7"),
                                ("UNC1706 tooling overlap", "unc1706")):
            with self.subTest(title=title):
                self.assertIn(expected, self._match(title))

    def test_short_free_text_aliases_are_still_excluded(self):
        """The floor's real purpose. "AMD" resolves to an actor in this corpus; admitting it would
        tag every report mentioning the chip vendor. Ambiguity is the criterion, not length."""
        self.assertNotIn("ransomhouse", self._match("AMD patches a firmware flaw"))

    def test_a_short_id_does_not_match_a_longer_one(self):
        """The collision the length floor was guarding against never needed the floor: a word
        boundary already prevents APT1 from matching inside APT12."""
        hits = self._match("APT12 campaign analysis")
        self.assertIn("apt12", hits)
        self.assertNotIn("apt1", hits)

    def test_mitre_group_numbers_require_the_four_digit_form(self):
        """G0006 is a MITRE group id; "G20" is a summit. Only the padded form is an identifier."""
        self.assertIn("apt1", self._match("Profile of G0006"))
        self.assertEqual(set(), self._match("Leaders meet at the G20 summit"))

    def test_long_free_text_aliases_are_unaffected(self):
        self.assertIn("apt1", self._match("Comment Crew resurfaces"))


if __name__ == "__main__":
    unittest.main()
