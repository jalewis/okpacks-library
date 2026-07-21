import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


PACK = Path(__file__).resolve().parents[1]
SCRIPT = PACK / "crons" / "scripts" / "actor_evidence_export.py"
SPEC = importlib.util.spec_from_file_location("actor_evidence_export", SCRIPT)
exporter = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(exporter)


class ActorEvidenceExportTests(unittest.TestCase):
    def _vault(self, root: Path) -> Path:
        vault = root / "vault"
        entities = vault / "wiki" / "entities" / "a"
        entities.mkdir(parents=True)
        (vault / "pack.yaml").write_text("name: okpack-threat-actors\nversion: 0.1.0\n")
        (vault / "engine.version").write_text("version: v0.11.5\nhermes_pin: test\n")
        (entities / "alpha.md").write_text(
            "---\ntype: actor\nid: alpha\ntitle: Alpha\naliases: [Sample Bear]\n"
            "origin_country: IR\nattribution_confidence: suspected\n"
            "attribution_notes: Reporting associates Alpha with an Iranian nexus; tasking is not established.\n"
            "attribution_sources:\n"
            "  - id: source:report-1\n"
            "    url: https://example.invalid/report-1\n"
            "    title: Example Report\n"
            "    publisher: Example Publisher\n"
            "    source_kind: threat-report\n"
            "techniques: [T1059]\nsources: [source:report-1, Microsoft]\n---\n\nBody is not exported.\n"
        )
        (entities / "unsourced.md").write_text(
            "---\ntype: actor\nid: unsourced\ntitle: Unsourced\n---\n"
        )
        (entities / "tool.md").write_text("---\ntype: tool\nid: tool\ntitle: Tool\n---\n")
        return vault

    def test_export_is_allowlisted_deterministic_and_provenanced(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            output = root / "snapshot"
            result = exporter.export_snapshot(self._vault(root), output, "2026-07-15T12:00:00Z")
            payload = (output / "actors.ndjson").read_bytes()
            manifest = json.loads((output / "manifest.json").read_text())
            records = [json.loads(line) for line in payload.splitlines()]
            self.assertEqual(manifest["record_count"], 1)
            self.assertEqual(manifest["contract"], "okengine-evidence-snapshot/v2")
            self.assertEqual(manifest["producer"]["engine_version"], "v0.11.5")
            self.assertEqual(manifest["content_sha256"], hashlib.sha256(payload).hexdigest())
            self.assertEqual(records[0]["origin_country"], "IR")
            self.assertEqual(records[0]["attribution_confidence"], "suspected")
            self.assertEqual(records[0]["sources"], ["source:report-1", "Microsoft"])
            self.assertEqual(records[0]["source_records"][0]["independence_status"], "not-assessed")
            context_source = next(item for item in records[0]["source_records"]
                                  if item["source_ref"] == "Microsoft")
            self.assertEqual(context_source["citation_scope"], "entity-provenance")
            self.assertEqual(context_source["retrieval_status"], "publisher-or-dataset-root")
            claim_source = next(item for item in records[0]["source_records"]
                                if item["citation_scope"] == "reported-country-nexus")
            self.assertEqual(claim_source["retrieval_status"], "exact-page")
            self.assertTrue(claim_source["evidence_origin_id"].startswith("origin:"))
            claim = records[0]["attribution_claims"][0]
            self.assertEqual(claim["claim_kind"], "reported-country-nexus")
            self.assertEqual(claim["object"], "IR")
            self.assertEqual(claim["statement_kind"], "corpus-attribution-note")
            self.assertFalse(claim["verbatim"])
            self.assertEqual(claim["independence_status"], "not-assessed")
            self.assertEqual(claim["citation_status"], "claim-specific")
            self.assertEqual(claim["lineage_status"], "not-assessed")
            self.assertEqual(claim["source_refs"], ["source:report-1"])
            self.assertEqual(claim["context_source_refs"], ["Microsoft"])
            self.assertNotIn("body", records[0])
            self.assertNotIn("prompt", records[0])
            self.assertEqual(result["skipped"][0]["reason"], "missing source provenance")

    def test_existing_output_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            output = root / "snapshot"
            output.mkdir()
            with self.assertRaisesRegex(exporter.ExportError, "already exists"):
                exporter.export_snapshot(self._vault(root), output)

    def test_actor_attack_url_becomes_claim_specific_guidepost(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            vault = self._vault(root)
            actor = vault / "wiki" / "entities" / "a" / "alpha.md"
            text = actor.read_text().replace(
                "attribution_sources:\n  - id: source:report-1\n    url: https://example.invalid/report-1\n    title: Example Report\n    publisher: Example Publisher\n    source_kind: threat-report\n",
                "url: https://attack.mitre.org/groups/G0001/\n",
            )
            actor.write_text(text)
            record, reason = exporter.project_actor(actor, vault / "wiki" / "entities")
            self.assertIsNone(reason)
            claim = record["attribution_claims"][0]
            self.assertEqual(claim["citation_status"], "claim-specific")
            self.assertEqual(claim["source_refs"], ["https://attack.mitre.org/groups/G0001/"])
            citation = next(item for item in record["source_records"]
                            if item["citation_scope"] == "reported-country-nexus")
            self.assertEqual(citation["publisher_key"], "mitre-attack")


if __name__ == "__main__":
    unittest.main()
