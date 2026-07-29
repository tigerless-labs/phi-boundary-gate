from __future__ import annotations

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from phi_boundary_gate.detectors import detect_candidates  # noqa: E402
from phi_boundary_gate.policy import load_policy  # noqa: E402
from phi_boundary_gate.presidio_detector import detect_presidio_candidates  # noqa: E402
from phi_boundary_gate.report import build_report  # noqa: E402
from phi_boundary_gate.trace import load_trace  # noqa: E402


class FakeAnalyzer:
    def analyze(self, text: str, language: str, entities: list[str]) -> list[SimpleNamespace]:
        return [
            SimpleNamespace(entity_type="PERSON", start=text.index("Riley Stone"), end=text.index("Riley Stone") + 12, score=0.83),
            SimpleNamespace(entity_type="LOCATION", start=text.index("9 Pine Lane"), end=text.index("9 Pine Lane") + 11, score=0.72),
        ]


class HybridDetectionTest(unittest.TestCase):
    def test_regex_detector_finds_expanded_phi_variants(self) -> None:
        content = (
            "Patient Name: Casey M. Example. Call (555) 013-4421 ext 204. "
            "Email casey.example+claims@example.org. "
            "address: 101 Example Harbor Road, Apt 4B, Boston, MA 02118. "
            "Subscriber ID: W123456789 Policy Number: HIX-8831-2026 Group Number: GRP-48102 "
            "Account Number: 7749201 Medical Record Number: 000883921 SSN: 123-45-6789 "
            "URL https://portal.example.test/member/MBR-SYN-8842 IP 192.0.2.44"
        )

        categories = {candidate.category for candidate in detect_candidates(content)}

        self.assertIn("name", categories)
        self.assertIn("phone", categories)
        self.assertIn("email", categories)
        self.assertIn("address", categories)
        self.assertIn("member_id", categories)
        self.assertIn("policy_number", categories)
        self.assertIn("group_number", categories)
        self.assertIn("account_number", categories)
        self.assertIn("mrn", categories)
        self.assertIn("ssn", categories)
        self.assertIn("url", categories)
        self.assertIn("ip_address", categories)

    def test_expanded_sample_trace_builds_policy_decisions(self) -> None:
        trace_path = ROOT / "samples/traces/expanded_phi_variants.jsonl"
        policy_path = ROOT / "samples/policies/default.yml"

        report = build_report(load_trace(trace_path), load_policy(policy_path), trace_path, policy_path)
        categories = {finding["category"] for finding in report["findings"]}

        self.assertGreaterEqual(report["summary"]["total_findings"], 15)
        self.assertIn("ssn", categories)
        self.assertIn("email", categories)
        self.assertIn("vehicle_id", categories)
        self.assertIn("device_id", categories)
        self.assertGreater(report["summary"]["by_disposition"]["violation"], 0)

    def test_presidio_adapter_maps_spans_to_phi_candidates(self) -> None:
        text = "Riley Stone lives at 9 Pine Lane."

        candidates = detect_presidio_candidates(text, analyzer=FakeAnalyzer())

        self.assertEqual([candidate.category for candidate in candidates], ["name", "address"])
        self.assertEqual(candidates[0].value, "Riley Stone")
        self.assertEqual(candidates[0].detector, "presidio")
        self.assertEqual(candidates[1].value, "9 Pine Lane")

    def test_presidio_candidates_merge_with_regex_candidates(self) -> None:
        text = "Riley Stone called 555-013-4421 from 9 Pine Lane."

        candidates = detect_candidates(text, enable_presidio=True, presidio_analyzer=FakeAnalyzer())
        by_category = {candidate.category: candidate for candidate in candidates}

        self.assertEqual(by_category["phone"].detector, "regex")
        self.assertEqual(by_category["name"].detector, "presidio")
        self.assertEqual(by_category["address"].detector, "regex")


if __name__ == "__main__":
    unittest.main()
