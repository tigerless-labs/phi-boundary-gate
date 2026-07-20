from __future__ import annotations

import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from phi_boundary_report.cli import main
from phi_boundary_report.detectors import detect_candidates
from phi_boundary_report.policy import load_policy
from phi_boundary_report.report import build_report
from phi_boundary_report.trace import load_trace


class MVPTest(unittest.TestCase):
    def test_detector_finds_labeled_synthetic_candidates(self) -> None:
        content = "Patient: Casey Example. DOB: 1978-04-18. Member ID: MBR-SYN-8842."

        candidates = detect_candidates(content)
        categories = {candidate.category for candidate in candidates}

        self.assertIn("name", categories)
        self.assertIn("dob", categories)
        self.assertIn("member_id", categories)

    def test_policy_flags_debug_log_identifier_as_violation(self) -> None:
        trace = load_trace(ROOT / "samples/traces/claim_agent_minimal.jsonl")
        policy = load_policy(ROOT / "samples/policies/default.yml")

        report = build_report(trace, policy, ROOT / "samples/traces/claim_agent_minimal.jsonl", ROOT / "samples/policies/default.yml")
        debug_member_findings = [
            finding
            for finding in report["findings"]
            if finding["layer"] == "debug_log" and finding["category"] == "member_id"
        ]

        self.assertEqual(len(debug_member_findings), 1)
        self.assertEqual(debug_member_findings[0]["policy"]["disposition"], "violation")

    def test_cli_writes_markdown_and_json_reports(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            markdown_path = tmp_path / "report.md"
            json_path = tmp_path / "report.json"

            with redirect_stdout(StringIO()):
                exit_code = main(
                    [
                        "--trace",
                        str(ROOT / "samples/traces/claim_agent_minimal.jsonl"),
                        "--policy",
                        str(ROOT / "samples/policies/default.yml"),
                        "--out",
                        str(markdown_path),
                        "--json",
                        str(json_path),
                    ]
                )

            self.assertEqual(exit_code, 0)
            self.assertIn("PHI Context Boundary Report", markdown_path.read_text(encoding="utf-8"))
            payload = json.loads(json_path.read_text(encoding="utf-8"))
            self.assertGreater(payload["summary"]["total_findings"], 0)
            self.assertIn("findings", payload)


if __name__ == "__main__":
    unittest.main()
