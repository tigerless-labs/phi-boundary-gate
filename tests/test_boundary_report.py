from __future__ import annotations

import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from phi_boundary_report.cli import main
from phi_boundary_report.detectors import detect_candidates
from phi_boundary_report.policy import load_policy
from phi_boundary_report.report import build_report
from phi_boundary_report.trace import load_trace


class BoundaryReportTest(unittest.TestCase):
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

    def test_no_phi_trace_writes_zero_findings(self) -> None:
        trace = load_trace(ROOT / "samples/traces/no_phi.jsonl")
        policy = load_policy(ROOT / "samples/policies/default.yml")

        report = build_report(trace, policy, ROOT / "samples/traces/no_phi.jsonl", ROOT / "samples/policies/default.yml")

        self.assertEqual(report["summary"]["total_findings"], 0)
        self.assertEqual(report["findings"], [])

    def test_trace_missing_required_content_fails(self) -> None:
        with self.assertRaisesRegex(ValueError, "missing required field\\(s\\): content"):
            load_trace(ROOT / "samples/traces/invalid_missing_content.jsonl")

    def test_trace_rejects_invalid_destination_layer(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            trace_path = Path(tmp) / "invalid_destination.jsonl"
            trace_path.write_text(
                '{"event_id":"evt_invalid_destination","timestamp":"2026-01-16T12:00:00Z",'
                '"layer":"tool_output","destinations":[{"layer":"external_vendor","path":"request.body"}],'
                '"content":"No identifiers here."}\n',
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "unsupported destination layer"):
                load_trace(trace_path)

    def test_policy_missing_redaction_fails(self) -> None:
        with self.assertRaisesRegex(ValueError, "must define a redaction string"):
            load_policy(ROOT / "samples/policies/invalid_missing_redaction.yml")

    def test_policy_rejects_unsupported_layer(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            policy_path = Path(tmp) / "invalid_layer.yml"
            policy_path.write_text(
                "version: 1\n"
                "categories:\n"
                "  member_id:\n"
                "    redaction: \"[REDACTED_MEMBER_ID]\"\n"
                "    deny_layers:\n"
                "      - model_provider\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "unsupported layer"):
                load_policy(policy_path)

    def test_policy_deny_precedes_redact(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            policy_path = Path(tmp) / "overlap.yml"
            policy_path.write_text(
                "version: 1\n"
                "categories:\n"
                "  member_id:\n"
                "    high_risk: true\n"
                "    redaction: \"[REDACTED_MEMBER_ID]\"\n"
                "    deny_layers:\n"
                "      - debug_log\n"
                "    redact_layers:\n"
                "      - debug_log\n",
                encoding="utf-8",
            )

            policy = load_policy(policy_path)
            decision = policy.decide("member_id", "debug_log")

            self.assertEqual(decision.disposition, "violation")

    def test_cli_returns_two_for_validation_errors(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            stderr = StringIO()

            with redirect_stderr(stderr):
                exit_code = main(
                    [
                        "--trace",
                        str(ROOT / "samples/traces/invalid_missing_content.jsonl"),
                        "--policy",
                        str(ROOT / "samples/policies/default.yml"),
                        "--out",
                        str(tmp_path / "report.md"),
                        "--json",
                        str(tmp_path / "report.json"),
                    ]
                )

            self.assertEqual(exit_code, 2)
            self.assertIn("missing required field(s): content", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
