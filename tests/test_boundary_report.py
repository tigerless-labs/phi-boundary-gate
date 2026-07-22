from __future__ import annotations

import json
import sys
import tempfile
import tomllib
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from phi_boundary_report import __version__, GuardDecision, ScanFinding, guard_text, redact_text, scan_text
from phi_boundary_report.cli import main
from phi_boundary_report.detectors import detect_candidates
from phi_boundary_report.policy import load_policy
from phi_boundary_report.report import build_report, write_markdown_report
from phi_boundary_report.trace import load_trace


class BoundaryReportTest(unittest.TestCase):
    def test_package_version_matches_project_metadata(self) -> None:
        metadata = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))

        self.assertEqual(__version__, metadata["project"]["version"])

    def test_detector_finds_labeled_synthetic_candidates(self) -> None:
        content = "Patient: Casey Example. DOB: 1978-04-18. Member ID: MBR-SYN-8842."

        candidates = detect_candidates(content)
        categories = {candidate.category for candidate in candidates}

        self.assertIn("name", categories)
        self.assertIn("dob", categories)
        self.assertIn("member_id", categories)

    def test_public_scan_text_returns_policy_decisions(self) -> None:
        policy = load_policy(ROOT / "samples/policies/default.yml")

        findings = scan_text("member_id=MBR-SYN-8842", layer="debug_log", policy=policy)

        self.assertEqual(len(findings), 1)
        self.assertIsInstance(findings[0], ScanFinding)
        self.assertEqual(findings[0].category, "member_id")
        self.assertEqual(findings[0].disposition, "violation")
        self.assertEqual(findings[0].redaction, "[REDACTED_MEMBER_ID]")

    def test_scan_finding_to_dict_preserves_existing_shape(self) -> None:
        policy = load_policy(ROOT / "samples/policies/default.yml")

        finding = scan_text("member_id=MBR-SYN-8842", layer="debug_log", policy=policy)[0]
        payload = finding.to_dict()

        self.assertEqual(payload["category"], "member_id")
        self.assertEqual(payload["span"], {"start": 10, "end": 22})
        self.assertEqual(payload["policy"]["disposition"], "violation")
        self.assertEqual(payload["redaction"]["suggested_value"], "[REDACTED_MEMBER_ID]")

    def test_redact_text_replaces_all_supplied_candidate_spans(self) -> None:
        policy = load_policy(ROOT / "samples/policies/default.yml")
        text = "member_id=MBR-SYN-8842 claim_id=CLM-SYN-44501 member_id=MBR-SYN-8842"
        findings = scan_text(text, layer="debug_log", policy=policy)

        redacted = redact_text(text, findings)

        self.assertNotIn("MBR-SYN-8842", redacted)
        self.assertNotIn("CLM-SYN-44501", redacted)
        self.assertEqual(redacted.count("[REDACTED_MEMBER_ID]"), 2)
        self.assertEqual(redacted.count("[REDACTED_CLAIM_ID]"), 1)

    def test_redact_text_leaves_no_phi_text_unchanged(self) -> None:
        text = "No identifiers here."

        self.assertEqual(redact_text(text, []), text)

    def test_guard_text_returns_violation_decision_and_redacted_text(self) -> None:
        policy = load_policy(ROOT / "samples/policies/default.yml")

        decision = guard_text("debug member_id=MBR-SYN-8842", layer="debug_log", policy=policy)

        self.assertIsInstance(decision, GuardDecision)
        self.assertTrue(decision.has_phi)
        self.assertTrue(decision.has_redactions)
        self.assertTrue(decision.has_violations)
        self.assertEqual(decision.worst_disposition, "violation")
        self.assertEqual(decision.redacted_text, "debug member_id=[REDACTED_MEMBER_ID]")
        self.assertFalse(decision.should_block)
        self.assertFalse(decision.should_redact)

    def test_guard_text_modes_set_block_and_redact_flags(self) -> None:
        policy = load_policy(ROOT / "samples/policies/default.yml")

        block_decision = guard_text("member_id=MBR-SYN-8842", layer="debug_log", policy=policy, mode="block_on_violation")
        redact_decision = guard_text("claim_id=CLM-SYN-44501", layer="model_input", policy=policy, mode="redact")

        self.assertTrue(block_decision.should_block)
        self.assertFalse(block_decision.should_redact)
        self.assertFalse(redact_decision.should_block)
        self.assertTrue(redact_decision.should_redact)

    def test_guard_decision_to_dict_preserves_api_shape(self) -> None:
        policy = load_policy(ROOT / "samples/policies/default.yml")

        payload = guard_text("member_id=MBR-SYN-8842", layer="debug_log", policy=policy, mode="block_on_violation").to_dict()

        self.assertEqual(payload["mode"], "block_on_violation")
        self.assertTrue(payload["should_block"])
        self.assertFalse(payload["should_redact"])
        self.assertEqual(payload["findings"][0]["category"], "member_id")

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
            self.assertIn("boundary_exposures", payload)

    def test_cli_writes_redacted_trace_when_requested(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            redacted_trace_path = tmp_path / "redacted.jsonl"

            with redirect_stdout(StringIO()):
                exit_code = main(
                    [
                        "--trace",
                        str(ROOT / "samples/traces/claim_agent_minimal.jsonl"),
                        "--policy",
                        str(ROOT / "samples/policies/default.yml"),
                        "--out",
                        str(tmp_path / "report.md"),
                        "--json",
                        str(tmp_path / "report.json"),
                        "--redacted-trace",
                        str(redacted_trace_path),
                    ]
                )

            self.assertEqual(exit_code, 0)
            redacted_trace = redacted_trace_path.read_text(encoding="utf-8")
            self.assertNotIn("MBR-SYN-8842", redacted_trace)
            self.assertNotIn("CLM-SYN-44501", redacted_trace)
            self.assertNotIn("Casey Example", redacted_trace)
            self.assertIn("[REDACTED_MEMBER_ID]", redacted_trace)

    def test_report_groups_repeated_candidates_into_boundary_exposures(self) -> None:
        trace = load_trace(ROOT / "samples/traces/claim_agent_minimal.jsonl")
        policy = load_policy(ROOT / "samples/policies/default.yml")

        report = build_report(trace, policy, ROOT / "samples/traces/claim_agent_minimal.jsonl", ROOT / "samples/policies/default.yml")
        member_exposure = next(
            exposure
            for exposure in report["boundary_exposures"]
            if exposure["category"] == "member_id" and exposure["value"] == "MBR-SYN-8842"
        )

        self.assertEqual(member_exposure["first_seen_event_id"], "evt_001")
        self.assertEqual(member_exposure["layers_seen"], ["user_message", "tool_output", "model_input", "debug_log"])
        self.assertEqual(member_exposure["worst_disposition"], "violation")
        self.assertEqual(member_exposure["worst_layer"], "debug_log")
        self.assertIn("Remove or redact before debug_log.", member_exposure["recommended_boundary_action"])

    def test_boundary_exposures_are_sorted_by_worst_disposition(self) -> None:
        trace = load_trace(ROOT / "samples/traces/claim_agent_minimal.jsonl")
        policy = load_policy(ROOT / "samples/policies/default.yml")

        report = build_report(trace, policy, ROOT / "samples/traces/claim_agent_minimal.jsonl", ROOT / "samples/policies/default.yml")
        severity = {"allowed": 0, "redact": 1, "violation": 2}
        severities = [severity[exposure["worst_disposition"]] for exposure in report["boundary_exposures"]]

        self.assertEqual(severities, sorted(severities, reverse=True))
        self.assertEqual(report["boundary_exposures"][0]["worst_disposition"], "violation")

    def test_no_phi_trace_writes_zero_findings(self) -> None:
        trace = load_trace(ROOT / "samples/traces/no_phi.jsonl")
        policy = load_policy(ROOT / "samples/policies/default.yml")

        report = build_report(trace, policy, ROOT / "samples/traces/no_phi.jsonl", ROOT / "samples/policies/default.yml")

        self.assertEqual(report["summary"]["total_findings"], 0)
        self.assertEqual(report["summary"]["total_boundary_exposures"], 0)
        self.assertEqual(report["findings"], [])
        self.assertEqual(report["boundary_exposures"], [])

    def test_markdown_includes_boundary_exposure_section(self) -> None:
        trace = load_trace(ROOT / "samples/traces/claim_agent_minimal.jsonl")
        policy = load_policy(ROOT / "samples/policies/default.yml")

        report = build_report(trace, policy, ROOT / "samples/traces/claim_agent_minimal.jsonl", ROOT / "samples/policies/default.yml")
        with tempfile.TemporaryDirectory() as tmp:
            markdown_path = Path(tmp) / "report.md"

            write_markdown_report(report, markdown_path)

            markdown = markdown_path.read_text(encoding="utf-8")
            self.assertIn("## Boundary Exposures", markdown)
            self.assertIn("MBR-SYN-8842", markdown)

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
