from __future__ import annotations

import contextlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from phi_boundary_gate import AuditResult, PhiBoundaryGate, audit_external_trace
from phi_boundary_gate.cli import main as cli_main


ROOT = Path(__file__).resolve().parents[1]
RAW_TRACE = ROOT / "samples/external_traces/generic_agent_run.jsonl"
MAPPING = ROOT / "samples/trace_mappings/generic_agent.yml"
POLICY = ROOT / "samples/policies/default.yml"


class DirectExternalAuditTests(unittest.TestCase):
    def test_sdk_helper_preserves_external_trace_path_and_diagnostics(self):
        gate = PhiBoundaryGate.from_policy_file(POLICY)

        with tempfile.TemporaryDirectory() as tmp:
            diagnostics = Path(tmp) / "diagnostics.json"
            result = audit_external_trace(
                gate,
                RAW_TRACE,
                mapping=MAPPING,
                diagnostics_path=diagnostics,
                report_value_mode="redacted",
            )

            self.assertIsInstance(result, AuditResult)
            self.assertEqual(result.to_dict()["trace_path"], str(RAW_TRACE))
            self.assertTrue(Path(result.to_dict()["trace_path"]).exists())
            self.assertEqual(result.to_dict()["schema_version"], 3)
            self.assertTrue(
                any(
                    finding.get("external_content_path")
                    for finding in result.findings
                )
            )
            self.assertNotIn("MBR-SYN-8842", json.dumps(result.to_dict()))

            diagnostics_payload = json.loads(
                diagnostics.read_text(encoding="utf-8")
            )
            self.assertEqual(diagnostics_payload["total_events"], 6)

    def test_sdk_facade_method_matches_function_helper(self):
        gate = PhiBoundaryGate.from_policy_file(POLICY)

        result = gate.audit_external_trace(
            RAW_TRACE,
            mapping=MAPPING,
            report_value_mode="hashed",
        )

        self.assertIsInstance(result, AuditResult)
        self.assertEqual(result.to_dict()["trace_path"], str(RAW_TRACE))
        self.assertNotIn("MBR-SYN-8842", json.dumps(result.to_dict()))

    def test_scan_external_trace_cli_writes_reports_and_preserves_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            report_md = tmp_path / "report.md"
            report_json = tmp_path / "report.json"
            diagnostics = tmp_path / "diagnostics.json"
            normalized = tmp_path / "normalized.jsonl"
            redacted = tmp_path / "redacted.jsonl"

            exit_code = cli_main(
                [
                    "scan-external-trace",
                    "--input",
                    str(RAW_TRACE),
                    "--mapping",
                    str(MAPPING),
                    "--policy",
                    str(POLICY),
                    "--out",
                    str(report_md),
                    "--json",
                    str(report_json),
                    "--diagnostics",
                    str(diagnostics),
                    "--normalized-trace",
                    str(normalized),
                    "--redacted-trace",
                    str(redacted),
                ]
            )

            self.assertEqual(exit_code, 0)
            for path in (
                report_md,
                report_json,
                diagnostics,
                normalized,
                redacted,
            ):
                self.assertTrue(path.exists(), path)

            payload = json.loads(report_json.read_text(encoding="utf-8"))
            self.assertEqual(payload["trace_path"], str(RAW_TRACE))
            self.assertGreaterEqual(payload["summary"]["total_findings"], 10)
            self.assertGreaterEqual(
                payload["summary"]["total_boundary_exposures"], 4
            )

            findings = payload.get("findings", [])
            self.assertTrue(findings)
            self.assertTrue(
                any(finding.get("external_content_path") for finding in findings),
                "expected at least one finding with external_content_path",
            )

            # Direct external scans are audit-safe by default.
            report_text = report_json.read_text(encoding="utf-8")
            self.assertNotIn("MBR-SYN-8842", report_text)

            diagnostics_payload = json.loads(
                diagnostics.read_text(encoding="utf-8")
            )
            self.assertEqual(diagnostics_payload["total_events"], 6)

    def test_invalid_mapping_returns_user_facing_error(self):
        stderr = io.StringIO()
        with tempfile.TemporaryDirectory() as tmp:
            with contextlib.redirect_stderr(stderr):
                exit_code = cli_main(
                    [
                        "scan-external-trace",
                        "--input",
                        str(RAW_TRACE),
                        "--mapping",
                        str(Path(tmp) / "missing.yml"),
                        "--policy",
                        str(POLICY),
                        "--out",
                        str(Path(tmp) / "report.md"),
                        "--json",
                        str(Path(tmp) / "report.json"),
                    ]
                )

        self.assertEqual(exit_code, 2)
        self.assertIn("error:", stderr.getvalue())

    def test_top_level_help_surfaces_new_command(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            with self.assertRaises(SystemExit) as exc:
                cli_main(["--help"])

        self.assertEqual(exc.exception.code, 0)
        self.assertIn("scan-external-trace", stdout.getvalue())

    def test_module_cli_help_routes_to_new_command(self):
        env = dict(**__import__("os").environ)
        env["PYTHONPATH"] = f"{ROOT / 'src'}:{ROOT}"
        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "phi_boundary_gate.cli",
                "scan-external-trace",
                "--help",
            ],
            check=True,
            capture_output=True,
            text=True,
            env=env,
        )

        self.assertIn("--mapping", completed.stdout)
        self.assertIn("--normalized-trace", completed.stdout)


if __name__ == "__main__":
    unittest.main()
