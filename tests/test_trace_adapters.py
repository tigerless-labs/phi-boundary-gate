from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from phi_boundary_gate.adapters import load_external_trace, write_converted_trace  # noqa: E402
from phi_boundary_gate.cli import main  # noqa: E402
from phi_boundary_gate.policy import load_policy  # noqa: E402
from phi_boundary_gate.report import build_report  # noqa: E402
from phi_boundary_gate.trace import load_trace  # noqa: E402


class TraceAdaptersTest(unittest.TestCase):
    def subprocess_env(self) -> dict[str, str]:
        env = os.environ.copy()
        env["PYTHONPATH"] = str(ROOT / "src")
        return env

    def test_generic_jsonl_mapping_converts_sample_trace(self) -> None:
        events = load_external_trace(
            ROOT / "samples/external_traces/generic_agent_run.jsonl",
            ROOT / "samples/trace_mappings/generic_agent.yml",
        )

        self.assertEqual(len(events), 6)
        self.assertEqual(events[0].layer, "user_message")
        self.assertEqual(events[2].layer, "tool_output")
        self.assertIn("tool_summary:", events[2].content)
        self.assertIn("member_id: MBR-SYN-8842", events[2].content)
        self.assertEqual(events[3].destinations, [{"layer": "model_provider", "path": "responses.create"}])
        self.assertEqual(events[3].metadata["external_content_paths"], ["prompt.system", "prompt.user"])
        self.assertEqual(events[5].metadata["agent_node"], "logger")

    def test_generic_jsonl_conversion_matches_golden_trace(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output_path = Path(tmp) / "normalized.jsonl"

            write_converted_trace(
                ROOT / "samples/external_traces/generic_agent_run.jsonl",
                ROOT / "samples/trace_mappings/generic_agent.yml",
                output_path,
            )

            self.assertEqual(
                output_path.read_text(encoding="utf-8"),
                (ROOT / "samples/normalized_traces/generic_agent_expected.jsonl").read_text(encoding="utf-8"),
            )

    def test_converted_trace_can_be_scanned_by_existing_report_flow(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            trace_path = Path(tmp) / "normalized.jsonl"
            write_converted_trace(
                ROOT / "samples/external_traces/generic_agent_run.jsonl",
                ROOT / "samples/trace_mappings/generic_agent.yml",
                trace_path,
            )

            events = load_trace(trace_path)
            policy = load_policy(ROOT / "samples/policies/default.yml")
            report = build_report(events, policy, trace_path, ROOT / "samples/policies/default.yml")

            self.assertGreaterEqual(report["summary"]["total_findings"], 10)
            self.assertGreaterEqual(report["summary"]["total_boundary_exposures"], 4)
            self.assertIn("model_input", report["summary"]["by_layer"])

    def test_missing_optional_event_id_uses_generated_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            raw_path = tmp_path / "raw.jsonl"
            mapping_path = tmp_path / "mapping.yml"
            raw_path.write_text(
                '{"created_at":"2026-02-03T15:00:00Z","event_type":"human",'
                '"payload":{"text":"Member ID: MBR-SYN-8842"}}\n',
                encoding="utf-8",
            )
            mapping_path.write_text(
                "version: 1\n"
                "event_id:\n"
                "  field: missing_id\n"
                "  required: false\n"
                "  fallback_prefix: agent_evt\n"
                "timestamp: created_at\n"
                "layer:\n"
                "  field: event_type\n"
                "  map:\n"
                "    human: user_message\n"
                "content: payload.text\n",
                encoding="utf-8",
            )

            events = load_external_trace(raw_path, mapping_path)

            self.assertEqual(events[0].event_id, "agent_evt_0001")

    def test_missing_required_content_field_fails_clearly(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            raw_path = tmp_path / "raw.jsonl"
            mapping_path = tmp_path / "mapping.yml"
            raw_path.write_text('{"id":"evt","created_at":"2026-02-03T15:00:00Z","event_type":"human"}\n', encoding="utf-8")
            mapping_path.write_text(
                "version: 1\n"
                "event_id: id\n"
                "timestamp: created_at\n"
                "layer:\n"
                "  field: event_type\n"
                "  map:\n"
                "    human: user_message\n"
                "content: payload.text\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "missing field 'payload.text'"):
                load_external_trace(raw_path, mapping_path)

    def test_invalid_mapped_layer_fails_clearly(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            raw_path = tmp_path / "raw.jsonl"
            mapping_path = tmp_path / "mapping.yml"
            raw_path.write_text(
                '{"id":"evt","created_at":"2026-02-03T15:00:00Z","event_type":"unknown",'
                '"payload":{"text":"No identifiers."}}\n',
                encoding="utf-8",
            )
            mapping_path.write_text(
                "version: 1\n"
                "event_id: id\n"
                "timestamp: created_at\n"
                "layer: event_type\n"
                "content: payload.text\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "unsupported layer"):
                load_external_trace(raw_path, mapping_path)

    def test_array_index_out_of_range_fails_clearly(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            raw_path = tmp_path / "raw.jsonl"
            mapping_path = tmp_path / "mapping.yml"
            raw_path.write_text(
                '{"id":"evt","created_at":"2026-02-03T15:00:00Z","event_type":"human",'
                '"messages":[]}\n',
                encoding="utf-8",
            )
            mapping_path.write_text(
                "version: 1\n"
                "event_id: id\n"
                "timestamp: created_at\n"
                "layer:\n"
                "  field: event_type\n"
                "  map:\n"
                "    human: user_message\n"
                "content: messages.0.content\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "list index 0 out of range"):
                load_external_trace(raw_path, mapping_path)

    def test_all_optional_content_fields_missing_fails_clearly(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            raw_path = tmp_path / "raw.jsonl"
            mapping_path = tmp_path / "mapping.yml"
            raw_path.write_text(
                '{"id":"evt","created_at":"2026-02-03T15:00:00Z","event_type":"human"}\n',
                encoding="utf-8",
            )
            mapping_path.write_text(
                "version: 1\n"
                "event_id: id\n"
                "timestamp: created_at\n"
                "layer:\n"
                "  field: event_type\n"
                "  map:\n"
                "    human: user_message\n"
                "content:\n"
                "  fields:\n"
                "    - field: payload.text\n"
                "      required: false\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "no content fields produced text"):
                load_external_trace(raw_path, mapping_path)

    def test_object_content_is_serialized_for_scanning(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            raw_path = tmp_path / "raw.jsonl"
            mapping_path = tmp_path / "mapping.yml"
            raw_path.write_text(
                '{"id":"evt","created_at":"2026-02-03T15:00:00Z","event_type":"tool",'
                '"payload":{"member_id":"MBR-SYN-8842","claim_id":"CLM-SYN-44501"}}\n',
                encoding="utf-8",
            )
            mapping_path.write_text(
                "version: 1\n"
                "event_id: id\n"
                "timestamp: created_at\n"
                "layer:\n"
                "  field: event_type\n"
                "  map:\n"
                "    tool: tool_output\n"
                "content: payload\n",
                encoding="utf-8",
            )

            events = load_external_trace(raw_path, mapping_path)

            self.assertIn('"member_id": "MBR-SYN-8842"', events[0].content)

    def test_invalid_yaml_mapping_fails_validation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            mapping_path = Path(tmp) / "mapping.yml"
            mapping_path.write_text("version: [\n", encoding="utf-8")

            stderr = StringIO()
            with redirect_stderr(stderr):
                exit_code = main(["validate-mapping", "--mapping", str(mapping_path)])

            self.assertEqual(exit_code, 2)
            self.assertIn("error:", stderr.getvalue())

    def test_cli_convert_trace_and_validate_trace(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output_path = Path(tmp) / "normalized.jsonl"

            with redirect_stdout(StringIO()) as stdout:
                exit_code = main(
                    [
                        "convert-trace",
                        "--input",
                        str(ROOT / "samples/external_traces/generic_agent_run.jsonl"),
                        "--mapping",
                        str(ROOT / "samples/trace_mappings/generic_agent.yml"),
                        "--out",
                        str(output_path),
                    ]
                )

            self.assertEqual(exit_code, 0)
            self.assertIn("Wrote 6 normalized event(s)", stdout.getvalue())
            self.assertEqual(len(load_trace(output_path)), 6)

            with redirect_stdout(StringIO()) as validate_stdout:
                self.assertEqual(main(["validate-trace", "--trace", str(output_path)]), 0)
            self.assertIn("Trace ok:", validate_stdout.getvalue())
            self.assertIn("Events: 6", validate_stdout.getvalue())

    def test_cli_validate_mapping(self) -> None:
        with redirect_stdout(StringIO()) as stdout:
            exit_code = main(["validate-mapping", "--mapping", str(ROOT / "samples/trace_mappings/generic_agent.yml")])

        self.assertEqual(exit_code, 0)
        self.assertIn("Mapping ok:", stdout.getvalue())
        self.assertIn("Content fields:", stdout.getvalue())
        self.assertIn("Layer aliases:", stdout.getvalue())

    def test_subprocess_cli_convert_validate_and_scan(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            normalized = tmp_path / "normalized.jsonl"
            report = tmp_path / "report.md"
            report_json = tmp_path / "report.json"

            convert = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "phi_boundary_gate.cli",
                    "convert-trace",
                    "--input",
                    str(ROOT / "samples/external_traces/generic_agent_run.jsonl"),
                    "--mapping",
                    str(ROOT / "samples/trace_mappings/generic_agent.yml"),
                    "--out",
                    str(normalized),
                ],
                cwd=ROOT,
                env=self.subprocess_env(),
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(convert.returncode, 0, convert.stderr)
            self.assertIn("Wrote 6 normalized event(s)", convert.stdout)

            validate = subprocess.run(
                [sys.executable, "-m", "phi_boundary_gate.cli", "validate-trace", "--trace", str(normalized)],
                cwd=ROOT,
                env=self.subprocess_env(),
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(validate.returncode, 0, validate.stderr)
            self.assertIn("Events: 6", validate.stdout)

            scan = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "phi_boundary_gate.cli",
                    "scan-trace",
                    "--trace",
                    str(normalized),
                    "--policy",
                    str(ROOT / "samples/policies/default.yml"),
                    "--out",
                    str(report),
                    "--json",
                    str(report_json),
                ],
                cwd=ROOT,
                env=self.subprocess_env(),
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(scan.returncode, 0, scan.stderr)
            self.assertIn("Wrote 15 PHI candidate finding(s)", scan.stdout)
            self.assertTrue(report.is_file())
            self.assertTrue(report_json.is_file())

    def test_cli_convert_trace_stdout_keeps_jsonl_on_stdout(self) -> None:
        stdout = StringIO()
        stderr = StringIO()

        with redirect_stdout(stdout), redirect_stderr(stderr):
            exit_code = main(
                [
                    "convert-trace",
                    "--input",
                    str(ROOT / "samples/external_traces/generic_agent_run.jsonl"),
                    "--mapping",
                    str(ROOT / "samples/trace_mappings/generic_agent.yml"),
                    "--stdout",
                ]
            )

        self.assertEqual(exit_code, 0)
        rows = [json.loads(line) for line in stdout.getvalue().splitlines()]
        self.assertEqual(len(rows), 6)
        self.assertEqual(rows[0]["layer"], "user_message")
        self.assertIn("Converted 6 normalized event(s)", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
