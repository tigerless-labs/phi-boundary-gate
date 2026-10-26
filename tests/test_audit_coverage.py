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

from phi_boundary_gate import AuditCoverageResult, PhiBoundaryGate, build_audit_coverage
from phi_boundary_gate.adapters import TraceAdapter
from phi_boundary_gate.cli import main
from phi_boundary_gate.trace import TraceEvent


ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "samples/policies/default.yml"
NO_PHI_TRACE = ROOT / "samples/traces/no_phi.jsonl"


def _event(
    event_id: str,
    layer: str,
    content: str,
    *,
    source: dict | None = None,
    destinations: list[dict] | None = None,
) -> TraceEvent:
    return TraceEvent(
        event_id=event_id,
        timestamp="2026-10-26T00:00:00Z",
        layer=layer,
        content=content,
        source=source or {},
        destinations=destinations or [],
    )


def _codes(result: AuditCoverageResult) -> list[str]:
    return [diagnostic["code"] for diagnostic in result.diagnostics]


class AuditCoverageTests(unittest.TestCase):
    def test_complete_multilayer_trace_counts_observed_scope(self) -> None:
        events = [
            _event(
                "evt-1",
                "user_message",
                "Synthetic request",
                source={"type": "synthetic"},
                destinations=[{"layer": "model_input"}],
            ),
            _event(
                "evt-2",
                "tool_output",
                '{"claim":"ready","attempt":2}',
                source={"type": "synthetic_tool"},
                destinations=[{"layer": "model_input"}],
            ),
            _event(
                "evt-3",
                "model_input",
                "Synthetic prompt",
                destinations=[{"layer": "model_provider"}],
            ),
        ]

        result = build_audit_coverage(
            events,
            expected_layers=["tool_output", "model_input", "user_message"],
        )

        self.assertEqual(
            result.summary,
            {
                "observed_event_count": 3,
                "events_by_layer": {"model_input": 1, "tool_output": 1, "user_message": 1},
                "empty_content_event_count": 0,
                "nonempty_content_event_count": 3,
                "scannable_segment_count": 4,
                "structured_content_event_count": 1,
                "structured_content_without_scalar_event_count": 0,
                "events_with_source_count": 2,
                "events_with_destinations_count": 3,
                "provider_destination_event_count": 1,
            },
        )
        self.assertEqual(result.diagnostics, [])

    def test_empty_trace_and_expected_layer_are_advisory(self) -> None:
        result = build_audit_coverage([], expected_layers=["model_input"])

        self.assertEqual(result.summary["observed_event_count"], 0)
        self.assertEqual(
            _codes(result),
            ["EMPTY_TRACE", "EXPECTED_LAYER_NOT_OBSERVED"],
        )
        self.assertEqual(result.diagnostics[1]["layers"], ["model_input"])

    def test_blank_and_scalarless_structured_content_are_counted_as_empty(self) -> None:
        result = build_audit_coverage(
            [
                _event("evt-1", "user_message", "  \n"),
                _event("evt-2", "tool_output", "{}"),
                _event("evt-3", "model_input", '{"empty":[],"value":null}'),
            ],
            expected_layers=["user_message", "tool_output", "model_input"],
        )

        self.assertEqual(result.summary["empty_content_event_count"], 3)
        self.assertEqual(result.summary["nonempty_content_event_count"], 0)
        self.assertEqual(result.summary["scannable_segment_count"], 0)
        self.assertEqual(result.summary["structured_content_event_count"], 2)
        self.assertEqual(result.summary["structured_content_without_scalar_event_count"], 2)
        self.assertEqual(_codes(result)[:2], ["EMPTY_CONTENT_EVENTS", "NO_EXPLICIT_DESTINATIONS"])

    def test_user_only_trace_does_not_invent_missing_execution_layers(self) -> None:
        result = build_audit_coverage([_event("evt-1", "user_message", "No identifiers.")])

        self.assertNotIn("EXPECTED_LAYER_NOT_OBSERVED", _codes(result))
        self.assertIn("COVERAGE_UNVERIFIED", _codes(result))
        self.assertEqual(result.to_dict()["expected_layers"], [])

    def test_only_explicit_expected_layers_can_be_reported_missing(self) -> None:
        result = build_audit_coverage(
            [_event("evt-1", "user_message", "No identifiers.")],
            expected_layers=["tool_output", "model_input"],
        )

        expected_warning = next(
            diagnostic
            for diagnostic in result.diagnostics
            if diagnostic["code"] == "EXPECTED_LAYER_NOT_OBSERVED"
        )
        self.assertEqual(expected_warning["layers"], ["model_input", "tool_output"])
        self.assertNotIn("COVERAGE_UNVERIFIED", _codes(result))

    def test_structured_json_plain_text_and_empty_object_have_distinct_counts(self) -> None:
        result = build_audit_coverage(
            [
                _event("evt-1", "tool_output", '{"name":"Example","count":2,"ok":true,"none":null}'),
                _event("evt-2", "tool_output", "{}"),
                _event("evt-3", "tool_output", "ordinary text"),
            ],
            expected_layers=["tool_output"],
        )

        self.assertEqual(result.summary["structured_content_event_count"], 2)
        self.assertEqual(result.summary["structured_content_without_scalar_event_count"], 1)
        self.assertEqual(result.summary["scannable_segment_count"], 4)
        self.assertEqual(result.summary["empty_content_event_count"], 1)

    def test_source_destination_and_provider_counts_are_event_based(self) -> None:
        result = build_audit_coverage(
            [
                _event("evt-1", "user_message", "one", source={"type": "synthetic"}),
                _event(
                    "evt-2",
                    "model_input",
                    "two",
                    destinations=[{"layer": "model_provider"}, {"layer": "debug_log"}],
                ),
                _event(
                    "evt-3",
                    "model_input",
                    "three",
                    source={"path": "synthetic"},
                    destinations=[{"layer": "model_provider"}],
                ),
            ],
            expected_layers=["user_message", "model_input"],
        )

        self.assertEqual(result.summary["events_with_source_count"], 2)
        self.assertEqual(result.summary["events_with_destinations_count"], 2)
        self.assertEqual(result.summary["provider_destination_event_count"], 2)

    def test_nonprovider_destinations_use_factual_provider_warning(self) -> None:
        result = build_audit_coverage(
            [
                _event(
                    "evt-1",
                    "user_message",
                    "No identifiers.",
                    destinations=[{"layer": "model_input"}],
                )
            ],
            expected_layers=["user_message"],
        )

        self.assertIn("NO_PROVIDER_DESTINATION_OBSERVED", _codes(result))
        self.assertNotIn("NO_EXPLICIT_DESTINATIONS", _codes(result))

    def test_mapping_evidence_is_aggregate_and_does_not_claim_dropped_events(self) -> None:
        result = build_audit_coverage(
            [_event("evt-1", "user_message", "No identifiers.")],
            expected_layers=["user_message"],
            mapping_diagnostics={
                "optional_content_paths_never_used": ["secret.raw_key", "payload.<script>"],
                "total_events": 999,
            },
        )
        encoded = json.dumps(result.to_dict(), sort_keys=True)

        self.assertEqual(result.to_dict()["mapping"], {"optional_content_fields_unused_count": 2})
        self.assertIn("MAPPING_OPTIONAL_CONTENT_UNUSED", _codes(result))
        self.assertNotIn("secret.raw_key", encoded)
        self.assertNotIn("payload.<script>", encoded)
        self.assertNotIn("dropped", encoded.lower())

    def test_sdk_and_cli_outputs_are_identical_and_deterministic(self) -> None:
        gate = PhiBoundaryGate.from_policy_file(POLICY)
        expected_layers = ["model_input", "user_message"]
        sdk_result = gate.coverage_trace(NO_PHI_TRACE, expected_layers=expected_layers)

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            arguments = [
                "scan-trace",
                "--trace",
                str(NO_PHI_TRACE),
                "--policy",
                str(POLICY),
                "--out",
                str(tmp_path / "report.md"),
                "--json",
                str(tmp_path / "report.json"),
                "--coverage-json",
                str(tmp_path / "coverage.json"),
                "--coverage-markdown",
                str(tmp_path / "coverage.md"),
                "--expect-layer",
                "model_input",
                "--expect-layer",
                "user_message",
            ]
            with redirect_stdout(StringIO()):
                self.assertEqual(main(arguments), 0)
            first_json = (tmp_path / "coverage.json").read_text(encoding="utf-8")
            first_markdown = (tmp_path / "coverage.md").read_text(encoding="utf-8")
            with redirect_stdout(StringIO()):
                self.assertEqual(main(arguments), 0)

            self.assertEqual(json.loads(first_json), sdk_result.to_dict())
            self.assertEqual(first_json, (tmp_path / "coverage.json").read_text(encoding="utf-8"))
            self.assertEqual(first_markdown, sdk_result.to_markdown())
            self.assertEqual(first_markdown, (tmp_path / "coverage.md").read_text(encoding="utf-8"))

    def test_sdk_coverage_example_runs_from_source_path(self) -> None:
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(ROOT / "src")

        completed = subprocess.run(
            [sys.executable, str(ROOT / "examples/sdk_audit_coverage.py")],
            check=True,
            capture_output=True,
            text=True,
            env=environment,
        )
        payload = json.loads(completed.stdout)

        self.assertEqual(payload["schema_version"], 1)
        self.assertIn("EXPECTED_LAYER_NOT_OBSERVED", [item["code"] for item in payload["diagnostics"]])

    def test_coverage_outputs_do_not_copy_phi_trace_paths_or_content(self) -> None:
        secret = "MBR-SYN-PRIVATE-9911"
        event = _event(
            "sensitive-event-id",
            "user_message",
            f"Member ID: {secret}",
            source={"path": "/private/records/patient.json"},
            destinations=[{"layer": "model_input", "path": "prompt.<script>"}],
        )
        result = build_audit_coverage(
            [event],
            expected_layers=["user_message"],
            mapping_diagnostics={"optional_content_paths_never_used": ["private.raw.key"]},
        )
        rendered = json.dumps(result.to_dict()) + result.to_markdown()

        for forbidden in (
            secret,
            "sensitive-event-id",
            "/private/records/patient.json",
            "prompt.<script>",
            "private.raw.key",
        ):
            self.assertNotIn(forbidden, rendered)

    def test_default_cli_report_and_stdout_stay_unchanged_without_coverage(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            base_args = [
                "scan-trace",
                "--trace",
                str(NO_PHI_TRACE),
                "--policy",
                str(POLICY),
                "--out",
                str(tmp_path / "report.md"),
                "--json",
                str(tmp_path / "report.json"),
            ]
            stdout = StringIO()
            with redirect_stdout(stdout):
                self.assertEqual(main(base_args), 0)

            report_json = (tmp_path / "report.json").read_text(encoding="utf-8")
            report_markdown = (tmp_path / "report.md").read_text(encoding="utf-8")
            self.assertNotIn("coverage", stdout.getvalue().lower())
            self.assertNotIn("coverage", json.loads(report_json)["summary"])
            self.assertFalse((tmp_path / "coverage.json").exists())

            coverage_stdout = StringIO()
            with redirect_stdout(coverage_stdout):
                self.assertEqual(
                    main(base_args + ["--coverage-json", str(tmp_path / "coverage.json")]),
                    0,
                )

            self.assertTrue(coverage_stdout.getvalue().startswith(stdout.getvalue()))
            self.assertEqual(report_json, (tmp_path / "report.json").read_text(encoding="utf-8"))
            self.assertEqual(report_markdown, (tmp_path / "report.md").read_text(encoding="utf-8"))

    def test_coverage_warnings_and_zero_findings_keep_cli_exit_zero(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            with redirect_stdout(StringIO()):
                exit_code = main(
                    [
                        "scan-trace",
                        "--trace",
                        str(NO_PHI_TRACE),
                        "--policy",
                        str(POLICY),
                        "--out",
                        str(tmp_path / "report.md"),
                        "--json",
                        str(tmp_path / "report.json"),
                        "--coverage-json",
                        str(tmp_path / "coverage.json"),
                        "--expect-layer",
                        "model_input",
                    ]
                )

            self.assertEqual(exit_code, 0)
            self.assertEqual(json.loads((tmp_path / "report.json").read_text())["summary"]["total_findings"], 0)
            self.assertIn(
                "EXPECTED_LAYER_NOT_OBSERVED",
                [item["code"] for item in json.loads((tmp_path / "coverage.json").read_text())["diagnostics"]],
            )

    def test_external_cli_reuses_mapping_evidence_without_leaking_keys(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            raw = tmp_path / "private-input.jsonl"
            mapping = tmp_path / "mapping.yml"
            raw.write_text(
                '{"id":"evt","ts":"2026-10-26T00:00:00Z","kind":"human",'
                '"payload":{"text":"No identifiers."}}\n',
                encoding="utf-8",
            )
            mapping.write_text(
                "version: 1\n"
                "event_id: id\n"
                "timestamp: ts\n"
                "layer:\n"
                "  field: kind\n"
                "  map:\n"
                "    human: user_message\n"
                "content:\n"
                "  fields:\n"
                "    - field: payload.text\n"
                "      required: true\n"
                "    - field: private.unused_key\n"
                "      required: false\n",
                encoding="utf-8",
            )
            adapter = TraceAdapter.from_mapping(mapping)
            events = adapter.load(raw)
            evidence = adapter.coverage_diagnostics(events)
            self.assertEqual(evidence["optional_content_paths_never_used"], ["private.unused_key"])

            with redirect_stdout(StringIO()):
                exit_code = main(
                    [
                        "scan-external-trace",
                        "--input",
                        str(raw),
                        "--mapping",
                        str(mapping),
                        "--policy",
                        str(POLICY),
                        "--out",
                        str(tmp_path / "report.md"),
                        "--json",
                        str(tmp_path / "report.json"),
                        "--coverage-json",
                        str(tmp_path / "coverage.json"),
                        "--expect-layer",
                        "model_input",
                    ]
                )

            coverage_text = (tmp_path / "coverage.json").read_text(encoding="utf-8")
            self.assertEqual(exit_code, 0)
            self.assertIn("MAPPING_OPTIONAL_CONTENT_UNUSED", coverage_text)
            self.assertNotIn("private.unused_key", coverage_text)
            self.assertNotIn(str(raw), coverage_text)

            gate = PhiBoundaryGate.from_policy_file(POLICY)
            sdk_result = gate.coverage_external_trace(
                raw,
                mapping=mapping,
                expected_layers=["model_input"],
            )
            self.assertEqual(sdk_result.to_dict(), json.loads(coverage_text))

    def test_invalid_trace_and_coverage_write_errors_remain_failures(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            invalid_trace = tmp_path / "invalid.jsonl"
            invalid_trace.write_text("not-json\n", encoding="utf-8")
            stderr = StringIO()
            with redirect_stderr(stderr):
                invalid_exit = main(
                    [
                        "scan-trace",
                        "--trace",
                        str(invalid_trace),
                        "--policy",
                        str(POLICY),
                        "--out",
                        str(tmp_path / "report.md"),
                        "--json",
                        str(tmp_path / "report.json"),
                        "--coverage-json",
                        str(tmp_path / "coverage.json"),
                    ]
                )

            blocked_parent = tmp_path / "not-a-directory"
            blocked_parent.write_text("file", encoding="utf-8")
            with redirect_stderr(stderr), redirect_stdout(StringIO()):
                write_exit = main(
                    [
                        "scan-trace",
                        "--trace",
                        str(NO_PHI_TRACE),
                        "--policy",
                        str(POLICY),
                        "--out",
                        str(tmp_path / "ok.md"),
                        "--json",
                        str(tmp_path / "ok.json"),
                        "--coverage-json",
                        str(blocked_parent / "coverage.json"),
                    ]
                )

            self.assertEqual(invalid_exit, 2)
            self.assertEqual(write_exit, 2)
            self.assertIn("error:", stderr.getvalue())

    def test_invalid_expected_layer_is_rejected_by_cli_and_sdk(self) -> None:
        with self.assertRaisesRegex(ValueError, "unsupported expected layer"):
            build_audit_coverage([], expected_layers=["provider_call"])

        stderr = StringIO()
        with redirect_stderr(stderr), self.assertRaises(SystemExit) as exc:
            main(
                [
                    "scan-trace",
                    "--trace",
                    str(NO_PHI_TRACE),
                    "--policy",
                    str(POLICY),
                    "--out",
                    "/tmp/report.md",
                    "--json",
                    "/tmp/report.json",
                    "--expect-layer",
                    "provider_call",
                ]
            )
        self.assertEqual(exc.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
