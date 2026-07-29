from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from phi_boundary_gate.trace import load_trace  # noqa: E402
from tools.trace_corpus_report import build_trace_corpus_report  # noqa: E402


TRACES = ROOT / "samples/traces"
EXPECTATIONS = ROOT / "samples/trace_expectations"
POLICY = ROOT / "samples/policies/default.yml"
BASELINE = ROOT / "reports/trace-corpus-coverage.json"


class TraceCorpusCoverageTest(unittest.TestCase):
    def test_every_valid_trace_has_expectation(self) -> None:
        expectation_traces = {
            Path(yaml.safe_load(path.read_text(encoding="utf-8"))["trace"]).name
            for path in EXPECTATIONS.glob("*.yml")
        }
        valid_traces = {
            path.name
            for path in TRACES.glob("*.jsonl")
            if not path.name.startswith("invalid_")
        }

        self.assertEqual(valid_traces, expectation_traces)

    def test_expectations_pass(self) -> None:
        report = build_trace_corpus_report(TRACES, EXPECTATIONS, POLICY)

        self.assertTrue(report["summary"]["all_expectations_passed"])
        self.assertGreaterEqual(report["summary"]["trace_count"], 7)
        self.assertIn("member_id", report["summary"]["categories_seen"])
        self.assertIn("model_input", report["summary"]["layers_seen"])
        for trace in report["traces"]:
            self.assertEqual(trace["expectation_status"], "pass", trace)

    def test_invalid_trace_still_fails_schema_validation(self) -> None:
        with self.assertRaisesRegex(ValueError, "missing required field"):
            load_trace(TRACES / "invalid_missing_content.jsonl")

    def test_near_miss_trace_has_no_findings(self) -> None:
        report = build_trace_corpus_report(TRACES, EXPECTATIONS, POLICY)
        near_miss = next(
            trace for trace in report["traces"] if trace["trace"].endswith("false_positive_near_misses.jsonl")
        )

        self.assertEqual(near_miss["findings"], 0)
        self.assertEqual(near_miss["categories"], {})

    def test_committed_trace_corpus_report_is_current(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            generated = Path(tmp) / "trace-corpus-coverage.json"
            subprocess.run(
                [
                    sys.executable,
                    "tools/trace_corpus_report.py",
                    "--traces",
                    str(TRACES),
                    "--expectations",
                    str(EXPECTATIONS),
                    "--policy",
                    str(POLICY),
                    "--out",
                    str(generated),
                ],
                cwd=ROOT,
                check=True,
            )

            self.assertEqual(
                json.loads(BASELINE.read_text(encoding="utf-8")),
                json.loads(generated.read_text(encoding="utf-8")),
            )


if __name__ == "__main__":
    unittest.main()
