from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from phi_boundary_gate import PhiBoundaryGate
from phi_boundary_gate.cli import main
from phi_boundary_gate.policy import Policy, load_policy
from phi_boundary_gate.report import build_report
from phi_boundary_gate.semantic import NoopSemanticResolver
from phi_boundary_gate.trace import TraceEvent


ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "samples/policies/default.yml"


def synthetic_event() -> TraceEvent:
    return TraceEvent(
        event_id="evt-1",
        timestamp="2026-10-22T00:00:00Z",
        layer="tool_output",
        content="member_id=MBR-SYN-8842",
        source={"type": "synthetic", "path": "payload.member"},
        destinations=[{"layer": "model_input", "path": "prompt.context"}],
    )


class AuditContextTests(unittest.TestCase):
    def test_fingerprints_are_stable_for_effectively_identical_configuration(self) -> None:
        policy = load_policy(POLICY_PATH)
        reordered = Policy(version=policy.version, categories=dict(reversed(list(policy.categories.items()))))

        first = build_report([synthetic_event()], policy, Path("first.jsonl"), Path("first.yml"))
        second = build_report([synthetic_event()], reordered, Path("second.jsonl"), Path("second.yml"))

        self.assertEqual(first["audit_context"], second["audit_context"])
        self.assertTrue(first["audit_context"]["policy_fingerprint"].startswith("sha256:"))
        self.assertTrue(first["audit_context"]["detector_fingerprint"].startswith("sha256:"))

    def test_semantic_identifier_is_hashed_and_reason_is_not_provenance(self) -> None:
        resolver_id = "approved-resolver/config-v1"
        report = build_report(
            [synthetic_event()],
            load_policy(POLICY_PATH),
            Path("trace.jsonl"),
            Path("policy.yml"),
            semantic_resolver=NoopSemanticResolver(),
            semantic_resolver_id=resolver_id,
            report_value_mode="hashed",
        )

        serialized_context = json.dumps(report["audit_context"])
        self.assertNotIn(resolver_id, serialized_context)
        self.assertNotIn("No semantic adjudication", serialized_context)
        self.assertEqual(report["audit_context"]["semantic_configuration"], "identified")

    def test_cli_and_sdk_record_the_same_audit_configuration(self) -> None:
        gate = PhiBoundaryGate.from_policy_file(POLICY_PATH)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            trace = root / "trace.jsonl"
            trace.write_text(
                json.dumps(
                    {
                        "event_id": "evt-1",
                        "timestamp": "2026-10-22T00:00:00Z",
                        "layer": "tool_output",
                        "content": "member_id=MBR-SYN-8842",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            sdk = gate.audit_trace(trace, policy_path=POLICY_PATH, report_value_mode="hashed").to_dict()
            with contextlib.redirect_stdout(io.StringIO()):
                code = main(
                    [
                        "scan-trace",
                        "--trace",
                        str(trace),
                        "--policy",
                        str(POLICY_PATH),
                        "--out",
                        str(root / "report.md"),
                        "--json",
                        str(root / "report.json"),
                        "--report-values",
                        "hashed",
                    ]
                )

            cli = json.loads((root / "report.json").read_text(encoding="utf-8"))
            self.assertEqual(code, 0)
            self.assertEqual(cli["audit_context"], sdk["audit_context"])
            combined = json.dumps(cli) + (root / "report.md").read_text(encoding="utf-8")
            self.assertNotIn("MBR-SYN-8842", combined)


if __name__ == "__main__":
    unittest.main()
