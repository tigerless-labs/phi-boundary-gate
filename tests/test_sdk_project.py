from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from phi_boundary_gate import (  # noqa: E402
    AuditResult,
    PhiBoundaryGate,
    ProjectConfigError,
    ProjectConfigNotFoundError,
    check_project_config,
    discover_project_config,
    init_project,
)
from phi_boundary_gate.cli import main  # noqa: E402
from phi_boundary_gate.trace import TraceEvent  # noqa: E402


class SdkProjectTest(unittest.TestCase):
    def subprocess_env(self) -> dict[str, str]:
        env = os.environ.copy()
        env["PYTHONPATH"] = str(ROOT / "src")
        return env

    def test_phi_boundary_gate_from_policy_file_guards_model_input(self) -> None:
        gate = PhiBoundaryGate.from_policy_file(ROOT / "samples/policies/default.yml")

        decision = gate.guard_model_input("member_id=MBR-SYN-8842")

        self.assertTrue(decision.has_phi)
        self.assertFalse(decision.should_block)
        self.assertEqual(decision.redacted_text, "member_id=[REDACTED_MEMBER_ID]")

    def test_phi_boundary_gate_redacts_for_log(self) -> None:
        gate = PhiBoundaryGate.from_policy_file(ROOT / "samples/policies/default.yml")

        safe_log = gate.redact_for_log("debug member_id=MBR-SYN-8842")

        self.assertEqual(safe_log, "debug member_id=[REDACTED_MEMBER_ID]")

    def test_guard_decision_safe_dict_omits_raw_text_and_values(self) -> None:
        gate = PhiBoundaryGate.from_policy_file(ROOT / "samples/policies/default.yml")

        payload = gate.guard_model_input("member_id=MBR-SYN-8842").to_safe_dict()

        serialized = str(payload)
        self.assertNotIn("MBR-SYN-8842", serialized)
        self.assertNotIn("text", payload)
        self.assertEqual(payload["categories"], ["member_id"])

    def test_discover_project_config_raises_stable_exception(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.assertTrue(issubclass(ProjectConfigNotFoundError, ProjectConfigError))
            self.assertTrue(issubclass(ProjectConfigNotFoundError, FileNotFoundError))
            with self.assertRaisesRegex(ProjectConfigError, "phi-boundary-gate init"):
                discover_project_config(Path(tmp))
            with self.assertRaises(FileNotFoundError):
                discover_project_config(Path(tmp))

    def test_init_project_writes_discoverable_config_and_templates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)

            config = init_project(root)
            discovered = discover_project_config(root)
            checked = check_project_config(root)

            self.assertEqual(discovered.config_path, config.config_path)
            self.assertEqual(checked.policy_path, root / "config/phi-policy.yml")
            self.assertTrue((root / "config/phi-compliance-policy.yml").is_file())
            self.assertEqual(json.loads(config.config_path.read_text(encoding="utf-8"))["policy"], "config/phi-policy.yml")

    def test_phi_boundary_gate_from_project_uses_discovered_policy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            init_project(root)

            gate = PhiBoundaryGate.from_project(root)
            decision = gate.guard_model_input("member_id=MBR-SYN-8842")

            self.assertTrue(decision.has_phi)
            self.assertEqual(decision.redacted_text, "member_id=[REDACTED_MEMBER_ID]")

    def test_phi_boundary_gate_audit_trace_returns_result_object(self) -> None:
        gate = PhiBoundaryGate.from_policy_file(ROOT / "samples/policies/default.yml")

        result = gate.audit_trace(
            ROOT / "samples/traces/claim_agent_minimal.jsonl",
            policy_path=ROOT / "samples/policies/default.yml",
            report_value_mode="hashed",
        )

        self.assertIsInstance(result, AuditResult)
        self.assertTrue(result.has_findings)
        self.assertTrue(result.has_violations)
        self.assertEqual(result.to_dict()["schema_version"], 3)
        self.assertIn("# PHI Boundary Gate Report", result.to_markdown())
        self.assertNotIn("MBR-SYN-8842", json.dumps(result.to_dict()))

    def test_audit_result_writes_json_and_markdown(self) -> None:
        gate = PhiBoundaryGate.from_policy_file(ROOT / "samples/policies/default.yml")
        events = [
            TraceEvent(
                event_id="evt_sdk",
                timestamp="2026-08-14T10:00:00Z",
                layer="debug_log",
                content="member_id=MBR-SYN-8842",
            )
        ]

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            result = gate.audit_events(events, report_value_mode="redacted")
            result.write_json(tmp_path / "report.json")
            result.write_markdown(tmp_path / "report.md")

            self.assertEqual(json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))["schema_version"], 3)
            self.assertIn("[REDACTED_MEMBER_ID]", (tmp_path / "report.md").read_text(encoding="utf-8"))

    def test_cli_init_and_check_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)

            with redirect_stdout(StringIO()):
                self.assertEqual(main(["init", "--root", str(root)]), 0)
                self.assertEqual(main(["check-config", "--root", str(root)]), 0)

    def test_public_sdk_examples_run_from_source_path(self) -> None:
        guard = subprocess.run(
            [sys.executable, str(ROOT / "examples/sdk_guard_model_input.py")],
            check=True,
            capture_output=True,
            text=True,
            env=self.subprocess_env(),
        )
        redact = subprocess.run(
            [sys.executable, str(ROOT / "examples/sdk_redact_logs.py")],
            check=True,
            capture_output=True,
            text=True,
            env=self.subprocess_env(),
        )
        audit = subprocess.run(
            [sys.executable, str(ROOT / "examples/sdk_audit_trace.py")],
            check=True,
            capture_output=True,
            text=True,
            env=self.subprocess_env(),
        )

        self.assertNotIn("MBR-SYN-8842", guard.stdout)
        self.assertIn("[REDACTED_MEMBER_ID]", guard.stdout)
        self.assertNotIn("MBR-SYN-8842", redact.stdout)
        self.assertIn("[REDACTED_MEMBER_ID]", redact.stdout)
        self.assertNotIn("MBR-SYN-8842", audit.stdout)
        self.assertIn('"schema_version": 3', audit.stdout)


if __name__ == "__main__":
    unittest.main()
