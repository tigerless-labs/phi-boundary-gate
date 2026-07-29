from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from phi_boundary_gate import (  # noqa: E402
    ComplianceContext,
    ComplianceDecision,
    guard_compliance,
    load_compliance_policy,
    load_policy,
)


class ComplianceGuardTest(unittest.TestCase):
    def setUp(self) -> None:
        self.phi_policy = load_policy(ROOT / "samples/policies/default.yml")
        self.compliance_policy = load_compliance_policy(ROOT / "samples/compliance_policies/default.yml")

    def test_allows_phi_for_confirmed_covered_service_profile(self) -> None:
        decision = guard_compliance(
            "member_id=MBR-SYN-8842",
            layer="model_input",
            phi_policy=self.phi_policy,
            compliance_policy=self.compliance_policy,
            context=ComplianceContext(
                phi_status="real_phi",
                vendor="google",
                service="vertex_ai",
                endpoint="generate_content",
                model="gemini-2.5-pro",
                feature="online_prediction",
                environment="production",
                logging="redacted_only",
                storage="none",
            ),
        )

        self.assertIsInstance(decision, ComplianceDecision)
        self.assertFalse(decision.should_block)
        self.assertTrue(decision.compliance_allowed)
        self.assertEqual(decision.service_id, "google_vertex_ai_ga_confirmed")
        self.assertEqual(decision.redacted_text, "member_id=[REDACTED_MEMBER_ID]")

    def test_blocks_phi_for_preview_model(self) -> None:
        decision = guard_compliance(
            "member_id=MBR-SYN-8842",
            layer="model_input",
            phi_policy=self.phi_policy,
            compliance_policy=self.compliance_policy,
            context=ComplianceContext(
                phi_status="real_phi",
                vendor="google",
                service="vertex_ai",
                endpoint="generate_content",
                model="gemini-3.1-pro-preview",
                feature="online_prediction",
                environment="production",
                logging="redacted_only",
                storage="none",
            ),
        )

        self.assertTrue(decision.should_block)
        self.assertIn("model_matches_denied_pattern", decision.block_reasons)
        self.assertIn("phi_status_requires_baa_but_baa_is_not_confirmed", decision.block_reasons)

    def test_blocks_phi_when_baa_is_not_confirmed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            policy_path = Path(tmp) / "compliance.yml"
            policy_path.write_text(
                "version: 1\n"
                "default_action: block\n"
                "phi_statuses:\n"
                "  real_phi:\n"
                "    requires_baa: true\n"
                "services:\n"
                "  pending_service:\n"
                "    vendor: acme\n"
                "    service: llm_api\n"
                "    covered_service: true\n"
                "    baa_executed: false\n"
                "    allowed_phi_status: [real_phi]\n"
                "    model_patterns: [safe-model]\n",
                encoding="utf-8",
            )
            compliance_policy = load_compliance_policy(policy_path)

            decision = guard_compliance(
                "member_id=MBR-SYN-8842",
                layer="model_input",
                phi_policy=self.phi_policy,
                compliance_policy=compliance_policy,
                context=ComplianceContext(
                    phi_status="real_phi",
                    vendor="acme",
                    service="llm_api",
                    endpoint="chat",
                    model="safe-model",
                    feature="online_prediction",
                ),
            )

        self.assertTrue(decision.should_block)
        self.assertIn("phi_status_requires_baa_but_baa_is_not_confirmed", decision.block_reasons)

    def test_blocks_phi_for_unknown_service_profile(self) -> None:
        decision = guard_compliance(
            "claim_id=CLM-SYN-44501",
            layer="model_input",
            phi_policy=self.phi_policy,
            compliance_policy=self.compliance_policy,
            context=ComplianceContext(
                phi_status="real_phi",
                vendor="unknown",
                service="llm",
                endpoint="chat",
                model="unknown-model",
                feature="online_prediction",
            ),
        )

        self.assertTrue(decision.should_block)
        self.assertIn("unknown_service_profile", decision.block_reasons)

    def test_allows_no_phi_without_known_service_profile(self) -> None:
        decision = guard_compliance(
            "Translate this general greeting.",
            layer="model_input",
            phi_policy=self.phi_policy,
            compliance_policy=self.compliance_policy,
            context=ComplianceContext(
                phi_status="non_phi",
                vendor="unknown",
                service="llm",
                endpoint="chat",
                model="unknown-model",
                feature="online_prediction",
            ),
        )

        self.assertFalse(decision.should_block)
        self.assertFalse(decision.text_decision.has_phi)
        self.assertIn("unknown_service_profile", decision.warnings)

    def test_blocks_raw_logging_for_production_phi(self) -> None:
        decision = guard_compliance(
            "member_id=MBR-SYN-8842",
            layer="model_input",
            phi_policy=self.phi_policy,
            compliance_policy=self.compliance_policy,
            context=ComplianceContext(
                phi_status="real_phi",
                vendor="google",
                service="vertex_ai",
                endpoint="generate_content",
                model="gemini-2.5-pro",
                feature="online_prediction",
                environment="production",
                logging="raw",
                storage="none",
            ),
        )

        self.assertTrue(decision.should_block)
        self.assertIn("logging_mode_not_allowed_for_phi", decision.block_reasons)
        self.assertIn("environment_requires_redacted_logging", decision.block_reasons)

    def test_blocks_denied_feature_for_phi(self) -> None:
        decision = guard_compliance(
            "member_id=MBR-SYN-8842",
            layer="model_input",
            phi_policy=self.phi_policy,
            compliance_policy=self.compliance_policy,
            context=ComplianceContext(
                phi_status="real_phi",
                vendor="google",
                service="vertex_ai",
                endpoint="generate_content",
                model="gemini-2.5-pro",
                feature="web_search",
                environment="production",
                logging="redacted_only",
                storage="none",
            ),
        )

        self.assertTrue(decision.should_block)
        self.assertIn("feature_denied_for_service", decision.block_reasons)

    def test_default_dict_is_safe_for_audit_logs(self) -> None:
        decision = guard_compliance(
            "member_id=MBR-SYN-8842",
            layer="model_input",
            phi_policy=self.phi_policy,
            compliance_policy=self.compliance_policy,
            context=ComplianceContext(
                phi_status="real_phi",
                vendor="google",
                service="vertex_ai",
                endpoint="generate_content",
                model="gemini-3.1-pro-preview",
                feature="online_prediction",
                environment="production",
                logging="redacted_only",
                storage="none",
            ),
        )

        payload_text = str(decision.to_dict())
        debug_payload_text = str(decision.to_dict(include_phi=True))

        self.assertNotIn("MBR-SYN-8842", payload_text)
        self.assertIn("MBR-SYN-8842", debug_payload_text)
        self.assertNotIn("MBR-SYN-8842", str(decision.block_reasons))

    def test_load_compliance_policy_rejects_invalid_phi_status(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            policy_path = Path(tmp) / "invalid.yml"
            policy_path.write_text(
                "version: 1\n"
                "phi_statuses:\n"
                "  confidential:\n"
                "    requires_baa: true\n"
                "services:\n"
                "  service:\n"
                "    vendor: acme\n"
                "    service: llm\n"
                "    covered_service: true\n"
                "    baa_executed: true\n"
                "    allowed_phi_status: [real_phi]\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "unsupported phi_status"):
                load_compliance_policy(policy_path)


if __name__ == "__main__":
    unittest.main()
