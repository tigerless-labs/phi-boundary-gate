from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from phi_boundary_gate import (  # noqa: E402
    NoopSemanticResolver,
    PhiBoundaryGate,
    SemanticContext,
    SemanticDecision,
    guard_text,
    scan_text,
)
from phi_boundary_gate.detectors import Candidate  # noqa: E402
from phi_boundary_gate.policy import load_policy  # noqa: E402
from phi_boundary_gate.report import build_report, render_markdown  # noqa: E402
from phi_boundary_gate.semantic import resolve_semantics  # noqa: E402
from phi_boundary_gate.trace import TraceEvent  # noqa: E402


class SyntheticContrastResolver:
    """Test-only resolver for synthetic contrast and integration coverage."""

    def __init__(self) -> None:
        self.contexts: list[SemanticContext] = []

    def resolve(self, context: SemanticContext) -> SemanticDecision:
        self.contexts.append(context)
        text = context.text.lower()
        if "patient " in text and "diagnosed" in text:
            return SemanticDecision("patient", "diagnosis", "linked", "likely_phi", 0.99, "Synthetic patient diagnosis.")
        if text.startswith("dr.") and "guideline" in text:
            return SemanticDecision("clinician", "general", "unlinked", "likely_not_phi", 0.99, "Synthetic author context.")
        if ("member " in text or "member:" in text) and ("claim was denied" in text or "claim id:" in text):
            return SemanticDecision("member", "claim", "linked", "likely_phi", 0.98, "Synthetic member claim.")
        if "claims the policy" in text:
            return SemanticDecision("unknown", "general", "unlinked", "likely_not_phi", 0.98, "Ordinary verb usage.")
        if "admission date" in text:
            return SemanticDecision("patient", "clinical", "linked", "likely_phi", 0.97, "Healthcare event date.")
        if "document published" in text:
            return SemanticDecision("unknown", "general", "unlinked", "likely_not_phi", 0.97, "Publication date.")
        return SemanticDecision("unknown", "unknown", "unclear", "uncertain", 0.4, "Insufficient context.")


class FailingResolver:
    def resolve(self, context: SemanticContext) -> SemanticDecision:
        raise RuntimeError(f"provider copied sensitive text: {context.text}")


class InvalidResolver:
    def resolve(self, context: SemanticContext) -> SemanticDecision:
        return {"disposition": "likely_phi"}  # type: ignore[return-value]


class SemanticContextGateTest(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = load_policy(ROOT / "samples/policies/default.yml")

    def test_synthetic_contrast_cases(self) -> None:
        cases = [
            ("Patient John Smith was diagnosed with diabetes.", "John Smith", "likely_phi"),
            ("Dr. John Smith authored this diabetes guideline.", "John Smith", "likely_not_phi"),
            ("Member Jane Doe's claim was denied.", "Jane Doe", "likely_phi"),
            ("Jane claims the policy is unfair.", "Jane", "likely_not_phi"),
            ("Admission date: May 5.", "May 5", "likely_phi"),
            ("Document published May 5.", "May 5", "likely_not_phi"),
        ]
        resolver = SyntheticContrastResolver()
        predictions = []
        for text, value, expected in cases:
            start = text.index(value)
            candidate = Candidate("name", value, start, start + len(value), 0.9, "Synthetic candidate.")
            decision = resolve_semantics(resolver, text=text, candidate=candidate, layer="model_input")
            predictions.append(decision.semantic_disposition)
            self.assertEqual(decision.semantic_disposition, expected)

        true_positive = sum(predicted == expected == "likely_phi" for predicted, (_, _, expected) in zip(predictions, cases))
        false_positive = sum(predicted == "likely_phi" and expected != "likely_phi" for predicted, (_, _, expected) in zip(predictions, cases))
        false_negative = sum(predicted != "likely_phi" and expected == "likely_phi" for predicted, (_, _, expected) in zip(predictions, cases))
        uncertain = predictions.count("uncertain")
        self.assertEqual(
            {
                "semantic_accuracy": sum(predicted == case[2] for predicted, case in zip(predictions, cases)) / len(cases),
                "likely_phi_precision": true_positive / (true_positive + false_positive),
                "likely_phi_recall": true_positive / (true_positive + false_negative),
                "false_positives": false_positive,
                "false_negatives": false_negative,
                "uncertain_rate": uncertain / len(cases),
            },
            {
                "semantic_accuracy": 1.0,
                "likely_phi_precision": 1.0,
                "likely_phi_recall": 1.0,
                "false_positives": 0,
                "false_negatives": 0,
                "uncertain_rate": 0.0,
            },
        )

    def test_default_disabled_preserves_v06_finding_shape(self) -> None:
        finding = scan_text("member_id=MBR-SYN-8842", "debug_log", self.policy)[0]

        self.assertIsNone(finding.semantic)
        self.assertNotIn("semantic", finding.to_dict())
        self.assertEqual(finding.disposition, "violation")

    def test_noop_resolver_preserves_existing_policy_behavior(self) -> None:
        baseline = guard_text("member_id=MBR-SYN-8842", "debug_log", self.policy, mode="block_on_violation")
        semantic = guard_text(
            "member_id=MBR-SYN-8842",
            "debug_log",
            self.policy,
            mode="block_on_violation",
            semantic_resolver=NoopSemanticResolver(),
        )

        self.assertEqual(semantic.findings[0].semantic.semantic_disposition, "uncertain")
        self.assertEqual(semantic.has_phi, baseline.has_phi)
        self.assertEqual(semantic.has_violations, baseline.has_violations)
        self.assertEqual(semantic.should_block, baseline.should_block)
        self.assertEqual(semantic.redacted_text, baseline.redacted_text)

    def test_sdk_injects_resolver_with_full_single_event_context(self) -> None:
        resolver = SyntheticContrastResolver()
        gate = PhiBoundaryGate.from_policy_file(ROOT / "samples/policies/default.yml", semantic_resolver=resolver)

        finding = gate.scan("Member: Jane Doe. Claim ID: CLM-SYN-44501", "model_input")[0]

        self.assertIsNotNone(finding.semantic)
        self.assertEqual(len(resolver.contexts), 2)
        self.assertEqual(resolver.contexts[0].text, "Member: Jane Doe. Claim ID: CLM-SYN-44501")
        self.assertEqual(resolver.contexts[0].layer, "model_input")

    def test_decision_validates_schema_and_confidence(self) -> None:
        with self.assertRaisesRegex(ValueError, "subject_role"):
            SemanticDecision("customer", "claim", "linked", "likely_phi", 0.9, "Invalid role.")  # type: ignore[arg-type]
        with self.assertRaisesRegex(ValueError, "confidence"):
            SemanticDecision("member", "claim", "linked", "likely_phi", 1.01, "Invalid confidence.")
        with self.assertRaisesRegex(ValueError, "reason"):
            SemanticDecision("member", "claim", "linked", "likely_phi", 0.9, "")

    def test_resolver_exception_and_invalid_output_fail_safe(self) -> None:
        for resolver in (FailingResolver(), InvalidResolver()):
            finding = scan_text(
                "member_id=MBR-SYN-8842",
                "debug_log",
                self.policy,
                semantic_resolver=resolver,
            )[0]

            self.assertEqual(finding.semantic.semantic_disposition, "uncertain")
            self.assertEqual(finding.semantic.confidence, 0.0)
            self.assertEqual(finding.disposition, "violation")
            self.assertNotIn("MBR-SYN-8842", finding.semantic.reason)

    def test_all_semantic_dispositions_preserve_high_risk_policy_result(self) -> None:
        class FixedResolver:
            def __init__(self, disposition: str) -> None:
                self.disposition = disposition

            def resolve(self, context: SemanticContext) -> SemanticDecision:
                return SemanticDecision(
                    "member",
                    "claim",
                    "linked" if self.disposition == "likely_phi" else "unclear",
                    self.disposition,  # type: ignore[arg-type]
                    0.99,
                    "Synthetic fixed result.",
                )

        for disposition in ("likely_phi", "uncertain", "likely_not_phi"):
            decision = guard_text(
                "claim_id=CLM-SYN-44501",
                "debug_log",
                self.policy,
                mode="block_on_violation",
                semantic_resolver=FixedResolver(disposition),
            )
            self.assertTrue(decision.has_phi)
            self.assertTrue(decision.has_violations)
            self.assertTrue(decision.should_block)
            self.assertEqual(decision.findings[0].disposition, "violation")

    def test_json_and_markdown_reports_include_bounded_semantic_metadata(self) -> None:
        event = TraceEvent(
            event_id="evt_semantic",
            timestamp="2026-10-06T00:00:00Z",
            layer="model_input",
            content="Member: Jane Doe. Claim ID: CLM-SYN-44501",
        )
        resolver = SyntheticContrastResolver()
        report = build_report(
            [event],
            self.policy,
            Path("<events>"),
            ROOT / "samples/policies/default.yml",
            semantic_resolver=resolver,
            report_value_mode="redacted",
        )
        serialized = json.dumps(report)
        markdown = render_markdown(report)

        semantic = report["findings"][0]["semantic"]
        self.assertEqual(
            set(semantic),
            {"subject_role", "information_role", "linkage", "disposition", "confidence"},
        )
        self.assertNotIn("reason", semantic)
        self.assertNotIn("Synthetic member claim", serialized)
        self.assertNotIn("Jane Doe", serialized)
        self.assertNotIn("CLM-SYN-44501", serialized)
        self.assertIn("- Semantic:", markdown)
        self.assertEqual(report["summary"]["by_semantic_disposition"], {"likely_phi": 2})


if __name__ == "__main__":
    unittest.main()
