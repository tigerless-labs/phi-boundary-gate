from __future__ import annotations

import contextlib
import copy
import io
import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from phi_boundary_gate.cli import main
from phi_boundary_gate.exposure_diff import (
    MAX_REVIEW_GUIDANCE_ITEMS,
    build_review_guidance,
    compare_audit_reports,
    compare_report_files,
    render_exposure_review_summary,
)
from phi_boundary_gate.policy import Policy, load_policy
from phi_boundary_gate.report import build_report
from phi_boundary_gate.semantic import NoopSemanticResolver
from phi_boundary_gate.trace import TraceEvent


ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "samples/policies/default.yml"


def event(
    event_id: str,
    content: dict[str, object],
    *,
    timestamp: str = "2026-10-13T00:00:00Z",
    source_type: str = "synthetic_claim_lookup",
    source_path: str = "tools.claim.response",
    destinations: list[dict[str, str]] | None = None,
) -> TraceEvent:
    return TraceEvent(
        event_id=event_id,
        timestamp=timestamp,
        layer="tool_output",
        content=json.dumps(content),
        source={"type": source_type, "path": source_path},
        destinations=(
            [{"layer": "model_input", "path": "prompt.context[0]"}] if destinations is None else destinations
        ),
        metadata={"external_content_paths": ["payload"]},
    )


def report(
    events: list[TraceEvent],
    *,
    policy: Policy | None = None,
    policy_path: str = "config/phi-policy.yml",
    report_value_mode: str = "redacted",
) -> dict:
    return build_report(
        events,
        policy or load_policy(POLICY_PATH),
        Path("synthetic-trace.jsonl"),
        Path(policy_path),
        report_value_mode=report_value_mode,
    )


def policy_with_member_denied_in_tool_output() -> Policy:
    baseline = load_policy(POLICY_PATH)
    categories = dict(baseline.categories)
    categories["member_id"] = replace(
        categories["member_id"],
        deny_layers=frozenset({"debug_log", "tool_output"}),
        redact_layers=categories["member_id"].redact_layers - {"tool_output"},
    )
    return Policy(version=baseline.version, categories=categories)


class ExposureDiffTest(unittest.TestCase):
    def test_identical_reports_have_only_unchanged_groups(self) -> None:
        baseline = report([event("evt-1", {"member_id": "member_id=MBR-SYN-10001"})])

        diff = compare_audit_reports(baseline, copy.deepcopy(baseline)).to_dict()

        self.assertEqual(diff["summary"]["new_exposures"], 0)
        self.assertEqual(diff["summary"]["no_longer_observed"], 0)
        self.assertEqual(diff["summary"]["changed_dispositions"], 0)
        self.assertEqual(diff["summary"]["changed_frequencies"], 0)
        self.assertEqual(diff["summary"]["unchanged"], 1)
        self.assertTrue(diff["comparability"]["semantic"]["coverage_compatible"])
        self.assertFalse(diff["comparability"]["semantic"]["directly_comparable"])

    def test_new_and_no_longer_observed_paths_are_reported(self) -> None:
        before = report(
            [
                event(
                    "evt-before",
                    {
                        "member_id": "member_id=MBR-SYN-10001",
                        "claim_id": "claim_id=CLM-SYN-10001",
                    },
                )
            ]
        )
        after = report(
            [
                event(
                    "evt-after",
                    {
                        "member_id": "member_id=MBR-SYN-20002",
                        "mrn": "MRN: A-20002",
                    },
                )
            ]
        )

        diff = compare_audit_reports(before, after).to_dict()

        self.assertEqual([item["category"] for item in diff["new_exposures"]], ["mrn"])
        self.assertEqual(
            [item["category"] for item in diff["no_longer_observed"]],
            ["claim_id"],
        )
        self.assertEqual(diff["summary"]["unchanged"], 1)

    def test_same_path_disposition_change_is_advisory_and_policy_difference_is_explicit(self) -> None:
        events = [event("evt-1", {"member_id": "member_id=MBR-SYN-10001"})]
        before = report(events, policy_path="policies/baseline.yml")
        after = report(
            events,
            policy=policy_with_member_denied_in_tool_output(),
            policy_path="policies/candidate.yml",
        )

        diff = compare_audit_reports(before, after).to_dict()

        self.assertEqual(diff["summary"]["changed_dispositions"], 1)
        change = diff["changed_dispositions"][0]
        self.assertEqual(change["before"]["worst_disposition"], "redact")
        self.assertEqual(change["after"]["worst_disposition"], "violation")
        self.assertEqual(change["direction"], "worsened")
        self.assertEqual(diff["summary"]["disposition_directions"]["worsened"], 1)
        self.assertEqual(diff["comparability"]["status"], "limited")
        self.assertFalse(diff["comparability"]["policy_reference_match"])
        self.assertIn("POLICY_FINGERPRINT_MISMATCH", diff["comparability"]["reason_codes"])
        self.assertTrue(any("Policy references differ" in warning for warning in diff["comparability"]["warnings"]))

    def test_same_path_frequency_counts_occurrences_and_distinct_events(self) -> None:
        before = report([event("evt-1", {"member_id": "member_id=MBR-SYN-10001"})])
        after = report(
            [
                event("evt-10", {"member_id": "member_id=MBR-SYN-20001"}),
                event("evt-11", {"member_id": "member_id=MBR-SYN-20002"}),
            ]
        )

        diff = compare_audit_reports(before, after).to_dict()

        self.assertEqual(diff["summary"]["changed_frequencies"], 1)
        self.assertEqual(diff["changed_frequencies"][0]["before"], {"events": 1, "occurrences": 1})
        self.assertEqual(diff["changed_frequencies"][0]["after"], {"events": 2, "occurrences": 2})

    def test_event_order_ids_timestamps_and_values_do_not_define_exposure_identity(self) -> None:
        before_events = [
            event("evt-1", {"member_id": "member_id=MBR-SYN-10001"}, timestamp="2026-01-01T00:00:00Z"),
            event("evt-2", {"member_id": "member_id=MBR-SYN-10002"}, timestamp="2026-01-01T00:00:01Z"),
        ]
        after_events = [
            event("renamed-b", {"member_id": "member_id=MBR-SYN-90002"}, timestamp="2030-01-01T00:00:01Z"),
            event("renamed-a", {"member_id": "member_id=MBR-SYN-90001"}, timestamp="2030-01-01T00:00:00Z"),
        ]

        diff = compare_audit_reports(report(before_events), report(after_events)).to_dict()

        self.assertEqual(diff["summary"]["unchanged"], 1)
        self.assertEqual(diff["summary"]["changed_frequencies"], 0)
        self.assertNotEqual(diff["before"]["report_ref"], diff["after"]["report_ref"])

    def test_one_finding_is_expanded_per_unique_destination(self) -> None:
        first_two = [
            {"layer": "model_input", "path": "prompt.context[0]"},
            {"layer": "debug_log", "path": "logs.audit"},
        ]
        with_third = [
            *first_two,
            {"layer": "model_provider", "path": "request.messages"},
        ]
        before = report([event("evt-1", {"member_id": "member_id=MBR-SYN-10001"}, destinations=first_two)])
        after = report([event("evt-2", {"member_id": "member_id=MBR-SYN-20002"}, destinations=with_third)])

        diff = compare_audit_reports(before, after).to_dict()

        self.assertEqual(diff["summary"]["before_exposure_groups"], 2)
        self.assertEqual(diff["summary"]["after_exposure_groups"], 3)
        self.assertEqual(diff["summary"]["new_exposures"], 1)
        self.assertEqual(diff["summary"]["unchanged"], 2)

    def test_array_indexes_are_matched_exactly_and_duplicate_destinations_are_deduplicated(self) -> None:
        duplicate_destination = {"layer": "model_input", "path": "prompt.context[0]"}
        before = report(
            [
                event(
                    "evt-1",
                    {"items": [{"member_id": "member_id=MBR-SYN-10001"}]},
                    destinations=[duplicate_destination, duplicate_destination],
                )
            ]
        )
        after = report(
            [
                event(
                    "evt-2",
                    {
                        "items": [
                            {"safe": "none"},
                            {"member_id": "member_id=MBR-SYN-20002"},
                        ]
                    },
                    destinations=[duplicate_destination],
                )
            ]
        )

        diff = compare_audit_reports(before, after).to_dict()

        self.assertEqual(diff["summary"]["before_group_occurrences"], 1)
        self.assertEqual(diff["summary"]["new_exposures"], 1)
        self.assertEqual(diff["summary"]["no_longer_observed"], 1)

    def test_empty_reports_are_supported(self) -> None:
        empty = report([])

        diff = compare_audit_reports(empty, copy.deepcopy(empty)).to_dict()

        self.assertEqual(diff["summary"]["before_exposure_groups"], 0)
        self.assertEqual(diff["summary"]["after_exposure_groups"], 0)
        self.assertEqual(diff["new_exposures"], [])
        self.assertEqual(diff["comparability"]["semantic"]["before_coverage"], "not_observable")

    def test_same_policy_reference_with_changed_content_detects_drift(self) -> None:
        events = [event("evt-1", {"member_id": "member_id=MBR-SYN-10001"})]
        before = report(events, policy_path="config/shared.yml")
        after = report(
            events,
            policy=policy_with_member_denied_in_tool_output(),
            policy_path="config/shared.yml",
        )

        comparability = compare_audit_reports(before, after).to_dict()["comparability"]

        self.assertTrue(comparability["policy_reference_match"])
        self.assertEqual(comparability["policy_fingerprint_comparison"], "mismatch")
        self.assertIn("POLICY_CONTENT_CHANGED_AT_SAME_REFERENCE", comparability["reason_codes"])

    def test_different_policy_references_with_same_effective_policy_do_not_drift(self) -> None:
        events = [event("evt-1", {"member_id": "member_id=MBR-SYN-10001"})]
        before = report(events, policy_path="config/first.yml")
        after = report(events, policy_path="config/second.yml")

        comparability = compare_audit_reports(before, after).to_dict()["comparability"]

        self.assertFalse(comparability["policy_reference_match"])
        self.assertEqual(comparability["policy_fingerprint_comparison"], "match")
        self.assertEqual(comparability["status"], "comparable_with_limitations")
        self.assertIn("POLICY_REFERENCE_CHANGED_EFFECTIVE_POLICY_MATCH", comparability["reason_codes"])

    def test_presidio_detector_and_semantic_configuration_diagnostics(self) -> None:
        policy = load_policy(POLICY_PATH)
        baseline = build_report([], policy, Path("trace.jsonl"), Path("policy.yml"))
        presidio = build_report(
            [],
            policy,
            Path("trace.jsonl"),
            Path("policy.yml"),
            enable_presidio=True,
        )
        semantic_unknown = build_report(
            [],
            policy,
            Path("trace.jsonl"),
            Path("policy.yml"),
            semantic_resolver=NoopSemanticResolver(),
        )
        semantic_first = build_report(
            [],
            policy,
            Path("trace.jsonl"),
            Path("policy.yml"),
            semantic_resolver=NoopSemanticResolver(),
            semantic_resolver_id="resolver/config-v1",
        )
        semantic_second = build_report(
            [],
            policy,
            Path("trace.jsonl"),
            Path("policy.yml"),
            semantic_resolver=NoopSemanticResolver(),
            semantic_resolver_id="resolver/config-v2",
        )

        detector_diff = compare_audit_reports(baseline, presidio).to_dict()["comparability"]
        presidio_unknown = compare_audit_reports(presidio, copy.deepcopy(presidio)).to_dict()["comparability"]
        unknown_diff = compare_audit_reports(semantic_unknown, semantic_unknown).to_dict()["comparability"]
        semantic_diff = compare_audit_reports(semantic_first, semantic_second).to_dict()["comparability"]

        self.assertIn("DETECTOR_FINGERPRINT_MISMATCH", detector_diff["reason_codes"])
        self.assertIn("PRESIDIO_ENABLEMENT_MISMATCH", detector_diff["reason_codes"])
        self.assertIn("PRESIDIO_CONFIGURATION_UNKNOWN", presidio_unknown["reason_codes"])
        self.assertIn("SEMANTIC_CONFIGURATION_UNKNOWN", unknown_diff["reason_codes"])
        self.assertIn("SEMANTIC_CONFIGURATION_MISMATCH", semantic_diff["reason_codes"])

    def test_legacy_v080_reports_are_comparable_with_incomplete_provenance(self) -> None:
        before = report([event("evt-1", {"member_id": "member_id=MBR-SYN-10001"})])
        after = copy.deepcopy(before)
        before.pop("audit_context")
        after.pop("audit_context")

        diff = compare_audit_reports(before, after).to_dict()

        self.assertEqual(diff["summary"]["unchanged"], 1)
        self.assertFalse(diff["comparability"]["provenance_complete"])
        self.assertEqual(diff["comparability"]["status"], "limited")
        self.assertIn("AUDIT_PROVENANCE_INCOMPLETE", diff["comparability"]["reason_codes"])

    def test_improved_and_equal_worst_set_change_directions(self) -> None:
        events = [event("evt-1", {"member_id": "member_id=MBR-SYN-10001"})]
        violation = report(events, policy=policy_with_member_denied_in_tool_output())
        redact = report(events)

        improved = compare_audit_reports(violation, redact).to_dict()
        self.assertEqual(improved["changed_dispositions"][0]["direction"], "improved")
        self.assertEqual(improved["summary"]["disposition_directions"]["improved"], 1)

        mixed_after = copy.deepcopy(violation)
        extra = copy.deepcopy(mixed_after["findings"][0])
        extra["finding_id"] = "finding-999"
        extra["event_id"] = "evt-2"
        extra["policy"]["disposition"] = "allowed"
        mixed_after["findings"].append(extra)
        mixed = compare_audit_reports(violation, mixed_after).to_dict()

        self.assertEqual(mixed["changed_dispositions"][0]["direction"], "mixed_or_other")
        self.assertEqual(mixed["summary"]["disposition_directions"]["mixed_or_other"], 1)
        self.assertEqual(sum(mixed["summary"]["disposition_directions"].values()), 1)

    def test_missing_fields_and_incompatible_schema_are_rejected(self) -> None:
        valid = report([event("evt-1", {"member_id": "member_id=MBR-SYN-10001"})])
        missing = copy.deepcopy(valid)
        del missing["findings"][0]["content_path"]
        incompatible = copy.deepcopy(valid)
        incompatible["schema_version"] = 2

        with self.assertRaisesRegex(ValueError, "content_path"):
            compare_audit_reports(missing, valid)
        with self.assertRaisesRegex(ValueError, "schema_version must be 3"):
            compare_audit_reports(valid, incompatible)

    def test_semantic_configuration_mismatch_is_limited_and_semantics_are_excluded(self) -> None:
        before = report([event("evt-1", {"member_id": "member_id=MBR-SYN-10001"})])
        after = copy.deepcopy(before)
        for finding in after["findings"]:
            finding["semantic"] = {
                "subject_role": "member",
                "information_role": "claim",
                "linkage": "linked",
                "disposition": "likely_phi",
                "confidence": 0.99,
            }

        diff = compare_audit_reports(before, after).to_dict()

        self.assertEqual(diff["comparability"]["status"], "limited")
        self.assertFalse(diff["comparability"]["semantic"]["directly_comparable"])
        self.assertEqual(diff["summary"]["unchanged"], 1)
        self.assertNotIn("subject_role", json.dumps(diff))

    def test_diff_never_copies_raw_phi_or_untrusted_paths_and_does_not_mutate_inputs(self) -> None:
        sensitive = "Casey Example MBR-SYN-8842"
        before = report(
            [
                event(
                    "evt-1",
                    {sensitive: "member_id=MBR-SYN-8842"},
                    source_type=sensitive,
                    source_path=f"records.{sensitive}",
                    destinations=[{"layer": "model_input", "path": f"prompt.{sensitive}"}],
                )
            ],
            policy_path=f"policies/{sensitive}.yml",
            report_value_mode="raw",
        )
        after = copy.deepcopy(before)
        before_snapshot = copy.deepcopy(before)
        after_snapshot = copy.deepcopy(after)

        result = compare_audit_reports(before, after)
        serialized = json.dumps(result.to_dict()) + result.to_markdown()

        self.assertNotIn("Casey Example", serialized)
        self.assertNotIn("MBR-SYN-8842", serialized)
        self.assertNotIn("records.", serialized)
        self.assertEqual(before, before_snapshot)
        self.assertEqual(after, after_snapshot)

    def test_output_is_deterministic_and_cli_is_advisory_for_new_exposure(self) -> None:
        before = report([event("evt-1", {"member_id": "member_id=MBR-SYN-10001"})])
        after = report(
            [
                event(
                    "evt-2",
                    {
                        "member_id": "member_id=MBR-SYN-20002",
                        "claim_id": "claim_id=CLM-SYN-20002",
                    },
                )
            ]
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            before_path = root / "before.json"
            after_path = root / "after.json"
            before_path.write_text(json.dumps(before), encoding="utf-8")
            after_path.write_text(json.dumps(after), encoding="utf-8")
            first = compare_report_files(before_path, after_path).to_dict()
            second = compare_report_files(before_path, after_path).to_dict()
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                code = main(
                    [
                        "compare-reports",
                        "--before",
                        str(before_path),
                        "--after",
                        str(after_path),
                        "--out",
                        str(root / "diff.md"),
                        "--json",
                        str(root / "diff.json"),
                    ]
                )

            self.assertEqual(first, second)
            self.assertEqual(code, 0)
            self.assertIn("new=1", stdout.getvalue())
            self.assertNotIn("regression review summary", stdout.getvalue())
            self.assertEqual(json.loads((root / "diff.json").read_text()), first)
            self.assertIn("This is advisory", (root / "diff.md").read_text())
            self.assertFalse((root / "review-summary.md").exists())

    def test_review_summary_prioritizes_changes_without_changing_diff_schema(self) -> None:
        before = report(
            [
                event(
                    "evt-before",
                    {
                        "member_id": "member_id=MBR-SYN-10001",
                        "claim_id": "claim_id=CLM-SYN-10001",
                    },
                )
            ]
        )
        after = report(
            [
                event(
                    "evt-after",
                    {
                        "member_id": "member_id=MBR-SYN-20002",
                        "mrn": "MRN: A-20002",
                    },
                )
            ],
            policy=policy_with_member_denied_in_tool_output(),
        )

        result = compare_audit_reports(before, after)
        diff = result.to_dict()
        review = result.to_review_summary()
        guidance = result.review_guidance()

        self.assertEqual(diff["summary"]["new_exposures"], 1)
        self.assertEqual(diff["summary"]["no_longer_observed"], 1)
        self.assertEqual(diff["summary"]["disposition_directions"]["worsened"], 1)
        self.assertNotIn("review_guidance", diff)
        self.assertIn("Newly observed routes: 1", review)
        self.assertIn("No longer observed routes: 1", review)
        self.assertIn("Worsened dispositions: 1", review)
        self.assertIn("`REVIEW_WORSENED_DISPOSITIONS`", review)
        self.assertIn("`REVIEW_NEWLY_OBSERVED_ROUTES`", review)
        self.assertIn("`VALIDATE_POLICY_COMPARABILITY`", review)
        self.assertEqual(guidance, build_review_guidance(diff))
        self.assertEqual(review, render_exposure_review_summary(diff))

    def test_review_summary_reports_improvement_without_claiming_risk_reduction(self) -> None:
        events = [event("evt-1", {"member_id": "member_id=MBR-SYN-10001"})]
        before = report(events, policy=policy_with_member_denied_in_tool_output())
        after = report(events)

        review = compare_audit_reports(before, after).to_review_summary()

        self.assertIn("Improved dispositions: 1", review)
        self.assertIn("`REVIEW_IMPROVED_DISPOSITIONS`", review)
        self.assertIn("without treating them as proof", review)

    def test_review_guidance_covers_detector_and_semantic_uncertainty(self) -> None:
        policy = load_policy(POLICY_PATH)
        baseline = build_report([], policy, Path("trace.jsonl"), Path("policy.yml"))
        changed = build_report(
            [],
            policy,
            Path("trace.jsonl"),
            Path("policy.yml"),
            enable_presidio=True,
            semantic_resolver=NoopSemanticResolver(),
        )

        guidance = compare_audit_reports(baseline, changed).review_guidance()
        codes = [item["code"] for item in guidance]

        self.assertIn("VALIDATE_DETECTOR_COMPARABILITY", codes)
        self.assertIn("VALIDATE_SEMANTIC_COMPARABILITY", codes)

    def test_review_summary_handles_legacy_provenance_and_empty_reports(self) -> None:
        before = report([])
        after = copy.deepcopy(before)
        before.pop("audit_context")
        after.pop("audit_context")

        result = compare_audit_reports(before, after)
        review = result.to_review_summary()
        codes = [item["code"] for item in result.review_guidance()]

        self.assertIn("Configuration evidence is incomplete", review)
        self.assertIn("VALIDATE_POLICY_COMPARABILITY", codes)
        self.assertIn("VALIDATE_DETECTOR_COMPARABILITY", codes)
        self.assertIn("VALIDATE_SEMANTIC_COMPARABILITY", codes)
        self.assertIn("Newly observed routes: 0", review)

    def test_review_summary_is_bounded_deterministic_and_omits_input_data(self) -> None:
        sensitive_name = "Casey Example"
        sensitive_path = "records.casey-example.private"
        after_events = [
            event(
                f"evt-{index}",
                {f"private-{index}": f"member_id=MBR-SYN-{10000 + index}"},
                source_type=sensitive_name,
                source_path=sensitive_path,
                destinations=[{"layer": "model_input", "path": f"prompt.{sensitive_name}.{index}"}],
            )
            for index in range(40)
        ]
        after = report(after_events)
        for finding in after["findings"]:
            finding["reason"] = "private detector explanation"
            finding["policy"]["reason"] = "private policy explanation"
        result = compare_audit_reports(report([]), after)

        first = result.to_review_summary()
        second = result.to_review_summary()

        self.assertEqual(first, second)
        self.assertIn("Newly observed routes: 40", first)
        self.assertLessEqual(len(result.review_guidance()), MAX_REVIEW_GUIDANCE_ITEMS)
        self.assertNotIn(sensitive_name, first)
        self.assertNotIn(sensitive_path, first)
        self.assertNotIn("MBR-SYN", first)
        self.assertNotIn("sha256:", first)
        self.assertNotIn("private detector explanation", first)
        self.assertNotIn("private policy explanation", first)

        all_categories = copy.deepcopy(result.to_dict())
        all_categories["summary"]["no_longer_observed"] = 1
        all_categories["summary"]["changed_frequencies"] = 1
        all_categories["summary"]["disposition_directions"] = {
            "worsened": 1,
            "improved": 1,
            "mixed_or_other": 1,
        }
        all_categories["comparability"]["reason_codes"] = [
            "POLICY_FINGERPRINT_MISMATCH",
            "DETECTOR_FINGERPRINT_MISMATCH",
            "SEMANTIC_CONFIGURATION_MISMATCH",
        ]
        bounded = render_exposure_review_summary(all_categories)
        self.assertEqual(len(build_review_guidance(all_categories)), MAX_REVIEW_GUIDANCE_ITEMS)
        self.assertIn("Additional guidance categories omitted: 3", bounded)

    def test_cli_review_summary_matches_sdk_and_risk_changes_exit_zero(self) -> None:
        events = [event("evt-1", {"member_id": "member_id=MBR-SYN-10001"})]
        before = report(events)
        after = report(events, policy=policy_with_member_denied_in_tool_output())
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            before_path = root / "before.json"
            after_path = root / "after.json"
            review_path = root / "review-summary.md"
            before_path.write_text(json.dumps(before), encoding="utf-8")
            after_path.write_text(json.dumps(after), encoding="utf-8")

            expected = compare_report_files(before_path, after_path).to_review_summary()
            code = main(
                [
                    "compare-reports",
                    "--before",
                    str(before_path),
                    "--after",
                    str(after_path),
                    "--out",
                    str(root / "diff.md"),
                    "--json",
                    str(root / "diff.json"),
                    "--review-summary",
                    str(review_path),
                ]
            )

            self.assertEqual(code, 0)
            self.assertEqual(review_path.read_text(), expected)

    def test_cli_review_summary_write_error_uses_existing_error_exit_code(self) -> None:
        valid = report([])
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            before_path = root / "before.json"
            after_path = root / "after.json"
            unwritable_target = root / "summary-directory"
            before_path.write_text(json.dumps(valid), encoding="utf-8")
            after_path.write_text(json.dumps(valid), encoding="utf-8")
            unwritable_target.mkdir()
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                code = main(
                    [
                        "compare-reports",
                        "--before",
                        str(before_path),
                        "--after",
                        str(after_path),
                        "--out",
                        str(root / "diff.md"),
                        "--json",
                        str(root / "diff.json"),
                        "--review-summary",
                        str(unwritable_target),
                    ]
                )

            self.assertEqual(code, 2)
            self.assertIn("error:", stderr.getvalue())

    def test_cli_invalid_json_returns_existing_validation_exit_code_without_outputs(self) -> None:
        valid = report([])
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            before_path = root / "before.json"
            after_path = root / "after.json"
            before_path.write_text("{not json", encoding="utf-8")
            after_path.write_text(json.dumps(valid), encoding="utf-8")
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                code = main(
                    [
                        "compare-reports",
                        "--before",
                        str(before_path),
                        "--after",
                        str(after_path),
                        "--out",
                        str(root / "diff.md"),
                        "--json",
                        str(root / "diff.json"),
                    ]
                )

            self.assertEqual(code, 2)
            self.assertIn("before report is invalid JSON", stderr.getvalue())
            self.assertFalse((root / "diff.md").exists())
            self.assertFalse((root / "diff.json").exists())


if __name__ == "__main__":
    unittest.main()
