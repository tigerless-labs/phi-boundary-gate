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
from phi_boundary_gate.exposure_diff import compare_audit_reports, compare_report_files
from phi_boundary_gate.policy import Policy, load_policy
from phi_boundary_gate.report import build_report
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
        self.assertEqual(diff["comparability"]["status"], "limited")
        self.assertFalse(diff["comparability"]["policy_reference_match"])
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
            self.assertEqual(json.loads((root / "diff.json").read_text()), first)
            self.assertIn("This is advisory", (root / "diff.md").read_text())

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
