from __future__ import annotations

import contextlib
import copy
import io
import json
import tempfile
import unittest
from pathlib import Path

from phi_boundary_gate import (
    COVERAGE_AWARE_DISCLAIMER,
    build_audit_coverage,
    compare_audit_reports,
    compare_coverage,
    compare_coverage_files,
    render_coverage_diff_markdown,
)
from phi_boundary_gate.cli import main
from phi_boundary_gate.policy import load_policy
from phi_boundary_gate.report import build_report
from phi_boundary_gate.trace import TraceEvent


ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "samples/policies/default.yml"


def event(event_id: str, layer: str, content: str = "Synthetic content") -> TraceEvent:
    return TraceEvent(
        event_id=event_id,
        timestamp="2026-10-27T00:00:00Z",
        layer=layer,
        content=content,
        source={"type": "synthetic"},
        destinations=[{"layer": "model_provider"}],
    )


def coverage(events: list[TraceEvent], *, expected_layers: list[str] | None = None) -> dict:
    return build_audit_coverage(events, expected_layers=expected_layers or []).to_dict()


def exposure_diff(
    before_groups: int,
    after_groups: int,
    before_occurrences: int | None = None,
    after_occurrences: int | None = None,
) -> dict:
    new_exposures = max(after_groups - before_groups, 0)
    no_longer_observed = max(before_groups - after_groups, 0)
    return {
        "schema_version": 1,
        "analysis_type": "advisory_exposure_diff",
        "summary": {
            "before_exposure_groups": before_groups,
            "after_exposure_groups": after_groups,
            "before_group_occurrences": before_groups if before_occurrences is None else before_occurrences,
            "after_group_occurrences": after_groups if after_occurrences is None else after_occurrences,
            "new_exposures": new_exposures,
            "no_longer_observed": no_longer_observed,
            "changed_dispositions": 0,
            "changed_frequencies": 0,
        },
    }


def audit_report(events: list[TraceEvent]) -> dict:
    return build_report(
        events,
        load_policy(POLICY_PATH),
        Path("synthetic-trace.jsonl"),
        Path("synthetic-policy.yml"),
        report_value_mode="redacted",
    )


def write_json(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data), encoding="utf-8")


class CoverageDiffTests(unittest.TestCase):
    def test_identical_coverage_is_stable_and_deterministic(self) -> None:
        baseline = coverage(
            [event("evt-1", "user_message"), event("evt-2", "model_input")],
            expected_layers=["user_message", "model_input"],
        )

        first = compare_coverage(baseline, copy.deepcopy(baseline), exposure_diff=exposure_diff(2, 2))
        second = compare_coverage(baseline, copy.deepcopy(baseline), exposure_diff=exposure_diff(2, 2))

        self.assertEqual(first.to_dict(), second.to_dict())
        self.assertEqual(first.to_markdown(), second.to_markdown())
        self.assertEqual(first.to_dict()["coverage_comparison"]["scope_direction"], "unchanged")
        self.assertEqual(first.to_dict()["reason_codes"], ["NO_OBSERVED_COVERAGE_CHANGE"])

    def test_layer_removal_addition_and_count_changes_are_separate(self) -> None:
        before = coverage(
            [
                event("evt-1", "user_message"),
                event("evt-2", "user_message"),
                event("evt-3", "tool_output"),
            ]
        )
        after = coverage(
            [
                event("evt-4", "user_message"),
                event("evt-5", "model_input"),
                event("evt-6", "model_input"),
            ]
        )

        comparison = compare_coverage(before, after).to_dict()["coverage_comparison"]

        self.assertEqual(comparison["layer_changes"]["previously_observed_missing"], ["tool_output"])
        self.assertEqual(comparison["layer_changes"]["newly_observed"], ["model_input"])
        self.assertEqual(comparison["events_by_layer"]["user_message"]["absolute_delta"], -1)
        self.assertEqual(comparison["events_by_layer"]["model_input"]["absolute_delta"], 2)
        self.assertEqual(comparison["events_by_layer"]["model_input"]["percentage_delta"], None)
        self.assertEqual(
            comparison["events_by_layer"]["model_input"]["percentage_delta_status"],
            "not_applicable_zero_baseline",
        )

    def test_event_content_and_scannable_deltas_have_absolute_and_percentage_values(self) -> None:
        before = coverage(
            [event("evt-1", "user_message", "one"), event("evt-2", "user_message", '{"a":"two","b":3}')]
        )
        after = coverage([event("evt-3", "user_message", "")])

        metrics = compare_coverage(before, after).to_dict()["coverage_comparison"]["metrics"]

        self.assertEqual(metrics["observed_event_count"]["absolute_delta"], -1)
        self.assertEqual(metrics["observed_event_count"]["percentage_delta"], -50.0)
        self.assertEqual(metrics["nonempty_content_event_count"]["absolute_delta"], -2)
        self.assertEqual(metrics["scannable_segment_count"]["absolute_delta"], -3)

    def test_exposure_decrease_with_contracted_coverage_is_not_claimed_as_improvement(self) -> None:
        before = coverage([event(f"evt-{index}", "tool_output") for index in range(4)])
        after = coverage([event("evt-after", "tool_output")])

        result = compare_coverage(before, after, exposure_diff=exposure_diff(12, 3, 20, 4))
        interpretation = result.to_dict()["exposure_interpretation"]

        self.assertEqual(interpretation["coverage_direction"], "contracted")
        self.assertEqual(interpretation["exposure_direction"], "decreased")
        self.assertEqual(
            interpretation["reason_codes"],
            ["OBSERVED_EXPOSURE_DECREASE_WITH_NARROWER_SCOPE"],
        )
        self.assertNotIn("risk improved", result.to_markdown().lower())

    def test_exposure_increase_with_expanded_coverage_is_not_attributed_to_agent(self) -> None:
        before = coverage([event("evt-before", "user_message")])
        after = coverage(
            [event("evt-after-1", "user_message"), event("evt-after-2", "model_input")]
        )

        result = compare_coverage(before, after, exposure_diff=exposure_diff(1, 4))
        interpretation = result.to_dict()["exposure_interpretation"]

        self.assertEqual(interpretation["coverage_direction"], "expanded")
        self.assertEqual(
            interpretation["reason_codes"],
            ["OBSERVED_EXPOSURE_INCREASE_WITH_BROADER_SCOPE"],
        )
        self.assertIn("must not be attributed", interpretation["messages"][0])

    def test_stable_coverage_with_exposure_change_preserves_limitations(self) -> None:
        observed = coverage([event("evt", "model_input")])

        result = compare_coverage(observed, copy.deepcopy(observed), exposure_diff=exposure_diff(1, 2))
        interpretation = result.to_dict()["exposure_interpretation"]

        self.assertEqual(
            interpretation["reason_codes"],
            ["OBSERVED_EXPOSURE_CHANGE_WITH_STABLE_COVERAGE"],
        )
        self.assertIn("detector recall", interpretation["messages"][0])

    def test_stable_coverage_detects_non_volume_exposure_changes(self) -> None:
        observed = coverage([event("evt", "model_input")])
        changed = exposure_diff(1, 1)
        changed["summary"]["changed_dispositions"] = 1

        interpretation = compare_coverage(
            observed,
            copy.deepcopy(observed),
            exposure_diff=changed,
        ).to_dict()["exposure_interpretation"]

        self.assertEqual(interpretation["exposure_direction"], "changed")
        self.assertEqual(
            interpretation["reason_codes"],
            ["OBSERVED_EXPOSURE_CHANGE_WITH_STABLE_COVERAGE"],
        )

    def test_empty_coverage_is_comparable_but_missing_coverage_is_unavailable(self) -> None:
        empty = coverage([])

        comparable = compare_coverage(empty, copy.deepcopy(empty), exposure_diff=exposure_diff(0, 0)).to_dict()
        missing = compare_coverage(None, None, exposure_diff=exposure_diff(0, 0)).to_dict()

        self.assertEqual(comparable["status"], "available")
        self.assertEqual(comparable["coverage_comparison"]["scope_direction"], "unchanged")
        self.assertEqual(
            comparable["coverage_comparison"]["metrics"]["observed_event_count"]["percentage_delta_status"],
            "not_applicable_zero_baseline",
        )
        self.assertEqual(missing["status"], "unavailable")
        self.assertEqual(missing["reason_codes"], ["COVERAGE_COMPARISON_UNAVAILABLE"])

    def test_incompatible_coverage_schema_is_unavailable_and_legacy_audit_reports_still_work(self) -> None:
        current = coverage([event("evt", "tool_output")])
        future = copy.deepcopy(current)
        future["schema_version"] = 2
        unavailable = compare_coverage(current, future, exposure_diff=exposure_diff(1, 1)).to_dict()

        before_report = audit_report([])
        after_report = audit_report([event("evt-phi", "tool_output", "member_id=MBR-SYN-70001")])
        before_report.pop("audit_context")
        after_report.pop("audit_context")
        legacy_diff = compare_audit_reports(before_report, after_report)
        compatible = compare_coverage(current, current, exposure_diff=legacy_diff).to_dict()

        self.assertEqual(unavailable["coverage_comparison"]["availability"], "after_incompatible")
        self.assertEqual(unavailable["exposure_interpretation"]["status"], "limited")
        self.assertEqual(compatible["status"], "available")

    def test_expected_layer_and_blind_spot_changes_are_explicit(self) -> None:
        before = coverage(
            [event("evt-1", "user_message", "")],
            expected_layers=["user_message", "model_input"],
        )
        after = coverage(
            [event("evt-2", "user_message")],
            expected_layers=["user_message", "tool_output"],
        )

        diff = compare_coverage(before, after).to_dict()
        expected = diff["coverage_comparison"]["expected_layer_changes"]
        diagnostics = diff["coverage_comparison"]["blind_spot_diagnostic_changes"]

        self.assertTrue(expected["configuration_changed"])
        self.assertEqual(expected["added_expected_layers"], ["tool_output"])
        self.assertEqual(expected["removed_expected_layers"], ["model_input"])
        self.assertIn("EMPTY_CONTENT_EVENTS", diagnostics["resolved"])
        self.assertIn("EXPECTED_LAYER_COVERAGE_CHANGED", diff["reason_codes"])
        self.assertIn("BLIND_SPOT_DIAGNOSTICS_CHANGED", diff["reason_codes"])

    def test_cli_rejects_one_sided_coverage_arguments(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = audit_report([])
            write_json(root / "before.json", report)
            write_json(root / "after.json", report)
            write_json(root / "before-coverage.json", coverage([]))
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                code = main(
                    [
                        "compare-reports",
                        "--before",
                        str(root / "before.json"),
                        "--after",
                        str(root / "after.json"),
                        "--out",
                        str(root / "diff.md"),
                        "--json",
                        str(root / "diff.json"),
                        "--before-coverage",
                        str(root / "before-coverage.json"),
                        "--coverage-diff-json",
                        str(root / "coverage-diff.json"),
                    ]
                )

            self.assertEqual(code, 2)
            self.assertIn("must be provided together", stderr.getvalue())
            self.assertFalse((root / "coverage-diff.json").exists())

    def test_sdk_and_cli_outputs_match_and_advisory_warning_exits_zero(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            before_report = audit_report([event("evt-1", "tool_output", "member_id=MBR-SYN-10001")])
            after_report = audit_report([])
            before_coverage = coverage(
                [event("evt-1", "tool_output")],
                expected_layers=["tool_output", "model_input"],
            )
            after_coverage = coverage([], expected_layers=["tool_output", "model_input"])
            for name, data in (
                ("before.json", before_report),
                ("after.json", after_report),
                ("before-coverage.json", before_coverage),
                ("after-coverage.json", after_coverage),
            ):
                write_json(root / name, data)
            expected = compare_coverage_files(
                root / "before-coverage.json",
                root / "after-coverage.json",
                exposure_diff=compare_audit_reports(before_report, after_report),
            )

            code = main(
                [
                    "compare-reports",
                    "--before",
                    str(root / "before.json"),
                    "--after",
                    str(root / "after.json"),
                    "--out",
                    str(root / "diff.md"),
                    "--json",
                    str(root / "diff.json"),
                    "--before-coverage",
                    str(root / "before-coverage.json"),
                    "--after-coverage",
                    str(root / "after-coverage.json"),
                    "--coverage-review",
                    str(root / "coverage-review.md"),
                    "--coverage-diff-json",
                    str(root / "coverage-diff.json"),
                ]
            )

            self.assertEqual(code, 0)
            self.assertEqual(json.loads((root / "coverage-diff.json").read_text()), expected.to_dict())
            self.assertEqual((root / "coverage-review.md").read_text(), expected.to_markdown())
            self.assertIn("EXPECTED_LAYER_NOT_OBSERVED", (root / "coverage-diff.json").read_text())

    def test_output_does_not_copy_phi_paths_content_or_free_text(self) -> None:
        sensitive = "Casey Example MBR-SYN-8842 records.private"
        before = coverage([event("evt", "tool_output")])
        after = copy.deepcopy(before)
        before["private_path"] = sensitive
        before["diagnostics"][0]["message"] = sensitive
        after["interpretation"]["observed_scope"] = sensitive

        result = compare_coverage(before, after, exposure_diff=exposure_diff(1, 1))
        serialized = json.dumps(result.to_dict()) + render_coverage_diff_markdown(result)

        self.assertNotIn("Casey Example", serialized)
        self.assertNotIn("MBR-SYN", serialized)
        self.assertNotIn("records.private", serialized)
        self.assertIn(COVERAGE_AWARE_DISCLAIMER, serialized)

    def test_default_exposure_diff_cli_output_remains_compatible(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            before = audit_report([])
            after = audit_report([event("evt", "tool_output", "member_id=MBR-SYN-10001")])
            write_json(root / "before.json", before)
            write_json(root / "after.json", after)
            expected = compare_audit_reports(before, after).to_dict()

            code = main(
                [
                    "compare-reports",
                    "--before",
                    str(root / "before.json"),
                    "--after",
                    str(root / "after.json"),
                    "--out",
                    str(root / "diff.md"),
                    "--json",
                    str(root / "diff.json"),
                ]
            )

            self.assertEqual(code, 0)
            self.assertEqual(json.loads((root / "diff.json").read_text()), expected)
            self.assertFalse((root / "coverage-diff.json").exists())

    def test_invalid_v1_coverage_and_write_errors_use_existing_error_exit_code(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = audit_report([])
            write_json(root / "before.json", report)
            write_json(root / "after.json", report)
            malformed = coverage([])
            del malformed["summary"]["scannable_segment_count"]
            write_json(root / "before-coverage.json", malformed)
            write_json(root / "after-coverage.json", coverage([]))
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                invalid_code = main(
                    [
                        "compare-reports",
                        "--before",
                        str(root / "before.json"),
                        "--after",
                        str(root / "after.json"),
                        "--out",
                        str(root / "diff.md"),
                        "--json",
                        str(root / "diff.json"),
                        "--before-coverage",
                        str(root / "before-coverage.json"),
                        "--after-coverage",
                        str(root / "after-coverage.json"),
                        "--coverage-diff-json",
                        str(root / "coverage-diff.json"),
                    ]
                )
            self.assertEqual(invalid_code, 2)
            self.assertIn("must be a non-negative integer", stderr.getvalue())

            write_json(root / "before-coverage.json", coverage([]))
            unwritable = root / "directory-target"
            unwritable.mkdir()
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                write_code = main(
                    [
                        "compare-reports",
                        "--before",
                        str(root / "before.json"),
                        "--after",
                        str(root / "after.json"),
                        "--out",
                        str(root / "diff.md"),
                        "--json",
                        str(root / "diff.json"),
                        "--before-coverage",
                        str(root / "before-coverage.json"),
                        "--after-coverage",
                        str(root / "after-coverage.json"),
                        "--coverage-diff-json",
                        str(unwritable),
                    ]
                )
            self.assertEqual(write_code, 2)
            self.assertIn("error:", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
