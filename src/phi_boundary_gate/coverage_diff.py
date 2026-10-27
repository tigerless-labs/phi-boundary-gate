from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from .coverage import COVERAGE_SCHEMA_VERSION
from .exposure_diff import DIFF_SCHEMA_VERSION, ExposureDiffResult
from .trace import SUPPORTED_LAYERS


COVERAGE_DIFF_SCHEMA_VERSION = 1

COVERAGE_AWARE_DISCLAIMER = (
    "Coverage-Aware Diff compares observed audit scope. It does not establish complete trace capture, "
    "causal risk changes, or HIPAA compliance."
)

_SUMMARY_METRICS = (
    "observed_event_count",
    "empty_content_event_count",
    "nonempty_content_event_count",
    "scannable_segment_count",
    "structured_content_event_count",
    "structured_content_without_scalar_event_count",
    "events_with_source_count",
    "events_with_destinations_count",
    "provider_destination_event_count",
)

_DIRECTION_METRICS = (
    "observed_event_count",
    "nonempty_content_event_count",
    "scannable_segment_count",
)

_KNOWN_DIAGNOSTIC_CODES = frozenset(
    {
        "EMPTY_TRACE",
        "EMPTY_CONTENT_EVENTS",
        "EXPECTED_LAYER_NOT_OBSERVED",
        "NO_EXPLICIT_DESTINATIONS",
        "NO_PROVIDER_DESTINATION_OBSERVED",
        "MAPPING_OPTIONAL_CONTENT_UNUSED",
        "COVERAGE_UNVERIFIED",
    }
)

_INTERPRETATION_MESSAGES = {
    "COVERAGE_COMPARISON_UNAVAILABLE": (
        "Coverage evidence is unavailable or incompatible, so the exposure diff is preserved without a coverage-based "
        "interpretation."
    ),
    "OBSERVED_EXPOSURE_DECREASE_WITH_NARROWER_SCOPE": (
        "Observed exposure decreased while observed audit scope contracted. The decrease may be affected by input-scope "
        "change and must not be interpreted by itself as improved privacy protection."
    ),
    "OBSERVED_EXPOSURE_INCREASE_WITH_BROADER_SCOPE": (
        "Observed exposure increased while observed audit scope expanded. The increase may be affected by broader "
        "observation and must not be attributed by itself to worse Agent behavior."
    ),
    "OBSERVED_EXPOSURE_CHANGE_WITH_STABLE_COVERAGE": (
        "Observed exposure changed without a change in the compared audit-scope statistics. This does not prove equal "
        "workloads, detector recall, complete trace capture, or equal real-world risk conditions."
    ),
    "OBSERVED_EXPOSURE_CHANGE_WITH_MIXED_COVERAGE": (
        "Observed exposure and audit-scope statistics changed in mixed directions. Review both evidence sets without "
        "making a causal risk attribution."
    ),
    "NO_OBSERVED_EXPOSURE_CHANGE": (
        "No aggregate exposure-volume change was observed. This does not establish unchanged real-world PHI risk."
    ),
    "EXPOSURE_COMPARISON_UNAVAILABLE": (
        "No compatible exposure diff was supplied, so this sidecar describes coverage changes only."
    ),
}


@dataclass(frozen=True)
class CoverageDiffResult:
    """Advisory comparison of aggregate audit coverage evidence."""

    report: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return self.report

    def to_markdown(self) -> str:
        return render_coverage_diff_markdown(self.report)

    def write_json(self, path: Path | str) -> None:
        write_coverage_diff_json(self.report, Path(path))

    def write_markdown(self, path: Path | str) -> None:
        write_coverage_diff_markdown(self.report, Path(path))


def load_coverage_report(path: Path | str, *, label: str = "coverage") -> dict[str, Any]:
    """Read a Coverage JSON sidecar without copying its source path into output."""

    source = Path(path)
    try:
        raw = json.loads(source.read_text(encoding="utf-8"))
    except OSError as exc:
        detail = exc.strerror or type(exc).__name__
        raise ValueError(f"{label} coverage could not be read: {detail}") from None
    except UnicodeError as exc:
        raise ValueError(f"{label} coverage is not valid UTF-8") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"{label} coverage is invalid JSON: {exc.msg}") from exc
    if not isinstance(raw, dict):
        raise ValueError(f"{label} coverage must be a JSON object")
    return raw


def compare_coverage_files(
    before_path: Path | str,
    after_path: Path | str,
    *,
    exposure_diff: Mapping[str, Any] | ExposureDiffResult | None = None,
) -> CoverageDiffResult:
    before = load_coverage_report(before_path, label="before")
    after = load_coverage_report(after_path, label="after")
    return compare_coverage(before, after, exposure_diff=exposure_diff)


def compare_coverage(
    before: Mapping[str, Any] | None,
    after: Mapping[str, Any] | None,
    *,
    exposure_diff: Mapping[str, Any] | ExposureDiffResult | None = None,
) -> CoverageDiffResult:
    """Compare v1 Coverage summaries and optionally interpret an Exposure Diff.

    Missing or unsupported Coverage evidence produces an explicit unavailable
    result. A malformed document that claims to be Coverage v1 is invalid input.
    """

    availability = _coverage_availability(before, after)
    exposure_summary = _exposure_summary(exposure_diff)
    if availability != "available":
        interpretation = _build_exposure_interpretation(None, exposure_summary)
        return CoverageDiffResult(
            {
                "schema_version": COVERAGE_DIFF_SCHEMA_VERSION,
                "analysis_type": "advisory_coverage_aware_exposure_diff",
                "status": "unavailable",
                "reason_codes": ["COVERAGE_COMPARISON_UNAVAILABLE"],
                "coverage_comparison": {
                    "status": "unavailable",
                    "availability": availability,
                    "before_evidence": _evidence_status(before),
                    "after_evidence": _evidence_status(after),
                },
                "exposure_interpretation": interpretation,
                "limitations": [COVERAGE_AWARE_DISCLAIMER],
            }
        )

    assert before is not None and after is not None
    before_data = _validate_coverage(before, "before")
    after_data = _validate_coverage(after, "after")
    comparison = _build_coverage_comparison(before_data, after_data)
    interpretation = _build_exposure_interpretation(comparison["scope_direction"], exposure_summary)
    return CoverageDiffResult(
        {
            "schema_version": COVERAGE_DIFF_SCHEMA_VERSION,
            "analysis_type": "advisory_coverage_aware_exposure_diff",
            "status": "available",
            "reason_codes": comparison.pop("reason_codes"),
            "coverage_comparison": comparison,
            "exposure_interpretation": interpretation,
            "limitations": [COVERAGE_AWARE_DISCLAIMER],
        }
    )


def render_coverage_diff_markdown(diff: Mapping[str, Any] | CoverageDiffResult) -> str:
    data = diff.to_dict() if isinstance(diff, CoverageDiffResult) else diff
    comparison = data["coverage_comparison"]
    interpretation = data["exposure_interpretation"]
    lines = [
        "# Coverage-Aware Exposure Diff",
        "",
        "**Status: Advisory / Non-blocking**",
        "",
    ]
    if comparison["status"] == "unavailable":
        lines.extend(
            [
                "## Coverage Evidence",
                "",
                "Coverage comparison unavailable.",
                "",
                f"- Before evidence: `{comparison['before_evidence']}`",
                f"- After evidence: `{comparison['after_evidence']}`",
                f"- Availability: `{comparison['availability']}`",
                "",
            ]
        )
    else:
        lines.extend(
            [
                "## Observed Scope Delta",
                "",
                f"- Scope direction: `{comparison['scope_direction']}`",
                f"- Reason codes: `{', '.join(data['reason_codes'])}`",
                "",
                "| Measure | Before | After | Absolute Delta | Percentage Delta |",
                "| --- | ---: | ---: | ---: | ---: |",
            ]
        )
        for metric in _SUMMARY_METRICS:
            delta = comparison["metrics"][metric]
            lines.append(
                "| {metric} | {before} | {after} | {absolute} | {percentage} |".format(
                    metric=metric,
                    before=delta["before"],
                    after=delta["after"],
                    absolute=_signed(delta["absolute_delta"]),
                    percentage=_format_percentage(delta),
                )
            )
        lines.extend(
            [
                "",
                "### Events by Layer",
                "",
                "| Layer | Before | After | Absolute Delta | Percentage Delta |",
                "| --- | ---: | ---: | ---: | ---: |",
            ]
        )
        if comparison["events_by_layer"]:
            for layer, delta in comparison["events_by_layer"].items():
                lines.append(
                    "| `{layer}` | {before} | {after} | {absolute} | {percentage} |".format(
                        layer=layer,
                        before=delta["before"],
                        after=delta["after"],
                        absolute=_signed(delta["absolute_delta"]),
                        percentage=_format_percentage(delta),
                    )
                )
        else:
            lines.append("| none | 0 | 0 | 0 | N/A |")

        layer_changes = comparison["layer_changes"]
        expected = comparison["expected_layer_changes"]
        diagnostics = comparison["blind_spot_diagnostic_changes"]
        lines.extend(
            [
                "",
                "### Layer and Configuration Evidence",
                "",
                f"- Previously observed layers missing: {_format_layers(layer_changes['previously_observed_missing'])}",
                f"- Newly observed layers: {_format_layers(layer_changes['newly_observed'])}",
                f"- Expected-layer configuration changed: `{str(expected['configuration_changed']).lower()}`",
                f"- Expected layers added: {_format_layers(expected['added_expected_layers'])}",
                f"- Expected layers removed: {_format_layers(expected['removed_expected_layers'])}",
                f"- Newly missing expected layers: {_format_layers(expected['newly_missing_expected_layers'])}",
                f"- No longer missing expected layers: {_format_layers(expected['no_longer_missing_expected_layers'])}",
                "",
                "### Blind-Spot Diagnostic Changes",
                "",
                f"- Added: {_format_codes(diagnostics['added'])}",
                f"- Resolved: {_format_codes(diagnostics['resolved'])}",
                f"- Detail changed: {_format_codes(diagnostics['detail_changed'])}",
                f"- Unchanged: {_format_codes(diagnostics['unchanged'])}",
                "",
            ]
        )

    lines.extend(
        [
            "## Coverage-Aware Interpretation",
            "",
            f"- Exposure direction: `{interpretation['exposure_direction']}`",
            f"- Coverage direction: `{interpretation['coverage_direction']}`",
        ]
    )
    lines.extend(
        f"- `{code}` — {_INTERPRETATION_MESSAGES[code]}"
        for code in interpretation["reason_codes"]
    )
    lines.extend(["", "## Limitations", "", COVERAGE_AWARE_DISCLAIMER, ""])
    return "\n".join(lines)


def write_coverage_diff_json(diff: Mapping[str, Any] | CoverageDiffResult, path: Path) -> None:
    data = diff.to_dict() if isinstance(diff, CoverageDiffResult) else diff
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_coverage_diff_markdown(diff: Mapping[str, Any] | CoverageDiffResult, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_coverage_diff_markdown(diff), encoding="utf-8")


def _coverage_availability(before: Mapping[str, Any] | None, after: Mapping[str, Any] | None) -> str:
    if before is None and after is None:
        return "both_missing"
    if before is None:
        return "before_missing"
    if after is None:
        return "after_missing"
    before_schema = before.get("schema_version") if isinstance(before, Mapping) else None
    after_schema = after.get("schema_version") if isinstance(after, Mapping) else None
    if before_schema != COVERAGE_SCHEMA_VERSION and after_schema != COVERAGE_SCHEMA_VERSION:
        return "both_incompatible"
    if before_schema != COVERAGE_SCHEMA_VERSION:
        return "before_incompatible"
    if after_schema != COVERAGE_SCHEMA_VERSION:
        return "after_incompatible"
    return "available"


def _evidence_status(coverage: Mapping[str, Any] | None) -> str:
    if coverage is None:
        return "missing"
    if not isinstance(coverage, Mapping) or coverage.get("schema_version") != COVERAGE_SCHEMA_VERSION:
        return "incompatible"
    return "compatible"


def _validate_coverage(coverage: Mapping[str, Any], label: str) -> dict[str, Any]:
    if not isinstance(coverage, Mapping):
        raise ValueError(f"{label} coverage must be an object")
    summary = coverage.get("summary")
    if not isinstance(summary, Mapping):
        raise ValueError(f"{label} coverage field 'summary' must be an object")
    safe_summary: dict[str, Any] = {}
    for metric in _SUMMARY_METRICS:
        safe_summary[metric] = _nonnegative_int(summary.get(metric), f"{label} coverage summary.{metric}")
    events_by_layer = summary.get("events_by_layer")
    if not isinstance(events_by_layer, Mapping):
        raise ValueError(f"{label} coverage summary.events_by_layer must be an object")
    safe_events_by_layer: dict[str, int] = {}
    for layer, count in events_by_layer.items():
        if layer not in SUPPORTED_LAYERS:
            raise ValueError(f"{label} coverage summary.events_by_layer has an unsupported layer")
        safe_events_by_layer[layer] = _nonnegative_int(
            count,
            f"{label} coverage summary.events_by_layer count",
        )
    safe_summary["events_by_layer"] = dict(sorted(safe_events_by_layer.items()))

    observed_layers = _validate_layers(coverage.get("observed_layers"), f"{label} coverage observed_layers")
    expected_layers = _validate_layers(coverage.get("expected_layers"), f"{label} coverage expected_layers")
    if observed_layers != sorted(safe_events_by_layer):
        raise ValueError(f"{label} coverage observed_layers must match summary.events_by_layer")
    if sum(safe_events_by_layer.values()) != safe_summary["observed_event_count"]:
        raise ValueError(f"{label} coverage event counts are inconsistent")
    if (
        safe_summary["empty_content_event_count"] + safe_summary["nonempty_content_event_count"]
        != safe_summary["observed_event_count"]
    ):
        raise ValueError(f"{label} coverage content event counts are inconsistent")

    diagnostics = coverage.get("diagnostics")
    if not isinstance(diagnostics, list):
        raise ValueError(f"{label} coverage diagnostics must be an array")
    safe_diagnostics: dict[str, dict[str, Any]] = {}
    for diagnostic in diagnostics:
        if not isinstance(diagnostic, Mapping) or diagnostic.get("code") not in _KNOWN_DIAGNOSTIC_CODES:
            raise ValueError(f"{label} coverage contains an unsupported diagnostic")
        code = diagnostic["code"]
        if code in safe_diagnostics:
            raise ValueError(f"{label} coverage contains a duplicate diagnostic")
        safe: dict[str, Any] = {"code": code}
        if "count" in diagnostic:
            safe["count"] = _nonnegative_int(diagnostic["count"], f"{label} coverage diagnostic count")
        if "layers" in diagnostic:
            safe["layers"] = _validate_layers(diagnostic["layers"], f"{label} coverage diagnostic layers")
        safe_diagnostics[code] = safe
    return {
        "summary": safe_summary,
        "observed_layers": observed_layers,
        "expected_layers": expected_layers,
        "diagnostics": safe_diagnostics,
    }


def _build_coverage_comparison(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    metrics = {
        metric: _delta(before["summary"][metric], after["summary"][metric])
        for metric in _SUMMARY_METRICS
    }
    all_layers = sorted(set(before["summary"]["events_by_layer"]) | set(after["summary"]["events_by_layer"]))
    events_by_layer = {
        layer: _delta(
            before["summary"]["events_by_layer"].get(layer, 0),
            after["summary"]["events_by_layer"].get(layer, 0),
        )
        for layer in all_layers
    }
    before_observed = set(before["observed_layers"])
    after_observed = set(after["observed_layers"])
    layer_changes = {
        "previously_observed_missing": sorted(before_observed - after_observed),
        "newly_observed": sorted(after_observed - before_observed),
    }

    before_expected = set(before["expected_layers"])
    after_expected = set(after["expected_layers"])
    before_missing = before_expected - before_observed
    after_missing = after_expected - after_observed
    expected_changes = {
        "configuration_changed": before_expected != after_expected,
        "added_expected_layers": sorted(after_expected - before_expected),
        "removed_expected_layers": sorted(before_expected - after_expected),
        "before_missing_expected_layers": sorted(before_missing),
        "after_missing_expected_layers": sorted(after_missing),
        "newly_missing_expected_layers": sorted(after_missing - before_missing),
        "no_longer_missing_expected_layers": sorted(before_missing - after_missing),
    }

    before_diagnostics = before["diagnostics"]
    after_diagnostics = after["diagnostics"]
    before_codes = set(before_diagnostics)
    after_codes = set(after_diagnostics)
    diagnostic_changes = {
        "added": sorted(after_codes - before_codes),
        "resolved": sorted(before_codes - after_codes),
        "detail_changed": sorted(
            code
            for code in before_codes & after_codes
            if before_diagnostics[code] != after_diagnostics[code]
        ),
        "unchanged": sorted(
            code
            for code in before_codes & after_codes
            if before_diagnostics[code] == after_diagnostics[code]
        ),
    }

    signs = {metrics[metric]["absolute_delta"] for metric in _DIRECTION_METRICS}
    signs.update(delta["absolute_delta"] for delta in events_by_layer.values())
    has_increase = any(value > 0 for value in signs)
    has_decrease = any(value < 0 for value in signs)
    if has_increase and has_decrease:
        scope_direction = "mixed"
    elif has_increase:
        scope_direction = "expanded"
    elif has_decrease:
        scope_direction = "contracted"
    else:
        scope_direction = "unchanged"

    reason_codes = ["NO_OBSERVED_COVERAGE_CHANGE"] if scope_direction == "unchanged" else ["OBSERVATION_SCOPE_CHANGED"]
    if layer_changes["previously_observed_missing"]:
        reason_codes.append("PREVIOUSLY_OBSERVED_LAYER_MISSING")
    if layer_changes["newly_observed"]:
        reason_codes.append("NEW_LAYER_OBSERVED")
    if metrics["scannable_segment_count"]["absolute_delta"] < 0:
        reason_codes.append("SCANNABLE_CONTENT_DECREASED")
    if expected_changes["configuration_changed"] or before_missing != after_missing:
        reason_codes.append("EXPECTED_LAYER_COVERAGE_CHANGED")
    if any(diagnostic_changes[key] for key in ("added", "resolved", "detail_changed")):
        reason_codes.append("BLIND_SPOT_DIAGNOSTICS_CHANGED")
    return {
        "status": "available",
        "coverage_schema_version": COVERAGE_SCHEMA_VERSION,
        "scope_direction": scope_direction,
        "metrics": metrics,
        "events_by_layer": events_by_layer,
        "layer_changes": layer_changes,
        "expected_layer_changes": expected_changes,
        "blind_spot_diagnostic_changes": diagnostic_changes,
        "reason_codes": reason_codes,
    }


def _exposure_summary(
    exposure_diff: Mapping[str, Any] | ExposureDiffResult | None,
) -> dict[str, int] | None:
    if exposure_diff is None:
        return None
    data = exposure_diff.to_dict() if isinstance(exposure_diff, ExposureDiffResult) else exposure_diff
    if not isinstance(data, Mapping):
        raise ValueError("exposure diff must be an object")
    if data.get("schema_version") != DIFF_SCHEMA_VERSION or data.get("analysis_type") != "advisory_exposure_diff":
        raise ValueError("exposure diff is not a compatible advisory exposure diff")
    summary = data.get("summary")
    if not isinstance(summary, Mapping):
        raise ValueError("exposure diff summary must be an object")
    return {
        field: _nonnegative_int(summary.get(field), f"exposure diff summary.{field}")
        for field in (
            "before_exposure_groups",
            "after_exposure_groups",
            "before_group_occurrences",
            "after_group_occurrences",
            "new_exposures",
            "no_longer_observed",
            "changed_dispositions",
            "changed_frequencies",
        )
    }


def _build_exposure_interpretation(
    coverage_direction: str | None,
    exposure_summary: dict[str, int] | None,
) -> dict[str, Any]:
    if exposure_summary is None:
        codes = ["EXPOSURE_COMPARISON_UNAVAILABLE"]
        return {
            "status": "unavailable",
            "exposure_direction": "unknown",
            "coverage_direction": coverage_direction or "unknown",
            "reason_codes": codes,
            "messages": [_INTERPRETATION_MESSAGES[code] for code in codes],
        }

    exposure_direction = _aggregate_direction(
        exposure_summary["before_exposure_groups"],
        exposure_summary["after_exposure_groups"],
        exposure_summary["before_group_occurrences"],
        exposure_summary["after_group_occurrences"],
    )
    exposure_changed = any(
        exposure_summary[field]
        for field in (
            "new_exposures",
            "no_longer_observed",
            "changed_dispositions",
            "changed_frequencies",
        )
    )
    if exposure_direction == "unchanged" and exposure_changed:
        exposure_direction = "changed"
    if coverage_direction is None:
        codes = ["COVERAGE_COMPARISON_UNAVAILABLE"]
        status = "limited"
    elif exposure_direction == "unchanged":
        codes = ["NO_OBSERVED_EXPOSURE_CHANGE"]
        status = "available"
    elif coverage_direction == "unchanged":
        codes = ["OBSERVED_EXPOSURE_CHANGE_WITH_STABLE_COVERAGE"]
        status = "available"
    elif exposure_direction == "decreased" and coverage_direction == "contracted":
        codes = ["OBSERVED_EXPOSURE_DECREASE_WITH_NARROWER_SCOPE"]
        status = "available"
    elif exposure_direction == "increased" and coverage_direction == "expanded":
        codes = ["OBSERVED_EXPOSURE_INCREASE_WITH_BROADER_SCOPE"]
        status = "available"
    else:
        codes = ["OBSERVED_EXPOSURE_CHANGE_WITH_MIXED_COVERAGE"]
        status = "available"
    return {
        "status": status,
        "exposure_direction": exposure_direction,
        "coverage_direction": coverage_direction or "unknown",
        "reason_codes": codes,
        "messages": [_INTERPRETATION_MESSAGES[code] for code in codes],
    }


def _aggregate_direction(before_groups: int, after_groups: int, before_occurrences: int, after_occurrences: int) -> str:
    changes = (after_groups - before_groups, after_occurrences - before_occurrences)
    if all(value == 0 for value in changes):
        return "unchanged"
    if all(value <= 0 for value in changes):
        return "decreased"
    if all(value >= 0 for value in changes):
        return "increased"
    return "mixed"


def _delta(before: int, after: int) -> dict[str, Any]:
    absolute = after - before
    if before == 0:
        percentage = None
        status = "not_applicable_zero_baseline"
    else:
        percentage = round((absolute / before) * 100, 2)
        status = "available"
    return {
        "before": before,
        "after": after,
        "absolute_delta": absolute,
        "percentage_delta": percentage,
        "percentage_delta_status": status,
    }


def _validate_layers(value: Any, label: str) -> list[str]:
    if not isinstance(value, list) or any(layer not in SUPPORTED_LAYERS for layer in value):
        raise ValueError(f"{label} must be an array of supported layers")
    if len(value) != len(set(value)):
        raise ValueError(f"{label} must not contain duplicates")
    return sorted(value)


def _nonnegative_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{label} must be a non-negative integer")
    return value


def _signed(value: int) -> str:
    return f"{value:+d}" if value else "0"


def _format_percentage(delta: Mapping[str, Any]) -> str:
    value = delta["percentage_delta"]
    return "N/A" if value is None else f"{value:+.2f}%"


def _format_layers(layers: list[str]) -> str:
    return ", ".join(f"`{layer}`" for layer in layers) if layers else "none"


def _format_codes(codes: list[str]) -> str:
    return ", ".join(f"`{code}`" for code in codes) if codes else "none"
