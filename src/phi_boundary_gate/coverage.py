from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

from .structured_content import content_segments, structured_content_segments
from .trace import SUPPORTED_LAYERS, TraceEvent


COVERAGE_SCHEMA_VERSION = 1

_INTERPRETATION = {
    "observed_scope": "Coverage describes observed normalized trace input only; it does not prove agent execution completeness.",
    "zero_findings": "Zero detected findings does not prove that the complete agent execution was PHI-free.",
    "compliance": "Coverage warnings are advisory and do not determine HIPAA compliance.",
}

_MESSAGES = {
    "EMPTY_TRACE": "No normalized trace events were observed.",
    "EMPTY_CONTENT_EVENTS": "One or more observed events had no scannable plain-text or structured scalar content.",
    "EXPECTED_LAYER_NOT_OBSERVED": "One or more explicitly expected layers were not observed.",
    "NO_EXPLICIT_DESTINATIONS": "No observed event included an explicit destination.",
    "NO_PROVIDER_DESTINATION_OBSERVED": "Destinations were observed, but none identified the model_provider sink.",
    "MAPPING_OPTIONAL_CONTENT_UNUSED": "One or more optional mapped content fields did not produce content in the observed external trace.",
    "COVERAGE_UNVERIFIED": "No expected layers were supplied, so execution-stage completeness was not checked.",
}


@dataclass(frozen=True)
class AuditCoverageResult:
    coverage: dict[str, Any]

    @property
    def summary(self) -> dict[str, Any]:
        return self.coverage["summary"]

    @property
    def diagnostics(self) -> list[dict[str, Any]]:
        return self.coverage["diagnostics"]

    @property
    def has_warnings(self) -> bool:
        return bool(self.diagnostics)

    def to_dict(self) -> dict[str, Any]:
        return self.coverage

    def to_markdown(self) -> str:
        return render_coverage_markdown(self.coverage)

    def write_json(self, path: Path | str) -> None:
        write_coverage_json(self.coverage, Path(path))

    def write_markdown(self, path: Path | str) -> None:
        write_coverage_markdown(self.coverage, Path(path))


def build_audit_coverage(
    events: list[TraceEvent],
    *,
    expected_layers: Iterable[str] = (),
    mapping_diagnostics: Mapping[str, Any] | None = None,
) -> AuditCoverageResult:
    """Summarize the normalized events actually available to the scanner.

    Adapter diagnostics are optional supporting evidence. Only their aggregate
    optional-content usage is copied into the result; raw mapping paths and
    external keys are never exported.
    """
    expected = _normalize_expected_layers(expected_layers)
    observed_layers = sorted({event.layer for event in events})
    events_by_layer = _count_values(event.layer for event in events)

    empty_content_event_count = 0
    scannable_segment_count = 0
    structured_content_event_count = 0
    structured_content_without_scalar_event_count = 0

    for event in events:
        structured_segments = structured_content_segments(event.content)
        if structured_segments is None:
            segment_count = sum(1 for segment in content_segments(event.content) if segment.text.strip())
        else:
            structured_content_event_count += 1
            segment_count = sum(1 for segment in structured_segments if segment.text.strip())
            if segment_count == 0:
                structured_content_without_scalar_event_count += 1
        scannable_segment_count += segment_count
        if segment_count == 0:
            empty_content_event_count += 1

    events_with_destinations_count = sum(bool(event.destinations) for event in events)
    provider_destination_event_count = sum(
        any(destination.get("layer") == "model_provider" for destination in event.destinations)
        for event in events
    )
    summary = {
        "observed_event_count": len(events),
        "events_by_layer": events_by_layer,
        "empty_content_event_count": empty_content_event_count,
        "nonempty_content_event_count": len(events) - empty_content_event_count,
        "scannable_segment_count": scannable_segment_count,
        "structured_content_event_count": structured_content_event_count,
        "structured_content_without_scalar_event_count": structured_content_without_scalar_event_count,
        "events_with_source_count": sum(bool(event.source) for event in events),
        "events_with_destinations_count": events_with_destinations_count,
        "provider_destination_event_count": provider_destination_event_count,
    }

    mapping_summary = _safe_mapping_summary(mapping_diagnostics)
    diagnostics = _build_diagnostics(
        summary,
        expected_layers=expected,
        observed_layers=observed_layers,
        mapping_summary=mapping_summary,
    )
    coverage: dict[str, Any] = {
        "schema_version": COVERAGE_SCHEMA_VERSION,
        "summary": summary,
        "observed_layers": observed_layers,
        "expected_layers": expected,
        "diagnostics": diagnostics,
        "interpretation": dict(_INTERPRETATION),
    }
    if mapping_summary is not None:
        coverage["mapping"] = mapping_summary
    return AuditCoverageResult(coverage)


def render_coverage_markdown(coverage: Mapping[str, Any] | AuditCoverageResult) -> str:
    data = coverage.to_dict() if isinstance(coverage, AuditCoverageResult) else coverage
    summary = data["summary"]
    observed_layers = data["observed_layers"]
    expected_layers = data["expected_layers"]
    lines = [
        "# Audit Coverage Summary",
        "",
        "## Observed Trace Scope",
        "",
        f"- Events examined: {summary['observed_event_count']}",
        f"- Layers observed: {_format_layers(observed_layers)}",
        f"- Expected layers: {_format_layers(expected_layers)}",
        f"- Non-empty content events: {summary['nonempty_content_event_count']}",
        f"- Empty content events: {summary['empty_content_event_count']}",
        f"- Scannable segments: {summary['scannable_segment_count']}",
        f"- Structured content events: {summary['structured_content_event_count']}",
        f"- Structured events without scalar content: {summary['structured_content_without_scalar_event_count']}",
        f"- Events with source: {summary['events_with_source_count']}",
        f"- Events with destinations: {summary['events_with_destinations_count']}",
        f"- Events with provider destination: {summary['provider_destination_event_count']}",
        "",
        "### Events by Layer",
        "",
    ]
    if summary["events_by_layer"]:
        lines.extend(
            f"- `{layer}`: {count}"
            for layer, count in summary["events_by_layer"].items()
        )
    else:
        lines.append("No layers observed.")

    lines.extend(["", "## Potential Blind Spots", ""])
    if data["diagnostics"]:
        for diagnostic in data["diagnostics"]:
            detail = ""
            if "count" in diagnostic:
                detail = f" Count: {diagnostic['count']}."
            if "layers" in diagnostic:
                detail = f" Layers: {_format_layers(diagnostic['layers'])}."
            lines.append(f"- `{diagnostic['code']}`: {diagnostic['message']}{detail}")
    else:
        lines.append("No potential blind spots were identified from the configured expectations and observed input.")

    interpretation = data["interpretation"]
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            interpretation["observed_scope"],
            "",
            interpretation["zero_findings"],
            "",
            interpretation["compliance"],
            "",
        ]
    )
    return "\n".join(lines)


def write_coverage_json(coverage: Mapping[str, Any] | AuditCoverageResult, path: Path) -> None:
    data = coverage.to_dict() if isinstance(coverage, AuditCoverageResult) else coverage
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_coverage_markdown(coverage: Mapping[str, Any] | AuditCoverageResult, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_coverage_markdown(coverage), encoding="utf-8")


def _normalize_expected_layers(expected_layers: Iterable[str]) -> list[str]:
    values = [expected_layers] if isinstance(expected_layers, str) else list(expected_layers)
    invalid = sorted({value for value in values if value not in SUPPORTED_LAYERS})
    if invalid:
        raise ValueError(
            "unsupported expected layer(s): {invalid}; expected one of: {allowed}".format(
                invalid=", ".join(repr(value) for value in invalid),
                allowed=", ".join(sorted(SUPPORTED_LAYERS)),
            )
        )
    return sorted(set(values))


def _safe_mapping_summary(mapping_diagnostics: Mapping[str, Any] | None) -> dict[str, int] | None:
    if mapping_diagnostics is None:
        return None
    unused = mapping_diagnostics.get("optional_content_paths_never_used", [])
    if not isinstance(unused, list):
        raise ValueError("mapping diagnostics optional_content_paths_never_used must be an array")
    return {"optional_content_fields_unused_count": len(unused)}


def _build_diagnostics(
    summary: Mapping[str, Any],
    *,
    expected_layers: list[str],
    observed_layers: list[str],
    mapping_summary: Mapping[str, int] | None,
) -> list[dict[str, Any]]:
    diagnostics: list[dict[str, Any]] = []
    event_count = summary["observed_event_count"]
    if event_count == 0:
        diagnostics.append(_diagnostic("EMPTY_TRACE"))
    if summary["empty_content_event_count"]:
        diagnostics.append(
            _diagnostic("EMPTY_CONTENT_EVENTS", count=summary["empty_content_event_count"])
        )

    missing_layers = sorted(set(expected_layers) - set(observed_layers))
    if missing_layers:
        diagnostics.append(_diagnostic("EXPECTED_LAYER_NOT_OBSERVED", layers=missing_layers))

    if event_count and summary["events_with_destinations_count"] == 0:
        diagnostics.append(_diagnostic("NO_EXPLICIT_DESTINATIONS"))
    elif event_count and summary["provider_destination_event_count"] == 0:
        diagnostics.append(_diagnostic("NO_PROVIDER_DESTINATION_OBSERVED"))

    if mapping_summary and mapping_summary["optional_content_fields_unused_count"]:
        diagnostics.append(
            _diagnostic(
                "MAPPING_OPTIONAL_CONTENT_UNUSED",
                count=mapping_summary["optional_content_fields_unused_count"],
            )
        )
    if event_count and not expected_layers:
        diagnostics.append(_diagnostic("COVERAGE_UNVERIFIED"))
    return diagnostics


def _diagnostic(code: str, **details: Any) -> dict[str, Any]:
    return {"code": code, "severity": "warning", "message": _MESSAGES[code], **details}


def _count_values(values: Iterable[str]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for value in values:
        counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items()))


def _format_layers(layers: Iterable[str]) -> str:
    values = list(layers)
    if not values:
        return "none"
    return ", ".join(f"`{value}`" for value in values)
