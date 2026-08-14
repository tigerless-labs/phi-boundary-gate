from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Literal

from .actions import DISPOSITION_RANK, recommended_boundary_action, redaction_action
from .detectors import detect_candidates
from .policy import Policy
from .structured_content import content_segments, external_content_path
from .trace import TraceEvent

ReportValueMode = Literal["raw", "redacted", "hashed"]
REPORT_VALUE_MODES = {"raw", "redacted", "hashed"}


def build_report(
    events: list[TraceEvent],
    policy: Policy,
    trace_path: Path,
    policy_path: Path,
    *,
    enable_presidio: bool = False,
    report_value_mode: ReportValueMode = "raw",
) -> dict[str, Any]:
    _validate_report_value_mode(report_value_mode)
    findings: list[dict[str, Any]] = []

    for event in events:
        for segment in content_segments(event.content):
            for candidate in detect_candidates(segment.text, enable_presidio=enable_presidio):
                findings.append(
                    _finding_from_candidate(
                        event=event,
                        candidate=candidate,
                        content_path=segment.path,
                        finding_number=len(findings) + 1,
                        policy=policy,
                    )
                )

    boundary_exposures = _boundary_exposures(findings)
    return {
        "schema_version": 3,
        "report_value_mode": report_value_mode,
        "finding_schema": "path-aware",
        "trace_path": str(trace_path),
        "policy_path": str(policy_path),
        "summary": _summary(findings, boundary_exposures),
        "boundary_exposures": _display_boundary_exposures(boundary_exposures, report_value_mode),
        "findings": _display_findings(findings, report_value_mode),
    }


def _finding_from_candidate(
    *,
    event: TraceEvent,
    candidate: Any,
    content_path: str | None,
    finding_number: int,
    policy: Policy,
) -> dict[str, Any]:
    decision = policy.decide(candidate.category, event.layer)
    metadata_paths = event.metadata.get("external_content_paths")
    return {
        "finding_id": f"finding-{finding_number:03d}",
        "event_id": event.event_id,
        "layer": event.layer,
        "category": candidate.category,
        "value": candidate.value,
        "value_display": candidate.value,
        "value_hash": _value_hash(candidate.value),
        "span": {"start": candidate.start, "end": candidate.end},
        "content_path": content_path,
        "external_content_path": external_content_path(metadata_paths, content_path),
        "confidence": candidate.confidence,
        "reason": candidate.reason,
        "source": event.source,
        "destinations": event.destinations,
        "policy": {
            "disposition": decision.disposition,
            "risk": decision.risk,
            "rule": decision.rule,
        },
        "redaction": {
            "action": redaction_action(decision.disposition),
            "suggested_value": decision.redaction,
        },
    }


def write_json_report(report: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_markdown_report(report: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_markdown(report), encoding="utf-8")


def render_markdown(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        "# PHI Boundary Gate Report",
        "",
        f"- Trace: `{report['trace_path']}`",
        f"- Policy: `{report['policy_path']}`",
        f"- Report value mode: `{report.get('report_value_mode', 'raw')}`",
        f"- Total PHI candidates: {summary['total_findings']}",
        f"- Boundary exposures: {summary['total_boundary_exposures']}",
        f"- Violations: {summary['by_disposition'].get('violation', 0)}",
        f"- Redaction required: {summary['by_disposition'].get('redact', 0)}",
        f"- High-risk candidates: {summary['high_risk_findings']}",
        "",
        "All findings are PHI candidates from a rule-based detector and require human review.",
        "",
        "## Boundary Exposures",
        "",
    ]

    if not report["boundary_exposures"]:
        lines.extend(["No boundary exposures found.", "", "## Findings", "", "No PHI candidates found.", ""])
        return "\n".join(lines)

    lines.extend(
        [
            "| ID | Category | Value | Layers Seen | Worst Disposition | Worst Layer | Recommended Action |",
            "| --- | --- | --- | --- | --- | --- | --- |",
        ]
    )
    for exposure in report["boundary_exposures"]:
        lines.append(
            "| {exposure_id} | {category} | `{value}` | {layers_seen} | {worst_disposition} | {worst_layer} | {action} |".format(
                exposure_id=exposure["exposure_id"],
                category=exposure["category"],
                value=_escape_table(exposure.get("value_display", exposure["value"])),
                layers_seen=" -> ".join(exposure["layers_seen"]),
                worst_disposition=exposure["worst_disposition"],
                worst_layer=exposure["worst_layer"],
                action=exposure["recommended_boundary_action"],
            )
        )

    lines.extend(["", "## Findings", ""])

    lines.extend(
        [
            "| ID | Event | Layer | Category | Value | Content Path | Disposition | Risk | Redaction |",
            "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
        ]
    )
    for finding in report["findings"]:
        lines.append(
            "| {finding_id} | {event_id} | {layer} | {category} | `{value}` | `{content_path}` | {disposition} | {risk} | `{redaction}` |".format(
                finding_id=finding["finding_id"],
                event_id=finding["event_id"],
                layer=finding["layer"],
                category=finding["category"],
                value=_escape_table(finding.get("value_display", finding["value"])),
                content_path=_escape_table(finding.get("content_path") or ""),
                disposition=finding["policy"]["disposition"],
                risk=finding["policy"]["risk"],
                redaction=finding["redaction"]["suggested_value"],
            )
        )

    lines.extend(["", "## Paths", ""])
    for finding in report["findings"]:
        lines.extend(
            [
                f"### {finding['finding_id']}",
                "",
                f"- Detector: {finding['reason']} Confidence: {finding['confidence']:.2f}.",
                f"- Policy: {finding['policy']['rule']}",
                f"- Content path: `{finding.get('content_path') or ''}`",
                f"- External content path: `{finding.get('external_content_path') or ''}`",
                f"- Source: `{json.dumps(finding['source'], sort_keys=True)}`",
                f"- Destinations: `{json.dumps(finding['destinations'], sort_keys=True)}`",
                "",
            ]
        )

    return "\n".join(lines)


def _summary(findings: list[dict[str, Any]], boundary_exposures: list[dict[str, Any]]) -> dict[str, Any]:
    by_disposition: dict[str, int] = {}
    by_layer: dict[str, int] = {}
    by_category: dict[str, int] = {}
    by_worst_disposition: dict[str, int] = {}
    high_risk_findings = 0

    for finding in findings:
        disposition = finding["policy"]["disposition"]
        layer = finding["layer"]
        category = finding["category"]
        by_disposition[disposition] = by_disposition.get(disposition, 0) + 1
        by_layer[layer] = by_layer.get(layer, 0) + 1
        by_category[category] = by_category.get(category, 0) + 1
        if finding["policy"]["risk"] == "high":
            high_risk_findings += 1

    for exposure in boundary_exposures:
        worst_disposition = exposure["worst_disposition"]
        by_worst_disposition[worst_disposition] = by_worst_disposition.get(worst_disposition, 0) + 1

    return {
        "total_findings": len(findings),
        "total_boundary_exposures": len(boundary_exposures),
        "high_risk_findings": high_risk_findings,
        "by_disposition": by_disposition,
        "by_worst_disposition": by_worst_disposition,
        "by_layer": by_layer,
        "by_category": by_category,
    }


def _boundary_exposures(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str], dict[str, Any]] = {}

    for finding in findings:
        key = (finding["category"], finding["value"])
        exposure = grouped.setdefault(
            key,
            {
                "category": finding["category"],
                "value": finding["value"],
                "value_display": finding["value"],
                "value_hash": finding["value_hash"],
                "redaction": finding["redaction"]["suggested_value"],
                "finding_ids": [],
                "event_ids": [],
                "layers_seen": [],
                "first_seen_event_id": finding["event_id"],
                "worst_disposition": finding["policy"]["disposition"],
                "worst_layer": finding["layer"],
                "content_paths_seen": [],
                "external_content_paths_seen": [],
                "sources": [],
                "destinations": [],
            },
        )
        exposure["finding_ids"].append(finding["finding_id"])
        _append_unique_scalar(exposure["event_ids"], finding["event_id"])
        _append_unique_scalar(exposure["layers_seen"], finding["layer"])
        _append_optional_scalar(exposure["content_paths_seen"], finding.get("content_path"))
        _append_optional_scalar(exposure["external_content_paths_seen"], finding.get("external_content_path"))
        _append_unique_object(exposure["sources"], finding["source"])
        for destination in finding["destinations"]:
            _append_unique_object(exposure["destinations"], destination)

        disposition = finding["policy"]["disposition"]
        if DISPOSITION_RANK[disposition] > DISPOSITION_RANK[exposure["worst_disposition"]]:
            exposure["worst_disposition"] = disposition
            exposure["worst_layer"] = finding["layer"]

    sorted_exposures = sorted(
        grouped.values(),
        key=lambda item: (
            -DISPOSITION_RANK[item["worst_disposition"]],
            item["first_seen_event_id"],
            item["category"],
            item["value"],
        ),
    )
    for index, exposure in enumerate(sorted_exposures, start=1):
        exposure["exposure_id"] = f"exposure-{index:03d}"
        exposure["recommended_boundary_action"] = recommended_boundary_action(
            exposure["worst_disposition"], exposure["worst_layer"]
        )

    return sorted_exposures


def _display_findings(findings: list[dict[str, Any]], report_value_mode: str) -> list[dict[str, Any]]:
    return [_display_finding(finding, report_value_mode) for finding in findings]


def _display_finding(finding: dict[str, Any], report_value_mode: str) -> dict[str, Any]:
    displayed = dict(finding)
    value_display = _display_value(
        finding["value"],
        finding["redaction"]["suggested_value"],
        finding["value_hash"],
        report_value_mode,
    )
    displayed["value"] = value_display
    displayed["value_display"] = value_display
    return displayed


def _display_boundary_exposures(exposures: list[dict[str, Any]], report_value_mode: str) -> list[dict[str, Any]]:
    return [_display_boundary_exposure(exposure, report_value_mode) for exposure in exposures]


def _display_boundary_exposure(exposure: dict[str, Any], report_value_mode: str) -> dict[str, Any]:
    displayed = dict(exposure)
    value_display = _display_value(
        exposure["value"],
        exposure["redaction"],
        exposure["value_hash"],
        report_value_mode,
    )
    displayed["value"] = value_display
    displayed["value_display"] = value_display
    displayed.pop("redaction", None)
    return displayed


def _display_value(value: str, redaction: str, value_hash: str, report_value_mode: str) -> str:
    if report_value_mode == "raw":
        return value
    if report_value_mode == "redacted":
        return redaction
    if report_value_mode == "hashed":
        return value_hash
    raise ValueError(f"unsupported report value mode {report_value_mode!r}; expected one of: {', '.join(sorted(REPORT_VALUE_MODES))}")


def _value_hash(value: str) -> str:
    return f"sha256:{hashlib.sha256(value.encode('utf-8')).hexdigest()}"


def _validate_report_value_mode(report_value_mode: str) -> None:
    if report_value_mode not in REPORT_VALUE_MODES:
        allowed = ", ".join(sorted(REPORT_VALUE_MODES))
        raise ValueError(f"unsupported report value mode {report_value_mode!r}; expected one of: {allowed}")


def _append_unique_scalar(items: list[str], value: str) -> None:
    if value not in items:
        items.append(value)


def _append_optional_scalar(items: list[str], value: str | None) -> None:
    if value is not None:
        _append_unique_scalar(items, value)


def _append_unique_object(items: list[dict[str, Any]], value: dict[str, Any]) -> None:
    encoded = json.dumps(value, sort_keys=True)
    if all(json.dumps(item, sort_keys=True) != encoded for item in items):
        items.append(value)


def _escape_table(value: str) -> str:
    return value.replace("|", "\\|")
