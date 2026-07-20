from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .detectors import detect_candidates
from .policy import Policy
from .trace import TraceEvent


def build_report(events: list[TraceEvent], policy: Policy, trace_path: Path, policy_path: Path) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []

    for event in events:
        for candidate in detect_candidates(event.content):
            decision = policy.decide(candidate.category, event.layer)
            finding_number = len(findings) + 1
            findings.append(
                {
                    "finding_id": f"finding-{finding_number:03d}",
                    "event_id": event.event_id,
                    "layer": event.layer,
                    "category": candidate.category,
                    "value": candidate.value,
                    "span": {"start": candidate.start, "end": candidate.end},
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
                        "action": _redaction_action(decision.disposition),
                        "suggested_value": decision.redaction,
                    },
                }
            )

    return {
        "schema_version": 1,
        "trace_path": str(trace_path),
        "policy_path": str(policy_path),
        "summary": _summary(findings),
        "findings": findings,
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
        "# PHI Context Boundary Report",
        "",
        f"- Trace: `{report['trace_path']}`",
        f"- Policy: `{report['policy_path']}`",
        f"- Total PHI candidates: {summary['total_findings']}",
        f"- Violations: {summary['by_disposition'].get('violation', 0)}",
        f"- Redaction required: {summary['by_disposition'].get('redact', 0)}",
        f"- High-risk candidates: {summary['high_risk_findings']}",
        "",
        "All findings are PHI candidates from a rule-based detector and require human review.",
        "",
        "## Findings",
        "",
    ]

    if not report["findings"]:
        lines.extend(["No PHI candidates found.", ""])
        return "\n".join(lines)

    lines.extend(
        [
            "| ID | Event | Layer | Category | Value | Disposition | Risk | Redaction |",
            "| --- | --- | --- | --- | --- | --- | --- | --- |",
        ]
    )
    for finding in report["findings"]:
        lines.append(
            "| {finding_id} | {event_id} | {layer} | {category} | `{value}` | {disposition} | {risk} | `{redaction}` |".format(
                finding_id=finding["finding_id"],
                event_id=finding["event_id"],
                layer=finding["layer"],
                category=finding["category"],
                value=_escape_table(finding["value"]),
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
                f"- Source: `{json.dumps(finding['source'], sort_keys=True)}`",
                f"- Destinations: `{json.dumps(finding['destinations'], sort_keys=True)}`",
                "",
            ]
        )

    return "\n".join(lines)


def _summary(findings: list[dict[str, Any]]) -> dict[str, Any]:
    by_disposition: dict[str, int] = {}
    by_layer: dict[str, int] = {}
    by_category: dict[str, int] = {}
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

    return {
        "total_findings": len(findings),
        "high_risk_findings": high_risk_findings,
        "by_disposition": by_disposition,
        "by_layer": by_layer,
        "by_category": by_category,
    }


def _redaction_action(disposition: str) -> str:
    if disposition == "violation":
        return "remove_or_redact_before_this_layer"
    if disposition == "redact":
        return "redact_before_this_layer"
    return "review"


def _escape_table(value: str) -> str:
    return value.replace("|", "\\|")
