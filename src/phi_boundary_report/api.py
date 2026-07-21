from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .actions import redaction_action, recommended_boundary_action, worst_disposition
from .detectors import detect_candidates
from .policy import Policy
from .trace import SUPPORTED_LAYERS, supported_layers_text


@dataclass(frozen=True)
class GuardDecision:
    text: str
    layer: str
    findings: list[dict[str, Any]]
    redacted_text: str
    has_phi: bool
    has_redactions: bool
    has_violations: bool
    worst_disposition: str
    recommended_action: str


def scan_text(text: str, layer: str, policy: Policy) -> list[dict[str, Any]]:
    if layer not in SUPPORTED_LAYERS:
        raise ValueError(f"unsupported layer {layer!r}; expected one of: {supported_layers_text()}")

    findings: list[dict[str, Any]] = []
    for candidate in detect_candidates(text):
        decision = policy.decide(candidate.category, layer)
        findings.append(
            {
                "layer": layer,
                "category": candidate.category,
                "value": candidate.value,
                "span": {"start": candidate.start, "end": candidate.end},
                "confidence": candidate.confidence,
                "reason": candidate.reason,
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
        )
    return findings


def redact_text(text: str, findings: list[dict[str, Any]]) -> str:
    replacements = _non_overlapping_replacements(findings)
    redacted = text
    for start, end, replacement in reversed(replacements):
        redacted = f"{redacted[:start]}{replacement}{redacted[end:]}"
    return redacted


def guard_text(text: str, layer: str, policy: Policy) -> GuardDecision:
    findings = scan_text(text, layer, policy)
    redacted_text = redact_text(text, findings)
    dispositions = [finding["policy"]["disposition"] for finding in findings]
    worst = worst_disposition(dispositions)
    worst_layer = layer if findings else ""
    has_redactions = redacted_text != text

    return GuardDecision(
        text=text,
        layer=layer,
        findings=findings,
        redacted_text=redacted_text,
        has_phi=bool(findings),
        has_redactions=has_redactions,
        has_violations=any(disposition == "violation" for disposition in dispositions),
        worst_disposition=worst,
        recommended_action=recommended_boundary_action(worst, worst_layer) if findings else "No PHI candidates found.",
    )


def _non_overlapping_replacements(findings: list[dict[str, Any]]) -> list[tuple[int, int, str]]:
    ordered = sorted(
        findings,
        key=lambda finding: (
            finding["span"]["start"],
            -(finding["span"]["end"] - finding["span"]["start"]),
        ),
    )
    replacements: list[tuple[int, int, str]] = []
    occupied_until = -1
    for finding in ordered:
        start = finding["span"]["start"]
        end = finding["span"]["end"]
        if start < occupied_until:
            continue
        replacements.append((start, end, finding["redaction"]["suggested_value"]))
        occupied_until = end
    return replacements
