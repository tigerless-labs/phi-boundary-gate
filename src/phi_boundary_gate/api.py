from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal, Mapping, Sequence

from .actions import redaction_action, recommended_boundary_action, worst_disposition
from .detectors import detect_candidates
from .policy import Policy
from .trace import SUPPORTED_LAYERS, supported_layers_text

GuardMode = Literal["report_only", "redact", "block_on_violation"]


@dataclass(frozen=True)
class ScanFinding:
    layer: str
    category: str
    value: str
    start: int
    end: int
    confidence: float
    reason: str
    disposition: str
    risk: str
    rule: str
    redaction_action: str
    redaction: str

    @property
    def span(self) -> dict[str, int]:
        return {"start": self.start, "end": self.end}

    def to_dict(self) -> dict[str, Any]:
        return {
            "layer": self.layer,
            "category": self.category,
            "value": self.value,
            "span": self.span,
            "confidence": self.confidence,
            "reason": self.reason,
            "policy": {
                "disposition": self.disposition,
                "risk": self.risk,
                "rule": self.rule,
            },
            "redaction": {
                "action": self.redaction_action,
                "suggested_value": self.redaction,
            },
        }

    def __getitem__(self, key: str) -> Any:
        return self.to_dict()[key]


@dataclass(frozen=True)
class GuardDecision:
    text: str
    layer: str
    mode: GuardMode
    findings: list[ScanFinding]
    redacted_text: str
    has_phi: bool
    has_redactions: bool
    has_violations: bool
    worst_disposition: str
    recommended_action: str
    should_block: bool
    should_redact: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "text": self.text,
            "layer": self.layer,
            "mode": self.mode,
            "findings": [finding.to_dict() for finding in self.findings],
            "redacted_text": self.redacted_text,
            "has_phi": self.has_phi,
            "has_redactions": self.has_redactions,
            "has_violations": self.has_violations,
            "worst_disposition": self.worst_disposition,
            "recommended_action": self.recommended_action,
            "should_block": self.should_block,
            "should_redact": self.should_redact,
        }


def scan_text(text: str, layer: str, policy: Policy, *, enable_presidio: bool = False) -> list[ScanFinding]:
    if layer not in SUPPORTED_LAYERS:
        raise ValueError(f"unsupported layer {layer!r}; expected one of: {supported_layers_text()}")

    findings: list[ScanFinding] = []
    for candidate in detect_candidates(text, enable_presidio=enable_presidio):
        decision = policy.decide(candidate.category, layer)
        findings.append(
            ScanFinding(
                layer=layer,
                category=candidate.category,
                value=candidate.value,
                start=candidate.start,
                end=candidate.end,
                confidence=candidate.confidence,
                reason=candidate.reason,
                disposition=decision.disposition,
                risk=decision.risk,
                rule=decision.rule,
                redaction_action=redaction_action(decision.disposition),
                redaction=decision.redaction,
            )
        )
    return findings


def redact_text(text: str, findings: Sequence[ScanFinding | Mapping[str, Any]]) -> str:
    replacements = _non_overlapping_replacements(findings)
    redacted = text
    for start, end, replacement in reversed(replacements):
        redacted = f"{redacted[:start]}{replacement}{redacted[end:]}"
    return redacted


def guard_text(
    text: str,
    layer: str,
    policy: Policy,
    mode: GuardMode = "report_only",
    *,
    enable_presidio: bool = False,
) -> GuardDecision:
    if mode not in ("report_only", "redact", "block_on_violation"):
        raise ValueError("mode must be one of: report_only, redact, block_on_violation")

    findings = scan_text(text, layer, policy, enable_presidio=enable_presidio)
    redacted_text = redact_text(text, findings)
    dispositions = [finding.disposition for finding in findings]
    worst = worst_disposition(dispositions)
    worst_layer = layer if findings else ""
    has_redactions = redacted_text != text
    has_violations = any(disposition == "violation" for disposition in dispositions)
    should_block = mode == "block_on_violation" and has_violations
    should_redact = mode == "redact" and has_redactions

    return GuardDecision(
        text=text,
        layer=layer,
        mode=mode,
        findings=findings,
        redacted_text=redacted_text,
        has_phi=bool(findings),
        has_redactions=has_redactions,
        has_violations=has_violations,
        worst_disposition=worst,
        recommended_action=recommended_boundary_action(worst, worst_layer) if findings else "No PHI candidates found.",
        should_block=should_block,
        should_redact=should_redact,
    )


def _non_overlapping_replacements(findings: Sequence[ScanFinding | Mapping[str, Any]]) -> list[tuple[int, int, str]]:
    ordered = sorted(
        findings,
        key=lambda finding: (
            _finding_start(finding),
            -(_finding_end(finding) - _finding_start(finding)),
        ),
    )
    replacements: list[tuple[int, int, str]] = []
    occupied_until = -1
    for finding in ordered:
        start = _finding_start(finding)
        end = _finding_end(finding)
        if start < occupied_until:
            continue
        replacements.append((start, end, _finding_redaction(finding)))
        occupied_until = end
    return replacements


def _finding_start(finding: ScanFinding | Mapping[str, Any]) -> int:
    if isinstance(finding, ScanFinding):
        return finding.start
    return int(finding["span"]["start"])


def _finding_end(finding: ScanFinding | Mapping[str, Any]) -> int:
    if isinstance(finding, ScanFinding):
        return finding.end
    return int(finding["span"]["end"])


def _finding_redaction(finding: ScanFinding | Mapping[str, Any]) -> str:
    if isinstance(finding, ScanFinding):
        return finding.redaction
    return str(finding["redaction"]["suggested_value"])
