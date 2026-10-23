from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .actions import DISPOSITION_RANK
from .detectors import RULES
from .report import REPORT_VALUE_MODES
from .trace import SUPPORTED_DESTINATION_LAYERS, SUPPORTED_LAYERS


AUDIT_REPORT_SCHEMA_VERSION = 3
DIFF_SCHEMA_VERSION = 1
EXPOSURE_KEY_VERSION = 1
KNOWN_CATEGORIES = frozenset(rule.category for rule in RULES)
KNOWN_DISPOSITIONS = frozenset(DISPOSITION_RANK)
MAX_REVIEW_GUIDANCE_ITEMS = 6

_GUIDANCE_MESSAGES = {
    "REVIEW_NEWLY_OBSERVED_ROUTES": (
        "Review newly observed route boundaries and confirm the observation scope."
    ),
    "REVIEW_WORSENED_DISPOSITIONS": (
        "Inspect worsened dispositions together with the effective policy and route context."
    ),
    "VALIDATE_POLICY_COMPARABILITY": (
        "Compare effective policy configuration before attributing disposition changes."
    ),
    "VALIDATE_DETECTOR_COMPARABILITY": (
        "Compare detector settings before attributing changes in observed routes."
    ),
    "VALIDATE_SEMANTIC_COMPARABILITY": (
        "Validate Semantic Resolver provenance and coverage before comparing semantic evidence."
    ),
    "VERIFY_NO_LONGER_OBSERVED": (
        "Verify no-longer-observed routes independently; absence here does not prove elimination."
    ),
    "REVIEW_IMPROVED_DISPOSITIONS": (
        "Review improved dispositions without treating them as proof of reduced real-world risk."
    ),
    "REVIEW_MIXED_DISPOSITIONS": (
        "Inspect mixed disposition-set changes; the highest recorded level did not establish a direction."
    ),
    "REVIEW_FREQUENCY_CONTEXT": (
        "Check collection scope for frequency changes; frequency alone does not establish worsening."
    ),
    "NO_PRIORITIZED_CHANGES": "No prioritized regression changes were observed in this comparison.",
}

_POLICY_LIMITATION_CODES = frozenset(
    {
        "AUDIT_PROVENANCE_INCOMPLETE",
        "POLICY_FINGERPRINT_MISMATCH",
        "POLICY_FINGERPRINT_MISSING",
    }
)
_DETECTOR_LIMITATION_CODES = frozenset(
    {
        "AUDIT_PROVENANCE_INCOMPLETE",
        "DETECTOR_FINGERPRINT_MISMATCH",
        "DETECTOR_FINGERPRINT_MISSING",
        "PRESIDIO_ENABLEMENT_MISMATCH",
        "PRESIDIO_CONFIGURATION_UNKNOWN",
    }
)
_SEMANTIC_LIMITATION_CODES = frozenset(
    {
        "AUDIT_PROVENANCE_INCOMPLETE",
        "SEMANTIC_CONFIGURATION_MISMATCH",
        "SEMANTIC_CONFIGURATION_UNKNOWN",
        "SEMANTIC_CONFIGURATION_MISSING",
        "SEMANTIC_COVERAGE_MISMATCH",
    }
)


@dataclass(frozen=True)
class ExposureDiffResult:
    """Advisory comparison of two validated JSON audit reports."""

    report: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return self.report

    def to_markdown(self) -> str:
        return render_exposure_diff_markdown(self.report)

    def to_review_summary(self) -> str:
        return render_exposure_review_summary(self.report)

    def review_guidance(self) -> list[dict[str, str]]:
        return build_review_guidance(self.report)

    def write_json(self, path: Path | str) -> None:
        write_exposure_diff_json(self.report, Path(path))

    def write_markdown(self, path: Path | str) -> None:
        write_exposure_diff_markdown(self.report, Path(path))

    def write_review_summary(self, path: Path | str) -> None:
        write_exposure_review_summary(self.report, Path(path))


def load_audit_report(path: Path | str, *, label: str = "report") -> dict[str, Any]:
    """Read one JSON audit report and validate the fields used by comparison."""

    source = Path(path)
    try:
        raw = json.loads(source.read_text(encoding="utf-8"))
    except OSError as exc:
        detail = exc.strerror or type(exc).__name__
        raise ValueError(f"{label} report could not be read: {detail}") from None
    except UnicodeError as exc:
        raise ValueError(f"{label} report is not valid UTF-8") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"{label} report is invalid JSON: {exc.msg}") from exc
    _validate_report(raw, label)
    return raw


def compare_report_files(before_path: Path | str, after_path: Path | str) -> ExposureDiffResult:
    before = load_audit_report(before_path, label="before")
    after = load_audit_report(after_path, label="after")
    return compare_audit_reports(before, after)


def compare_audit_reports(before: dict[str, Any], after: dict[str, Any]) -> ExposureDiffResult:
    """Compare exact, schema-defined exposure routes without copying sensitive payloads."""

    _validate_report(before, "before")
    _validate_report(after, "after")
    before_groups = _exposure_groups(before["findings"])
    after_groups = _exposure_groups(after["findings"])
    before_keys = set(before_groups)
    after_keys = set(after_groups)
    shared_keys = before_keys & after_keys

    new_exposures = [after_groups[key] for key in sorted(after_keys - before_keys)]
    no_longer_observed = [before_groups[key] for key in sorted(before_keys - after_keys)]
    changed_dispositions: list[dict[str, Any]] = []
    changed_frequencies: list[dict[str, Any]] = []
    unchanged: list[dict[str, Any]] = []

    for key in sorted(shared_keys):
        before_group = before_groups[key]
        after_group = after_groups[key]
        disposition_changed = before_group["dispositions"] != after_group["dispositions"]
        frequency_changed = before_group["frequency"] != after_group["frequency"]
        if disposition_changed:
            direction = _disposition_direction(before_group, after_group)
            changed_dispositions.append(
                {
                    "exposure": _descriptor(before_group),
                    "direction": direction,
                    "before": {
                        "dispositions": before_group["dispositions"],
                        "worst_disposition": before_group["worst_disposition"],
                    },
                    "after": {
                        "dispositions": after_group["dispositions"],
                        "worst_disposition": after_group["worst_disposition"],
                    },
                }
            )
        if frequency_changed:
            changed_frequencies.append(
                {
                    "exposure": _descriptor(before_group),
                    "before": before_group["frequency"],
                    "after": after_group["frequency"],
                }
            )
        if not disposition_changed and not frequency_changed:
            unchanged.append(after_group)

    comparability = _comparability(before, after)
    disposition_directions = {
        direction: sum(change["direction"] == direction for change in changed_dispositions)
        for direction in ("worsened", "improved", "mixed_or_other")
    }
    result = {
        "schema_version": DIFF_SCHEMA_VERSION,
        "analysis_type": "advisory_exposure_diff",
        "exposure_key_version": EXPOSURE_KEY_VERSION,
        "before": _report_identity(before),
        "after": _report_identity(after),
        "comparability": comparability,
        "summary": {
            "before_exposure_groups": len(before_groups),
            "after_exposure_groups": len(after_groups),
            "before_group_occurrences": _sum_frequency(before_groups, "occurrences"),
            "after_group_occurrences": _sum_frequency(after_groups, "occurrences"),
            "new_exposures": len(new_exposures),
            "no_longer_observed": len(no_longer_observed),
            "changed_dispositions": len(changed_dispositions),
            "disposition_directions": disposition_directions,
            "changed_frequencies": len(changed_frequencies),
            "unchanged": len(unchanged),
        },
        "new_exposures": new_exposures,
        "no_longer_observed": no_longer_observed,
        "changed_dispositions": changed_dispositions,
        "changed_frequencies": changed_frequencies,
        "unchanged": unchanged,
    }
    return ExposureDiffResult(result)


def write_exposure_diff_json(report: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_exposure_diff_markdown(report: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_exposure_diff_markdown(report), encoding="utf-8")


def write_exposure_review_summary(report: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_exposure_review_summary(report), encoding="utf-8")


def build_review_guidance(
    report: dict[str, Any],
    *,
    max_items: int = MAX_REVIEW_GUIDANCE_ITEMS,
) -> list[dict[str, str]]:
    """Return prioritized, bounded guidance containing only fixed safe text."""

    if max_items < 1:
        raise ValueError("max_items must be at least 1")
    candidates = _review_guidance_candidates(report)
    return candidates[:max_items]


def render_exposure_review_summary(report: dict[str, Any]) -> str:
    """Render a bounded, PHI-safe review summary without route-level input data."""

    summary = report["summary"]
    comparability = report["comparability"]
    directions = summary["disposition_directions"]
    guidance_candidates = _review_guidance_candidates(report)
    guidance = guidance_candidates[:MAX_REVIEW_GUIDANCE_ITEMS]
    omitted_guidance = len(guidance_candidates) - len(guidance)
    comparability_label = (
        "Limited by configuration evidence"
        if comparability["status"] == "limited"
        else "Comparable with documented limitations"
    )
    evidence_label = (
        "Configuration evidence is incomplete or differs between reports."
        if comparability["status"] == "limited"
        else "Recorded policy and detector evidence is comparable; semantic evidence remains excluded from route keys."
    )
    lines = [
        "# PHI Exposure Regression Review",
        "",
        "**Status: Advisory / Non-blocking**",
        "",
        "## Comparability",
        "",
        f"- Configuration comparison: {comparability_label}.",
        f"- Limitations: {evidence_label}",
        "",
        "## Observed Changes",
        "",
        f"- Newly observed routes: {summary['new_exposures']}",
        f"- No longer observed routes: {summary['no_longer_observed']}",
        f"- Worsened dispositions: {directions['worsened']}",
        f"- Improved dispositions: {directions['improved']}",
        f"- Mixed or other disposition changes: {directions['mixed_or_other']}",
        f"- Frequency changes: {summary['changed_frequencies']}",
        "",
        "## Suggested Review",
        "",
    ]
    lines.extend(f"- `{item['code']}` — {item['message']}" for item in guidance)
    if omitted_guidance:
        lines.append(f"- Additional guidance categories omitted: {omitted_guidance}")
    lines.extend(
        [
            "",
            "## Limitations",
            "",
            "Observed differences identify PHI candidate evidence in two reports. They do not independently prove "
            "PHI leakage, causal attribution, risk elimination, or HIPAA noncompliance.",
            "",
            "This summary cannot override Guard, policy, compliance, or CI decisions.",
            "",
        ]
    )
    return "\n".join(lines)


def render_exposure_diff_markdown(report: dict[str, Any]) -> str:
    summary = report["summary"]
    comparability = report["comparability"]
    lines = [
        "# PHI Exposure Diff",
        "",
        "This is advisory exposure-change analysis, not a hard gate or a compliance determination.",
        "",
        f"- Before report: `{report['before']['report_ref']}`",
        f"- After report: `{report['after']['report_ref']}`",
        f"- Audit report schema: `{report['before']['audit_schema_version']}`",
        f"- Exposure key version: `{report['exposure_key_version']}`",
        "",
        "## Comparability Status",
        "",
        f"**{comparability['status']}**",
        "",
        f"- Structural comparability: `{comparability['structural']['status']}`",
        f"- Disposition comparability: `{comparability['disposition']['status']}`",
        f"- Reason codes: `{', '.join(comparability['reason_codes'])}`",
        "",
    ]
    lines.extend(f"- {warning}" for warning in comparability["warnings"])
    lines.extend(
        [
            "",
            "## Exposure Summary",
            "",
            "| Measure | Before | After |",
            "| --- | ---: | ---: |",
            "| Exposure groups | {before} | {after} |".format(
                before=summary["before_exposure_groups"],
                after=summary["after_exposure_groups"],
            ),
            "| Group occurrences | {before} | {after} |".format(
                before=summary["before_group_occurrences"],
                after=summary["after_group_occurrences"],
            ),
            "",
            f"- New Exposure: {summary['new_exposures']}",
            f"- No Longer Observed: {summary['no_longer_observed']}",
            f"- Changed Disposition: {summary['changed_dispositions']}",
            f"  - Worsened: {summary['disposition_directions']['worsened']}",
            f"  - Improved: {summary['disposition_directions']['improved']}",
            f"  - Mixed or Other: {summary['disposition_directions']['mixed_or_other']}",
            f"- Changed Frequency: {summary['changed_frequencies']}",
            f"- Unchanged: {summary['unchanged']}",
            "",
        ]
    )
    _append_group_section(lines, "New Exposures", report["new_exposures"])
    _append_group_section(lines, "No Longer Observed", report["no_longer_observed"])
    _append_disposition_section(lines, report["changed_dispositions"])
    _append_frequency_section(lines, report["changed_frequencies"])
    _append_group_section(lines, "Unchanged", report["unchanged"])
    lines.extend(
        [
            "## Count Definitions",
            "",
            "- An exposure group is one exact canonical route: category, source layer/type/path, "
            "destination layer/path, content path, and external content path.",
            "- A finding with multiple destinations contributes one observation to each destination route.",
            "- Occurrences count finding-to-destination observations. Events count distinct report-local "
            "event IDs within a group; event IDs are never part of the comparison key or output.",
            "- JSON array indexes are matched exactly. Reordering an array can therefore appear as a route change.",
            "",
        ]
    )
    return "\n".join(lines)


def _review_guidance_candidates(report: dict[str, Any]) -> list[dict[str, str]]:
    summary = report["summary"]
    directions = summary["disposition_directions"]
    reason_codes = frozenset(report["comparability"]["reason_codes"])
    codes: list[str] = []

    if directions["worsened"]:
        codes.append("REVIEW_WORSENED_DISPOSITIONS")
    if summary["new_exposures"]:
        codes.append("REVIEW_NEWLY_OBSERVED_ROUTES")
    if reason_codes & _POLICY_LIMITATION_CODES:
        codes.append("VALIDATE_POLICY_COMPARABILITY")
    if reason_codes & _DETECTOR_LIMITATION_CODES:
        codes.append("VALIDATE_DETECTOR_COMPARABILITY")
    if reason_codes & _SEMANTIC_LIMITATION_CODES:
        codes.append("VALIDATE_SEMANTIC_COMPARABILITY")
    if summary["no_longer_observed"]:
        codes.append("VERIFY_NO_LONGER_OBSERVED")
    if directions["improved"]:
        codes.append("REVIEW_IMPROVED_DISPOSITIONS")
    if directions["mixed_or_other"]:
        codes.append("REVIEW_MIXED_DISPOSITIONS")
    if summary["changed_frequencies"]:
        codes.append("REVIEW_FREQUENCY_CONTEXT")
    if not codes:
        codes.append("NO_PRIORITIZED_CHANGES")

    return [{"code": code, "message": _GUIDANCE_MESSAGES[code]} for code in codes]


def _validate_report(report: Any, label: str) -> None:
    if not isinstance(report, dict):
        raise ValueError(f"{label} report must be a JSON object")
    if report.get("schema_version") != AUDIT_REPORT_SCHEMA_VERSION:
        raise ValueError(f"{label} report schema_version must be {AUDIT_REPORT_SCHEMA_VERSION}")
    if report.get("finding_schema") != "path-aware":
        raise ValueError(f"{label} report finding_schema must be 'path-aware'")
    if report.get("report_value_mode") not in REPORT_VALUE_MODES:
        raise ValueError(f"{label} report has an unsupported report_value_mode")
    for field in ("trace_path", "policy_path"):
        if not isinstance(report.get(field), str):
            raise ValueError(f"{label} report field {field!r} must be a string")
    if not isinstance(report.get("summary"), dict):
        raise ValueError(f"{label} report field 'summary' must be an object")
    if not isinstance(report.get("boundary_exposures"), list):
        raise ValueError(f"{label} report field 'boundary_exposures' must be an array")
    findings = report.get("findings")
    if not isinstance(findings, list):
        raise ValueError(f"{label} report field 'findings' must be an array")
    for index, finding in enumerate(findings):
        _validate_finding(finding, label, index)
    if "audit_context" in report:
        _validate_audit_context(report["audit_context"], label)


def _validate_audit_context(context: Any, label: str) -> None:
    prefix = f"{label} report audit_context"
    if not isinstance(context, dict):
        raise ValueError(f"{prefix} must be an object")
    if context.get("fingerprint_version") != 1:
        raise ValueError(f"{prefix}.fingerprint_version must be 1")
    for field in ("policy_fingerprint", "detector_fingerprint"):
        value = context.get(field)
        if not isinstance(value, str) or not _is_sha256_ref(value):
            raise ValueError(f"{prefix}.{field} must be a sha256 reference")
    for field in ("presidio_enabled", "semantic_enabled"):
        if not isinstance(context.get(field), bool):
            raise ValueError(f"{prefix}.{field} must be a boolean")
    resolver_fingerprint = context.get("semantic_resolver_fingerprint")
    if resolver_fingerprint is not None and (
        not isinstance(resolver_fingerprint, str) or not _is_sha256_ref(resolver_fingerprint)
    ):
        raise ValueError(f"{prefix}.semantic_resolver_fingerprint must be a sha256 reference or null")
    if context.get("presidio_configuration") not in {"unknown", "not_applicable"}:
        raise ValueError(f"{prefix}.presidio_configuration is not supported")
    if context.get("semantic_configuration") not in {"identified", "unknown", "not_applicable"}:
        raise ValueError(f"{prefix}.semantic_configuration is not supported")


def _validate_finding(finding: Any, label: str, index: int) -> None:
    prefix = f"{label} report findings[{index}]"
    if not isinstance(finding, dict):
        raise ValueError(f"{prefix} must be an object")
    category = finding.get("category")
    if category not in KNOWN_CATEGORIES:
        raise ValueError(f"{prefix}.category is not a supported detector category")
    layer = finding.get("layer")
    if layer not in SUPPORTED_LAYERS:
        raise ValueError(f"{prefix}.layer is not supported")
    if not isinstance(finding.get("event_id"), str):
        raise ValueError(f"{prefix}.event_id must be a string")
    value_hash = finding.get("value_hash")
    if not isinstance(value_hash, str) or not _is_sha256_ref(value_hash):
        raise ValueError(f"{prefix}.value_hash must be a sha256 reference")
    for field in ("content_path", "external_content_path"):
        if field not in finding or finding[field] is not None and not isinstance(finding[field], str):
            raise ValueError(f"{prefix}.{field} must be a string or null")
    source = finding.get("source")
    if not isinstance(source, dict):
        raise ValueError(f"{prefix}.source must be an object")
    _validate_optional_string(source, "type", f"{prefix}.source")
    _validate_optional_string(source, "path", f"{prefix}.source")
    destinations = finding.get("destinations")
    if not isinstance(destinations, list):
        raise ValueError(f"{prefix}.destinations must be an array")
    for destination_index, destination in enumerate(destinations):
        destination_prefix = f"{prefix}.destinations[{destination_index}]"
        if not isinstance(destination, dict):
            raise ValueError(f"{destination_prefix} must be an object")
        _validate_optional_string(destination, "path", destination_prefix)
        _validate_optional_string(destination, "layer", destination_prefix)
        if destination.get("layer") is not None and destination["layer"] not in SUPPORTED_DESTINATION_LAYERS:
            raise ValueError(f"{destination_prefix}.layer is not supported")
    policy = finding.get("policy")
    if not isinstance(policy, dict):
        raise ValueError(f"{prefix}.policy must be an object")
    if policy.get("disposition") not in KNOWN_DISPOSITIONS:
        raise ValueError(f"{prefix}.policy.disposition is not supported")
    if "semantic" in finding and not isinstance(finding["semantic"], dict):
        raise ValueError(f"{prefix}.semantic must be an object when present")


def _validate_optional_string(container: dict[str, Any], field: str, prefix: str) -> None:
    if field in container and not isinstance(container[field], str):
        raise ValueError(f"{prefix}.{field} must be a string")


def _exposure_groups(findings: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    accumulators: dict[str, dict[str, Any]] = {}
    for finding in findings:
        destination_descriptors = _destination_descriptors(finding["destinations"])
        for destination in destination_descriptors:
            descriptor = _finding_descriptor(finding, destination)
            key = _json_ref(descriptor)
            accumulator = accumulators.setdefault(
                key,
                {
                    **descriptor,
                    "exposure_key": key,
                    "_events": set(),
                    "_occurrences": 0,
                    "_dispositions": set(),
                },
            )
            accumulator["_events"].add(finding["event_id"])
            accumulator["_occurrences"] += 1
            accumulator["_dispositions"].add(finding["policy"]["disposition"])

    groups: dict[str, dict[str, Any]] = {}
    for key, accumulator in accumulators.items():
        dispositions = sorted(
            accumulator.pop("_dispositions"),
            key=lambda value: (DISPOSITION_RANK[value], value),
        )
        events = accumulator.pop("_events")
        occurrences = accumulator.pop("_occurrences")
        groups[key] = {
            **accumulator,
            "dispositions": dispositions,
            "worst_disposition": max(dispositions, key=lambda value: DISPOSITION_RANK[value]),
            "frequency": {"events": len(events), "occurrences": occurrences},
        }
    return groups


def _destination_descriptors(destinations: list[dict[str, Any]]) -> list[dict[str, Any] | None]:
    if not destinations:
        return [None]
    unique: dict[str, dict[str, Any]] = {}
    for destination in destinations:
        descriptor = {
            "layer": destination.get("layer"),
            "path_ref": _field_ref(destination.get("path")),
        }
        unique[_canonical_json(descriptor)] = descriptor
    return [unique[key] for key in sorted(unique)]


def _finding_descriptor(finding: dict[str, Any], destination: dict[str, Any] | None) -> dict[str, Any]:
    source = finding["source"]
    return {
        "category": finding["category"],
        "source": {
            "layer": finding["layer"],
            "type_ref": _field_ref(source.get("type")),
            "path_ref": _field_ref(source.get("path")),
        },
        "destination": destination,
        "content_path_ref": _field_ref(finding.get("content_path")),
        "external_content_path_ref": _field_ref(finding.get("external_content_path")),
    }


def _descriptor(group: dict[str, Any]) -> dict[str, Any]:
    return {
        "exposure_key": group["exposure_key"],
        "category": group["category"],
        "source": group["source"],
        "destination": group["destination"],
        "content_path_ref": group["content_path_ref"],
        "external_content_path_ref": group["external_content_path_ref"],
    }


def _comparability(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    policy_reference_match = before["policy_path"] == after["policy_path"]
    before_context = before.get("audit_context")
    after_context = after.get("audit_context")
    before_semantic = _semantic_coverage(before["findings"])
    after_semantic = _semantic_coverage(after["findings"])
    semantic_coverage_compatible = before_semantic == after_semantic and before_semantic in {
        "none",
        "complete",
        "not_observable",
    }

    policy_state = _fingerprint_comparison(before_context, after_context, "policy_fingerprint")
    detector_state = _fingerprint_comparison(before_context, after_context, "detector_fingerprint")
    presidio_state = _presidio_comparison(before_context, after_context)
    semantic_state = _semantic_configuration_comparison(before_context, after_context)
    provenance_complete = before_context is not None and after_context is not None

    reason_codes: list[str] = []
    diagnostics: list[dict[str, str]] = []

    def diagnose(code: str, dimension: str, severity: str, message: str) -> None:
        reason_codes.append(code)
        diagnostics.append(
            {
                "code": code,
                "dimension": dimension,
                "severity": severity,
                "message": message,
            }
        )

    if not provenance_complete:
        diagnose(
            "AUDIT_PROVENANCE_INCOMPLETE",
            "configuration",
            "warning",
            "One or both reports predate audit provenance; effective configuration equality cannot be established.",
        )
    if policy_state == "match":
        diagnose(
            "POLICY_FINGERPRINT_MATCH",
            "disposition",
            "info",
            "Effective policy fingerprints match.",
        )
        if not policy_reference_match:
            diagnose(
                "POLICY_REFERENCE_CHANGED_EFFECTIVE_POLICY_MATCH",
                "disposition",
                "info",
                "Policy references differ, but the normalized effective policy is the same.",
            )
    elif policy_state == "mismatch":
        diagnose(
            "POLICY_FINGERPRINT_MISMATCH",
            "disposition",
            "warning",
            "Effective policy fingerprints differ; disposition changes may be configuration-driven.",
        )
        if policy_reference_match:
            diagnose(
                "POLICY_CONTENT_CHANGED_AT_SAME_REFERENCE",
                "disposition",
                "warning",
                "The same policy reference resolved to different effective policy content.",
            )
    else:
        diagnose(
            "POLICY_FINGERPRINT_MISSING",
            "disposition",
            "warning",
            "Effective policy fingerprints are unavailable.",
        )

    if detector_state == "match":
        diagnose("DETECTOR_FINGERPRINT_MATCH", "structural", "info", "Recorded detector fingerprints match.")
    elif detector_state == "mismatch":
        diagnose(
            "DETECTOR_FINGERPRINT_MISMATCH",
            "structural",
            "warning",
            "Detector fingerprints differ; observed exposure populations may be configuration-driven.",
        )
    else:
        diagnose(
            "DETECTOR_FINGERPRINT_MISSING",
            "structural",
            "warning",
            "Detector fingerprints are unavailable.",
        )

    if presidio_state == "mismatch":
        diagnose(
            "PRESIDIO_ENABLEMENT_MISMATCH",
            "structural",
            "warning",
            "Presidio enablement differs between reports.",
        )
    elif presidio_state == "unknown":
        diagnose(
            "PRESIDIO_CONFIGURATION_UNKNOWN",
            "structural",
            "warning",
            "Presidio external analyzer/model configuration is enabled but cannot be verified.",
        )

    if semantic_state == "match":
        diagnose(
            "SEMANTIC_CONFIGURATION_MATCH",
            "semantic",
            "info",
            "Recorded Semantic Resolver configuration matches.",
        )
    elif semantic_state == "mismatch":
        diagnose(
            "SEMANTIC_CONFIGURATION_MISMATCH",
            "semantic",
            "warning",
            "Semantic Resolver enablement or configuration differs.",
        )
    elif semantic_state == "unknown":
        diagnose(
            "SEMANTIC_CONFIGURATION_UNKNOWN",
            "semantic",
            "warning",
            "An enabled Semantic Resolver lacks a stable configuration identifier.",
        )
    else:
        diagnose(
            "SEMANTIC_CONFIGURATION_MISSING",
            "semantic",
            "warning",
            "Semantic Resolver provenance is unavailable.",
        )
    if not semantic_coverage_compatible:
        diagnose(
            "SEMANTIC_COVERAGE_MISMATCH",
            "semantic",
            "warning",
            "Semantic metadata coverage differs or is incomplete.",
        )

    configuration_limited = (
        policy_state != "match"
        or detector_state != "match"
        or presidio_state in {"mismatch", "unknown", "missing"}
        or semantic_state not in {"match", "not_applicable"}
        or not semantic_coverage_compatible
    )
    status = "limited" if configuration_limited else "comparable_with_limitations"
    disposition_status = "limited" if configuration_limited else "comparable"
    warnings = [
        "Paths and source types are represented only by SHA-256 references; no input path, "
        "matched value, raw trace text, policy rule text, or semantic rationale is copied.",
        "New Exposure means newly observed in these reports, not a confirmed new PHI leak.",
        "No Longer Observed does not prove that a risk was eliminated.",
        "Configuration evidence can support comparability but cannot attribute an observed change solely to Agent behavior.",
    ]
    if policy_state == "mismatch" and not policy_reference_match:
        warnings.append(
            "Policy references differ. Disposition changes may come from policy selection rather "
            "than an Agent exposure-path change."
        )
    warnings.extend(item["message"] for item in diagnostics if item["severity"] == "warning")
    return {
        "status": status,
        "reason_codes": reason_codes,
        "diagnostics": diagnostics,
        "structural": {
            "status": "comparable",
            "route_key_compatible": True,
            "observation_basis": "limited" if detector_state != "match" or presidio_state != "match" else "comparable",
        },
        "disposition": {
            "status": disposition_status,
            "policy_fingerprint_comparison": policy_state,
            "configuration_basis": "limited" if configuration_limited else "comparable",
        },
        "provenance_complete": provenance_complete,
        "policy_reference_match": policy_reference_match,
        "policy_reference": {
            "before": _field_ref(before["policy_path"]),
            "after": _field_ref(after["policy_path"]),
        },
        "policy_fingerprint_comparison": policy_state,
        "detector_configuration": detector_state,
        "presidio_configuration": presidio_state,
        "semantic": {
            "before_coverage": before_semantic,
            "after_coverage": after_semantic,
            "coverage_compatible": semantic_coverage_compatible,
            "directly_comparable": False,
            "configuration_comparison": semantic_state,
            "included_in_exposure_key": False,
        },
        "warnings": warnings,
    }


def _fingerprint_comparison(
    before_context: dict[str, Any] | None,
    after_context: dict[str, Any] | None,
    field: str,
) -> str:
    if before_context is None or after_context is None:
        return "missing"
    return "match" if before_context[field] == after_context[field] else "mismatch"


def _presidio_comparison(
    before_context: dict[str, Any] | None,
    after_context: dict[str, Any] | None,
) -> str:
    if before_context is None or after_context is None:
        return "missing"
    if before_context["presidio_enabled"] != after_context["presidio_enabled"]:
        return "mismatch"
    if before_context["presidio_enabled"]:
        return "unknown"
    return "match"


def _semantic_configuration_comparison(
    before_context: dict[str, Any] | None,
    after_context: dict[str, Any] | None,
) -> str:
    if before_context is None or after_context is None:
        return "missing"
    if before_context["semantic_enabled"] != after_context["semantic_enabled"]:
        return "mismatch"
    if not before_context["semantic_enabled"]:
        return "match"
    before_fingerprint = before_context["semantic_resolver_fingerprint"]
    after_fingerprint = after_context["semantic_resolver_fingerprint"]
    if before_fingerprint is None or after_fingerprint is None:
        return "unknown"
    return "match" if before_fingerprint == after_fingerprint else "mismatch"


def _semantic_coverage(findings: list[dict[str, Any]]) -> str:
    if not findings:
        return "not_observable"
    count = sum("semantic" in finding for finding in findings)
    if count == 0:
        return "none"
    if count == len(findings):
        return "complete"
    return "partial"


def _report_identity(report: dict[str, Any]) -> dict[str, Any]:
    return {
        "report_ref": _json_ref(report),
        "audit_schema_version": report["schema_version"],
        "finding_schema": report["finding_schema"],
        "report_value_mode": report["report_value_mode"],
        "semantic_coverage": _semantic_coverage(report["findings"]),
    }


def _sum_frequency(groups: dict[str, dict[str, Any]], field: str) -> int:
    return sum(group["frequency"][field] for group in groups.values())


def _disposition_direction(before_group: dict[str, Any], after_group: dict[str, Any]) -> str:
    before_rank = DISPOSITION_RANK[before_group["worst_disposition"]]
    after_rank = DISPOSITION_RANK[after_group["worst_disposition"]]
    if after_rank > before_rank:
        return "worsened"
    if after_rank < before_rank:
        return "improved"
    return "mixed_or_other"


def _field_ref(value: str | None) -> str | None:
    if value is None:
        return None
    return f"sha256:{hashlib.sha256(value.encode('utf-8')).hexdigest()}"


def _json_ref(value: Any) -> str:
    return f"sha256:{hashlib.sha256(_canonical_json(value).encode('utf-8')).hexdigest()}"


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _is_sha256_ref(value: str) -> bool:
    if not value.startswith("sha256:") or len(value) != len("sha256:") + 64:
        return False
    return all(character in "0123456789abcdef" for character in value[len("sha256:") :])


def _append_group_section(lines: list[str], title: str, groups: list[dict[str, Any]]) -> None:
    lines.extend([f"## {title}", ""])
    if not groups:
        lines.extend(["None.", ""])
        return
    lines.extend(
        [
            "| Exposure Key | Category | Source Layer | Destination Layer | Disposition | Events | Occurrences |",
            "| --- | --- | --- | --- | --- | ---: | ---: |",
        ]
    )
    for group in groups:
        destination = group["destination"] or {}
        lines.append(
            "| `{key}` | {category} | {source} | {destination} | {disposition} | {events} | {occurrences} |".format(
                key=group["exposure_key"],
                category=group["category"],
                source=group["source"]["layer"],
                destination=destination.get("layer") or "none",
                disposition=group["worst_disposition"],
                events=group["frequency"]["events"],
                occurrences=group["frequency"]["occurrences"],
            )
        )
    _append_route_references(lines, groups)


def _append_disposition_section(lines: list[str], changes: list[dict[str, Any]]) -> None:
    lines.extend(["## Changed Dispositions", ""])
    if not changes:
        lines.extend(["None.", ""])
        return
    lines.extend(
        [
            "| Exposure Key | Category | Before | After | Direction |",
            "| --- | --- | --- | --- | --- |",
        ]
    )
    for change in changes:
        exposure = change["exposure"]
        lines.append(
            "| `{key}` | {category} | {before} | {after} | {direction} |".format(
                key=exposure["exposure_key"],
                category=exposure["category"],
                before=change["before"]["worst_disposition"],
                after=change["after"]["worst_disposition"],
                direction=change["direction"],
            )
        )
    _append_route_references(lines, [change["exposure"] for change in changes])


def _append_frequency_section(lines: list[str], changes: list[dict[str, Any]]) -> None:
    lines.extend(["## Changed Frequencies", ""])
    if not changes:
        lines.extend(["None.", ""])
        return
    lines.extend(
        [
            "| Exposure Key | Category | Before Events / Occurrences | After Events / Occurrences |",
            "| --- | --- | ---: | ---: |",
        ]
    )
    for change in changes:
        exposure = change["exposure"]
        before = change["before"]
        after = change["after"]
        lines.append(
            "| `{key}` | {category} | {before_events} / {before_occurrences} | "
            "{after_events} / {after_occurrences} |".format(
                key=exposure["exposure_key"],
                category=exposure["category"],
                before_events=before["events"],
                before_occurrences=before["occurrences"],
                after_events=after["events"],
                after_occurrences=after["occurrences"],
            )
        )
    _append_route_references(lines, [change["exposure"] for change in changes])


def _append_route_references(lines: list[str], groups: list[dict[str, Any]]) -> None:
    lines.extend(["", "Route references:", ""])
    for group in groups:
        destination = group["destination"] or {}
        lines.append(
            "- `{key}`: source-type=`{source_type}`; source-path=`{source_path}`; "
            "destination-path=`{destination_path}`; content-path=`{content_path}`; "
            "external-content-path=`{external_path}`".format(
                key=group["exposure_key"],
                source_type=group["source"]["type_ref"] or "none",
                source_path=group["source"]["path_ref"] or "none",
                destination_path=destination.get("path_ref") or "none",
                content_path=group["content_path_ref"] or "none",
                external_path=group["external_content_path_ref"] or "none",
            )
        )
    lines.append("")
