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


@dataclass(frozen=True)
class ExposureDiffResult:
    """Advisory comparison of two validated JSON audit reports."""

    report: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return self.report

    def to_markdown(self) -> str:
        return render_exposure_diff_markdown(self.report)

    def write_json(self, path: Path | str) -> None:
        write_exposure_diff_json(self.report, Path(path))

    def write_markdown(self, path: Path | str) -> None:
        write_exposure_diff_markdown(self.report, Path(path))


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
            changed_dispositions.append(
                {
                    "exposure": _descriptor(before_group),
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
    policy_match = before["policy_path"] == after["policy_path"]
    before_semantic = _semantic_coverage(before["findings"])
    after_semantic = _semantic_coverage(after["findings"])
    semantic_coverage_compatible = before_semantic == after_semantic and before_semantic in {
        "none",
        "complete",
    }
    warnings = [
        "Audit reports do not record policy-content or detector-configuration fingerprints; "
        "observed differences cannot be attributed solely to Agent behavior.",
        "Paths and source types are represented only by SHA-256 references; no input path, "
        "matched value, raw trace text, policy rule text, or semantic rationale is copied.",
        "New Exposure means newly observed in these reports, not a confirmed new PHI leak.",
        "No Longer Observed does not prove that a risk was eliminated.",
    ]
    status = "comparable_with_limitations"
    if not policy_match:
        status = "limited"
        warnings.append(
            "Policy references differ. Disposition changes may come from policy selection rather "
            "than an Agent exposure-path change."
        )
    if not semantic_coverage_compatible:
        status = "limited"
        warnings.append(
            "Semantic metadata coverage differs or is incomplete, so semantic outcomes are not "
            "directly comparable. Semantic fields are excluded from this diff."
        )
    else:
        warnings.append(
            "Semantic fields are intentionally excluded and audit reports do not identify the "
            "resolver configuration; this comparison does not rerun or replace the Semantic Context Gate."
        )
    return {
        "status": status,
        "policy_reference_match": policy_match,
        "policy_reference": {
            "before": _field_ref(before["policy_path"]),
            "after": _field_ref(after["policy_path"]),
        },
        "detector_configuration": "not_recorded_in_audit_report",
        "semantic": {
            "before_coverage": before_semantic,
            "after_coverage": after_semantic,
            "coverage_compatible": semantic_coverage_compatible,
            "directly_comparable": False,
            "included_in_exposure_key": False,
        },
        "warnings": warnings,
    }


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
            "| Exposure Key | Category | Before | After |",
            "| --- | --- | --- | --- |",
        ]
    )
    for change in changes:
        exposure = change["exposure"]
        lines.append(
            "| `{key}` | {category} | {before} | {after} |".format(
                key=exposure["exposure_key"],
                category=exposure["category"],
                before=change["before"]["worst_disposition"],
                after=change["after"]["worst_disposition"],
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
