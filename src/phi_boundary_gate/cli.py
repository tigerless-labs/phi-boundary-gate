from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .adapters import (
    TraceAdapter,
    load_external_trace,
    mapping_summary,
    validate_trace_mapping,
    write_conversion_diagnostics,
    write_converted_trace,
)
from .coverage import build_audit_coverage
from .exposure_diff import compare_report_files
from .policy import load_policy
from .project import check_project_config, init_project
from .redacted_trace import write_redacted_trace
from .report import REPORT_VALUE_MODES, build_report, write_json_report, write_markdown_report
from .trace import SUPPORTED_LAYERS, TraceEvent, load_trace, trace_event_to_dict, write_trace

COMMANDS = {
    "compare-reports",
    "init",
    "check-config",
    "convert-trace",
    "scan-external-trace",
    "scan-trace",
    "validate-mapping",
    "validate-trace",
}


def main(argv: list[str] | None = None) -> int:
    args_list = list(sys.argv[1:] if argv is None else argv)
    if args_list and args_list[0] not in COMMANDS and args_list[0] not in ("-h", "--help"):
        return _scan_trace(args_list)

    parser = argparse.ArgumentParser(description="Gate PHI boundary flows and manage project policy config.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser("init", help="Create project policy config files.")
    init_parser.add_argument("--root", type=Path, default=Path.cwd(), help="Project root to initialize.")
    init_parser.add_argument("--policy", type=Path, help="Policy path relative to --root.")
    init_parser.add_argument("--compliance-policy", type=Path, help="Compliance policy path relative to --root.")
    init_parser.add_argument("--force", action="store_true", help="Overwrite existing generated config files.")

    check_parser = subparsers.add_parser("check-config", help="Validate discovered project config and policies.")
    check_parser.add_argument("--root", type=Path, default=Path.cwd(), help="Start directory for config discovery.")

    convert_parser = subparsers.add_parser("convert-trace", help="Normalize an external JSONL trace.")
    convert_parser.add_argument("--input", required=True, type=Path, help="Path to the external JSONL trace.")
    convert_parser.add_argument("--mapping", required=True, type=Path, help="Path to a mapping v1 YAML file.")
    output_group = convert_parser.add_mutually_exclusive_group(required=True)
    output_group.add_argument("--out", type=Path, help="Path for the normalized PHI Boundary Gate JSONL trace.")
    output_group.add_argument("--stdout", action="store_true", help="Write normalized JSONL to stdout.")
    convert_parser.add_argument("--diagnostics", type=Path, help="Optional path for adapter diagnostics JSON.")

    external_parser = subparsers.add_parser(
        "scan-external-trace",
        help="Normalize and scan an external JSONL trace in one step.",
    )
    _add_scan_external_trace_args(external_parser)

    scan_parser = subparsers.add_parser("scan-trace", help="Scan a JSONL trace and write audit outputs.")
    _add_scan_trace_args(scan_parser)

    compare_parser = subparsers.add_parser(
        "compare-reports",
        help="Compare two JSON audit reports and write an advisory exposure diff.",
    )
    compare_parser.add_argument("--before", required=True, type=Path, help="Baseline JSON audit report.")
    compare_parser.add_argument("--after", required=True, type=Path, help="Candidate JSON audit report.")
    compare_parser.add_argument("--out", required=True, type=Path, help="Path for the Markdown diff.")
    compare_parser.add_argument("--json", required=True, type=Path, dest="json_out", help="Path for the JSON diff.")
    compare_parser.add_argument(
        "--review-summary",
        type=Path,
        help="Optional path for a concise advisory Markdown review summary.",
    )

    mapping_parser = subparsers.add_parser("validate-mapping", help="Validate a mapping v1 YAML file.")
    mapping_parser.add_argument("--mapping", required=True, type=Path, help="Path to a mapping v1 YAML file.")

    validate_parser = subparsers.add_parser("validate-trace", help="Validate a PHI Boundary Gate JSONL trace.")
    validate_parser.add_argument("--trace", required=True, type=Path, help="Path to the normalized JSONL trace.")

    args = parser.parse_args(args_list)
    if args.command == "init":
        return _init(args)
    if args.command == "check-config":
        return _check_config(args)
    if args.command == "convert-trace":
        return _convert_trace(args)
    if args.command == "scan-external-trace":
        return _scan_external_trace(args)
    if args.command == "compare-reports":
        return _compare_reports(args)
    if args.command == "validate-mapping":
        return _validate_mapping(args)
    if args.command == "validate-trace":
        return _validate_trace(args)
    return _scan_trace_from_args(args)


def _add_scan_trace_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--trace", required=True, type=Path, help="Path to a synthetic JSONL trace.")
    parser.add_argument("--policy", required=True, type=Path, help="Path to a YAML PHI policy.")
    parser.add_argument("--out", required=True, type=Path, help="Path for the Markdown report.")
    parser.add_argument("--json", required=True, type=Path, dest="json_out", help="Path for the JSON report.")
    parser.add_argument("--redacted-trace", type=Path, help="Optional path for a redacted JSONL trace.")
    parser.add_argument(
        "--report-values",
        choices=sorted(REPORT_VALUE_MODES),
        default="raw",
        help="How matched values are displayed in Markdown and JSON reports.",
    )
    parser.add_argument(
        "--enable-presidio",
        action="store_true",
        help="Enable optional local Presidio PII detection in addition to built-in regex rules.",
    )
    _add_coverage_args(parser)


def _add_scan_external_trace_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--input", required=True, type=Path, help="Path to the external JSONL trace.")
    parser.add_argument("--mapping", required=True, type=Path, help="Path to a mapping v1 YAML file.")
    parser.add_argument("--policy", required=True, type=Path, help="Path to a YAML PHI policy.")
    parser.add_argument("--out", required=True, type=Path, help="Path for the Markdown report.")
    parser.add_argument("--json", required=True, type=Path, dest="json_out", help="Path for the JSON report.")
    parser.add_argument("--diagnostics", type=Path, help="Optional path for adapter diagnostics JSON.")
    parser.add_argument(
        "--normalized-trace",
        type=Path,
        help="Optional path to retain the normalized trace for debugging; it may contain sensitive content.",
    )
    parser.add_argument("--redacted-trace", type=Path, help="Optional path for a redacted normalized JSONL trace.")
    parser.add_argument(
        "--report-values",
        choices=sorted(REPORT_VALUE_MODES),
        default="redacted",
        help="How matched values are displayed in Markdown and JSON reports.",
    )
    parser.add_argument(
        "--enable-presidio",
        action="store_true",
        help="Enable optional local Presidio PII detection in addition to built-in regex rules.",
    )
    _add_coverage_args(parser)


def _add_coverage_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--coverage-json",
        type=Path,
        help="Optional path for the advisory audit coverage JSON.",
    )
    parser.add_argument(
        "--coverage-markdown",
        type=Path,
        help="Optional path for the advisory audit coverage Markdown.",
    )
    parser.add_argument(
        "--expect-layer",
        action="append",
        choices=sorted(SUPPORTED_LAYERS),
        default=[],
        help="Expected trace layer; repeat to diagnose explicitly missing layers.",
    )


def _scan_trace(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Gate synthetic PHI boundary flows and write audit reports.")
    _add_scan_trace_args(parser)
    args = parser.parse_args(argv)
    return _scan_trace_from_args(args)


def _scan_trace_from_args(args: argparse.Namespace) -> int:
    try:
        events = load_trace(args.trace)
        policy = load_policy(args.policy)
        report = build_report(
            events,
            policy,
            args.trace,
            args.policy,
            enable_presidio=args.enable_presidio,
            report_value_mode=args.report_values,
        )
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    return _write_scan_outputs(
        events,
        policy,
        report,
        markdown_out=args.out,
        json_out=args.json_out,
        redacted_trace_out=args.redacted_trace,
        enable_presidio=args.enable_presidio,
        coverage_json_out=args.coverage_json,
        coverage_markdown_out=args.coverage_markdown,
        expected_layers=args.expect_layer,
    )


def _scan_external_trace(args: argparse.Namespace) -> int:
    try:
        adapter = TraceAdapter.from_mapping(args.mapping)
        events = adapter.load(args.input)
        policy = load_policy(args.policy)

        if args.normalized_trace:
            args.normalized_trace.parent.mkdir(parents=True, exist_ok=True)
            write_trace(events, args.normalized_trace)

        if args.diagnostics:
            diagnostics = adapter.diagnostics(args.input)
            args.diagnostics.parent.mkdir(parents=True, exist_ok=True)
            args.diagnostics.write_text(
                json.dumps(diagnostics, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )

        mapping_diagnostics = adapter.coverage_diagnostics(events)

        report = build_report(
            events,
            policy,
            args.input,
            args.policy,
            enable_presidio=args.enable_presidio,
            report_value_mode=args.report_values,
        )
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    return _write_scan_outputs(
        events,
        policy,
        report,
        markdown_out=args.out,
        json_out=args.json_out,
        redacted_trace_out=args.redacted_trace,
        enable_presidio=args.enable_presidio,
        coverage_json_out=args.coverage_json,
        coverage_markdown_out=args.coverage_markdown,
        expected_layers=args.expect_layer,
        mapping_diagnostics=mapping_diagnostics,
    )


def _write_scan_outputs(
    events: list[TraceEvent],
    policy,
    report: dict,
    *,
    markdown_out: Path,
    json_out: Path,
    redacted_trace_out: Path | None,
    enable_presidio: bool,
    coverage_json_out: Path | None,
    coverage_markdown_out: Path | None,
    expected_layers: list[str],
    mapping_diagnostics: dict | None = None,
) -> int:
    coverage = None
    try:
        write_markdown_report(report, markdown_out)
        write_json_report(report, json_out)
        if redacted_trace_out:
            write_redacted_trace(events, policy, redacted_trace_out, enable_presidio=enable_presidio)
        if coverage_json_out or coverage_markdown_out:
            coverage = build_audit_coverage(
                events,
                expected_layers=expected_layers,
                mapping_diagnostics=mapping_diagnostics,
            )
            if coverage_json_out:
                coverage.write_json(coverage_json_out)
            if coverage_markdown_out:
                coverage.write_markdown(coverage_markdown_out)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    summary = report["summary"]
    redacted_note = f" and redacted trace {redacted_trace_out}" if redacted_trace_out else ""
    print(
        "Wrote {total} PHI candidate finding(s): {markdown} and {json}{redacted}".format(
            total=summary["total_findings"],
            markdown=markdown_out,
            json=json_out,
            redacted=redacted_note,
        )
    )
    if coverage is not None:
        outputs = [str(path) for path in (coverage_json_out, coverage_markdown_out) if path is not None]
        print(
            "Wrote advisory audit coverage: {outputs}; warning(s)={warnings}".format(
                outputs=" and ".join(outputs),
                warnings=len(coverage.diagnostics),
            )
        )
    return 0


def _compare_reports(args: argparse.Namespace) -> int:
    try:
        result = compare_report_files(args.before, args.after)
        result.write_markdown(args.out)
        result.write_json(args.json_out)
        if args.review_summary:
            result.write_review_summary(args.review_summary)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    summary = result.to_dict()["summary"]
    print(
        "Wrote advisory exposure diff: {markdown} and {json}; "
        "new={new}, no-longer-observed={removed}, disposition-changed={disposition}, "
        "frequency-changed={frequency}".format(
            markdown=args.out,
            json=args.json_out,
            new=summary["new_exposures"],
            removed=summary["no_longer_observed"],
            disposition=summary["changed_dispositions"],
            frequency=summary["changed_frequencies"],
        )
    )
    if args.review_summary:
        print(f"Wrote advisory regression review summary: {args.review_summary}")
    return 0


def _convert_trace(args: argparse.Namespace) -> int:
    try:
        if args.stdout:
            events = load_external_trace(args.input, args.mapping)
            _write_trace_stdout(events)
        else:
            events = write_converted_trace(args.input, args.mapping, args.out)
        if args.diagnostics:
            write_conversion_diagnostics(args.input, args.mapping, args.diagnostics)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.stdout:
        print(f"Converted {len(events)} normalized event(s).", file=sys.stderr)
    else:
        print(f"Wrote {len(events)} normalized event(s): {args.out}")
    return 0


def _validate_trace(args: argparse.Namespace) -> int:
    try:
        events = load_trace(args.trace)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if not events:
        print(f"error: {args.trace}: trace has no events", file=sys.stderr)
        return 2

    layers = sorted({event.layer for event in events})
    destination_layers = sorted(
        {
            str(destination["layer"])
            for event in events
            for destination in event.destinations
            if "layer" in destination
        }
    )
    print(f"Trace ok: {args.trace}")
    print(f"Events: {len(events)}")
    print(f"Layers: {', '.join(layers)}")
    if destination_layers:
        print(f"Destination layers: {', '.join(destination_layers)}")
    return 0


def _validate_mapping(args: argparse.Namespace) -> int:
    try:
        mapping = validate_trace_mapping(args.mapping)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    summary = mapping_summary(mapping)
    print(f"Mapping ok: {args.mapping}")
    print(f"Version: {summary['version']}")
    print(f"Content fields: {', '.join(summary['content_fields'])}")
    if summary["layer_aliases"]:
        aliases = ", ".join(f"{key}->{value}" for key, value in sorted(summary["layer_aliases"].items()))
        print(f"Layer aliases: {aliases}")
    if summary["metadata_fields"]:
        print(f"Metadata fields: {', '.join(summary['metadata_fields'])}")
    print(f"Destinations configured: {summary['destination_count']}")
    return 0


def _write_trace_stdout(events: list[TraceEvent]) -> None:
    for event in events:
        print(json.dumps(trace_event_to_dict(event), sort_keys=True))


def _init(args: argparse.Namespace) -> int:
    try:
        config = init_project(
            args.root,
            policy_path=args.policy,
            compliance_policy_path=args.compliance_policy,
            force=args.force,
        )
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"Wrote PHI Boundary Gate config: {config.config_path}")
    print(f"Policy: {config.policy_path}")
    if config.compliance_policy_path:
        print(f"Compliance policy: {config.compliance_policy_path}")
    return 0


def _check_config(args: argparse.Namespace) -> int:
    try:
        config = check_project_config(args.root)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"Config ok: {config.config_path}")
    print(f"Policy ok: {config.policy_path}")
    if config.compliance_policy_path:
        print(f"Compliance policy ok: {config.compliance_policy_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
