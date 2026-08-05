from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .adapters import load_external_trace, mapping_summary, validate_trace_mapping, write_converted_trace
from .policy import load_policy
from .project import check_project_config, init_project
from .redacted_trace import write_redacted_trace
from .report import build_report, write_json_report, write_markdown_report
from .trace import TraceEvent, load_trace, trace_event_to_dict

COMMANDS = {"init", "check-config", "convert-trace", "scan-trace", "validate-mapping", "validate-trace"}


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

    scan_parser = subparsers.add_parser("scan-trace", help="Scan a JSONL trace and write audit outputs.")
    _add_scan_trace_args(scan_parser)

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
        "--enable-presidio",
        action="store_true",
        help="Enable optional local Presidio PII detection in addition to built-in regex rules.",
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
        report = build_report(events, policy, args.trace, args.policy, enable_presidio=args.enable_presidio)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    write_markdown_report(report, args.out)
    write_json_report(report, args.json_out)
    if args.redacted_trace:
        try:
            write_redacted_trace(events, policy, args.redacted_trace, enable_presidio=args.enable_presidio)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    summary = report["summary"]
    redacted_note = f" and redacted trace {args.redacted_trace}" if args.redacted_trace else ""
    print(
        "Wrote {total} PHI candidate finding(s): {markdown} and {json}{redacted}".format(
            total=summary["total_findings"],
            markdown=args.out,
            json=args.json_out,
            redacted=redacted_note,
        )
    )
    return 0


def _convert_trace(args: argparse.Namespace) -> int:
    try:
        if args.stdout:
            events = load_external_trace(args.input, args.mapping)
            _write_trace_stdout(events)
        else:
            events = write_converted_trace(args.input, args.mapping, args.out)
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
