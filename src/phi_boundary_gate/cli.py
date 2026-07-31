from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .policy import load_policy
from .project import check_project_config, init_project
from .redacted_trace import write_redacted_trace
from .report import build_report, write_json_report, write_markdown_report
from .trace import load_trace

COMMANDS = {"init", "check-config", "scan-trace"}


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

    scan_parser = subparsers.add_parser("scan-trace", help="Scan a JSONL trace and write audit outputs.")
    _add_scan_trace_args(scan_parser)

    args = parser.parse_args(args_list)
    if args.command == "init":
        return _init(args)
    if args.command == "check-config":
        return _check_config(args)
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
