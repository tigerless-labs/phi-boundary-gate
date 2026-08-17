from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Sequence

from .adapters import (
    build_conversion_diagnostics,
    load_trace_mapping,
    write_converted_trace,
)
from .cli import main as legacy_main


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phi-boundary-gate scan-external-trace",
        description=(
            "Normalize an external JSONL trace with a mapping and scan it "
            "through the existing PHI Boundary Gate audit pipeline."
        ),
    )
    parser.add_argument("--input", required=True, help="External JSONL trace.")
    parser.add_argument("--mapping", required=True, help="Mapping v1 YAML file.")
    parser.add_argument("--policy", required=True, help="Boundary policy YAML file.")
    parser.add_argument("--out", required=True, help="Markdown report output path.")
    parser.add_argument("--json", required=True, help="JSON report output path.")
    parser.add_argument(
        "--report-values",
        choices=("raw", "redacted", "hashed"),
        default="redacted",
        help=(
            "How finding values appear in reports. Direct external scans "
            "default to redacted for audit-safe output."
        ),
    )
    parser.add_argument(
        "--diagnostics",
        help="Optional adapter diagnostics JSON output path.",
    )
    parser.add_argument(
        "--normalized-trace",
        help=(
            "Optional path to retain the normalized trace for debugging. "
            "The normalized trace may still contain sensitive content."
        ),
    )
    parser.add_argument(
        "--redacted-trace",
        help="Optional redacted normalized trace output path.",
    )
    parser.add_argument(
        "--enable-presidio",
        action="store_true",
        help="Enable the optional Presidio detector during the scan.",
    )
    return parser


def _write_diagnostics(
    input_path: Path,
    mapping_path: Path,
    output_path: Path,
) -> None:
    diagnostics = build_conversion_diagnostics(
        input_path,
        load_trace_mapping(mapping_path),
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(diagnostics, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _scan_args(args: argparse.Namespace, normalized_path: Path) -> list[str]:
    forwarded = [
        "scan-trace",
        "--trace",
        str(normalized_path),
        "--policy",
        args.policy,
        "--out",
        args.out,
        "--json",
        args.json,
        "--report-values",
        args.report_values,
    ]
    if args.redacted_trace:
        forwarded.extend(["--redacted-trace", args.redacted_trace])
    if args.enable_presidio:
        forwarded.append("--enable-presidio")
    return forwarded


def _prepare_normalized(
    args: argparse.Namespace,
    normalized_path: Path,
) -> None:
    input_path = Path(args.input)
    mapping_path = Path(args.mapping)

    normalized_path.parent.mkdir(parents=True, exist_ok=True)
    write_converted_trace(input_path, mapping_path, normalized_path)

    if args.diagnostics:
        _write_diagnostics(input_path, mapping_path, Path(args.diagnostics))


def _prepare_or_error(
    args: argparse.Namespace,
    normalized_path: Path,
) -> bool:
    try:
        _prepare_normalized(args, normalized_path)
        return True
    except Exception as exc:
        # Conversion is a user/input boundary: malformed external traces or
        # mappings should fail like the existing convert-trace command rather
        # than emit a traceback. Scan errors are deliberately not swallowed.
        print(f"error: {exc}", file=sys.stderr)
        return False


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    if args.normalized_trace:
        normalized_path = Path(args.normalized_trace)
        if not _prepare_or_error(args, normalized_path):
            return 2
        return legacy_main(_scan_args(args, normalized_path))

    with tempfile.TemporaryDirectory(
        prefix="phi-boundary-gate-external-cli-"
    ) as tmp_dir:
        normalized_path = Path(tmp_dir) / "normalized-trace.jsonl"
        if not _prepare_or_error(args, normalized_path):
            return 2
        return legacy_main(_scan_args(args, normalized_path))


if __name__ == "__main__":
    raise SystemExit(main())
