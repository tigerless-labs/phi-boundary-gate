from __future__ import annotations

import argparse
from pathlib import Path

from .policy import load_policy
from .report import build_report, write_json_report, write_markdown_report
from .trace import load_trace


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate a synthetic PHI context boundary report.")
    parser.add_argument("--trace", required=True, type=Path, help="Path to a synthetic JSONL trace.")
    parser.add_argument("--policy", required=True, type=Path, help="Path to a YAML PHI policy.")
    parser.add_argument("--out", required=True, type=Path, help="Path for the Markdown report.")
    parser.add_argument("--json", required=True, type=Path, dest="json_out", help="Path for the JSON report.")
    args = parser.parse_args(argv)

    events = load_trace(args.trace)
    policy = load_policy(args.policy)
    report = build_report(events, policy, args.trace, args.policy)

    write_markdown_report(report, args.out)
    write_json_report(report, args.json_out)

    summary = report["summary"]
    print(
        "Wrote {total} PHI candidate finding(s): {markdown} and {json}".format(
            total=summary["total_findings"],
            markdown=args.out,
            json=args.json_out,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
