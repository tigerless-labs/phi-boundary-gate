from __future__ import annotations

import argparse
import json
from pathlib import Path

from phi_boundary_gate import build_audit_coverage, load_trace


ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description="Summarize observed audit coverage.")
    parser.add_argument("--trace", type=Path, default=ROOT / "samples/traces/no_phi.jsonl")
    args = parser.parse_args()

    coverage = build_audit_coverage(
        load_trace(args.trace),
        expected_layers=["model_input", "tool_output"],
    )
    print(json.dumps(coverage.to_dict(), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
