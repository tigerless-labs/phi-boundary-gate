from __future__ import annotations

import argparse
from pathlib import Path

from phi_boundary_gate import TraceAdapter, validate_trace_mapping


ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description="Normalize a generic agent JSONL trace with mapping v1.")
    parser.add_argument("--input", type=Path, default=ROOT / "samples/external_traces/generic_agent_run.jsonl")
    parser.add_argument("--mapping", type=Path, default=ROOT / "samples/trace_mappings/generic_agent.yml")
    parser.add_argument("--out", type=Path, default=Path("/tmp/phi-example-normalized.jsonl"))
    args = parser.parse_args()

    validate_trace_mapping(args.mapping)
    adapter = TraceAdapter.from_mapping(args.mapping)
    events = adapter.write(args.input, args.out)
    print(f"Wrote {len(events)} normalized event(s): {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
