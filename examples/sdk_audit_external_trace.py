from __future__ import annotations

import json
from pathlib import Path

from phi_boundary_gate import PhiBoundaryGate


ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    gate = PhiBoundaryGate.from_policy_file(ROOT / "samples/policies/default.yml")
    result = gate.audit_external_trace(
        ROOT / "samples/external_traces/generic_agent_run.jsonl",
        mapping=ROOT / "samples/trace_mappings/generic_agent.yml",
        report_value_mode="redacted",
    )
    print(
        json.dumps(
            {
                "has_violations": result.has_violations,
                "total_findings": result.summary["total_findings"],
                "trace_path": result.to_dict()["trace_path"],
                "schema_version": result.to_dict()["schema_version"],
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
