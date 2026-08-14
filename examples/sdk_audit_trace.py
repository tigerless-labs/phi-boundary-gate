from __future__ import annotations

import json
from pathlib import Path

from phi_boundary_gate import PhiBoundaryGate


ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    gate = PhiBoundaryGate.from_policy_file(ROOT / "samples/policies/default.yml")
    result = gate.audit_trace(
        ROOT / "samples/traces/claim_agent_minimal.jsonl",
        policy_path=ROOT / "samples/policies/default.yml",
        report_value_mode="redacted",
    )
    print(
        json.dumps(
            {
                "has_violations": result.has_violations,
                "total_findings": result.summary["total_findings"],
                "schema_version": result.to_dict()["schema_version"],
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
