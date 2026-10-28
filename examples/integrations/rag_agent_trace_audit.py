from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path

from phi_boundary_gate import PhiBoundaryGate


ROOT = Path(__file__).resolve().parents[2]


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit a mapped synthetic RAG/agent trace without network access.")
    parser.add_argument("--input", type=Path, default=ROOT / "samples/external_traces/generic_agent_run.jsonl")
    parser.add_argument("--mapping", type=Path, default=ROOT / "samples/trace_mappings/generic_agent.yml")
    parser.add_argument("--policy", type=Path, default=ROOT / "samples/policies/default.yml")
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path(tempfile.gettempdir()) / "phi-rag-agent-audit",
    )
    parser.add_argument("--report-values", choices=("redacted", "hashed"), default="hashed")
    args = parser.parse_args()

    args.out_dir.mkdir(parents=True, exist_ok=True)
    gate = PhiBoundaryGate.from_policy_file(args.policy)
    result = gate.audit_external_trace(
        args.input,
        mapping=args.mapping,
        diagnostics_path=args.out_dir / "mapping-diagnostics.json",
        report_value_mode=args.report_values,
    )
    coverage = gate.coverage_external_trace(
        args.input,
        mapping=args.mapping,
        expected_layers=["user_message", "rag_context", "tool_output", "model_input"],
    )

    result.write_json(args.out_dir / "audit-report.json")
    result.write_markdown(args.out_dir / "audit-report.md")
    coverage.write_json(args.out_dir / "coverage.json")
    coverage.write_markdown(args.out_dir / "coverage.md")

    print(
        json.dumps(
            {
                "audit_schema_version": result.to_dict()["schema_version"],
                "coverage_schema_version": coverage.to_dict()["schema_version"],
                "finding_count": result.summary["total_findings"],
                "has_violations": result.has_violations,
                "observed_layers": coverage.to_dict()["observed_layers"],
                "potential_blind_spot_codes": [item["code"] for item in coverage.diagnostics],
                "report_value_mode": args.report_values,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
