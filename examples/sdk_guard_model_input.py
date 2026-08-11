from __future__ import annotations

import argparse
import json
from pathlib import Path

from phi_boundary_gate import PhiBoundaryGate


ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description="Guard model input with the SDK facade.")
    parser.add_argument("--policy", type=Path, default=ROOT / "samples/policies/default.yml")
    args = parser.parse_args()

    gate = PhiBoundaryGate.from_policy_file(args.policy)
    decision = gate.guard_model_input("Summarize member_id=MBR-SYN-8842 for the next care step.")
    print(json.dumps(decision.to_safe_dict(), sort_keys=True))
    return 1 if decision.should_block else 0


if __name__ == "__main__":
    raise SystemExit(main())
