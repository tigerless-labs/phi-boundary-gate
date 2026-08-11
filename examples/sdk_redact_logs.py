from __future__ import annotations

import argparse
from pathlib import Path

from phi_boundary_gate import PhiBoundaryGate


ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description="Redact text before writing application logs.")
    parser.add_argument("--policy", type=Path, default=ROOT / "samples/policies/default.yml")
    args = parser.parse_args()

    gate = PhiBoundaryGate.from_policy_file(args.policy)
    print(gate.redact_for_log("debug claim_id=CLM-SYN-44501 member_id=MBR-SYN-8842"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
