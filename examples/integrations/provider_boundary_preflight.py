from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Literal, Protocol

from phi_boundary_gate import ComplianceContext, ComplianceDecision, PhiBoundaryGate, load_compliance_policy


ROOT = Path(__file__).resolve().parents[2]


class ModelClient(Protocol):
    def generate(self, text: str) -> str:
        """Send text to an application-owned model client."""


class OfflineModelClient:
    """Local stand-in that proves routing without making a network call."""

    def __init__(self) -> None:
        self.call_count = 0

    def generate(self, text: str) -> str:
        self.call_count += 1
        return "offline-example-response"


def safe_audit_metadata(decision: ComplianceDecision) -> dict[str, object]:
    audit = decision.audit
    return {
        "should_block": decision.should_block,
        "compliance_allowed": decision.compliance_allowed,
        "block_reasons": list(decision.block_reasons),
        "warning_codes": list(decision.warnings),
        "finding_count": audit["finding_count"],
        "service_matched": audit["service_matched"],
        "service_id": decision.service_id,
    }


def preflight_and_send(
    gate: PhiBoundaryGate,
    client: ModelClient,
    text: str,
    context: ComplianceContext,
    *,
    outbound_mode: Literal["original", "redacted"],
) -> dict[str, object]:
    decision = gate.guard_compliance(
        text,
        layer="model_input",
        context=context,
        enforce_declared_phi=True,
    )
    metadata = safe_audit_metadata(decision)
    if decision.should_block:
        return {**metadata, "provider_called": False}

    # The application chooses explicitly: preserve the original request when
    # the approved route needs full semantics, or opt into detector-driven
    # redaction. The guard never silently substitutes one for the other.
    outbound_text = text if outbound_mode == "original" else decision.redacted_text
    client.generate(outbound_text)
    return {**metadata, "provider_called": True, "outbound_mode": outbound_mode}


def main() -> int:
    parser = argparse.ArgumentParser(description="Run an offline provider-boundary preflight example.")
    parser.add_argument("--phi-policy", type=Path, default=ROOT / "samples/policies/default.yml")
    parser.add_argument(
        "--compliance-policy",
        type=Path,
        default=ROOT / "examples/integrations/provider_boundary_policy.yml",
    )
    parser.add_argument("--outbound-mode", choices=("original", "redacted"), default="original")
    args = parser.parse_args()

    gate = PhiBoundaryGate.from_policy_file(
        args.phi_policy,
        compliance_policy=load_compliance_policy(args.compliance_policy),
    )
    client = OfflineModelClient()
    request_text = "Create the requested follow-up summary."

    allowed = preflight_and_send(
        gate,
        client,
        request_text,
        ComplianceContext(
            phi_status="real_phi",
            vendor="northstar_example",
            service="model_gateway",
            endpoint="generate",
            model="care-text-1",
            feature="text_generation",
            environment="production",
            region="example-region-1",
            logging="metadata_only",
            storage="none",
            purpose="care_summary",
        ),
        outbound_mode=args.outbound_mode,
    )
    blocked = preflight_and_send(
        gate,
        client,
        request_text,
        ComplianceContext(
            phi_status="real_phi",
            vendor="unlisted_example",
            service="model_api",
            endpoint="generate",
            model="general-text-1",
            feature="text_generation",
            environment="production",
            logging="metadata_only",
            storage="none",
        ),
        outbound_mode=args.outbound_mode,
    )

    print(json.dumps({"allowed": allowed, "blocked": blocked, "offline_client_calls": client.call_count}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
