# Compliance Guard

The compliance guard adds a deterministic eligibility check on top of PHI scanning. It is designed for projects that need to prevent PHI from being sent to a model, feature, logging path, or storage mode that is not approved by the organization's BAA and service policy.

It does not discover whether your company signed a BAA. That is an organizational fact. The guard enforces the facts supplied in a private compliance policy file.

The consuming project must provide both policy files. The sample policies in this
repository are fixtures and schema examples, not installed package data.

## Basic Use

```python
from pathlib import Path

from phi_boundary_gate import (
    ComplianceContext,
    guard_compliance,
    load_compliance_policy,
    load_policy,
)

phi_policy = load_policy(Path("config/phi-policy.yml"))
compliance_policy = load_compliance_policy(Path("config/phi-compliance-policy.yml"))

request_text = "Create the requested follow-up summary."
decision = guard_compliance(
    request_text,
    layer="model_input",
    phi_policy=phi_policy,
    compliance_policy=compliance_policy,
    context=ComplianceContext(
        phi_status="real_phi",
        vendor="northstar_example",
        service="model_gateway",
        endpoint="generate",
        model="care-text-1",
        feature="text_generation",
        environment="production",
        logging="redacted_only",
        storage="none",
    ),
    enforce_declared_phi=True,
)

if decision.should_block:
    raise RuntimeError(decision.block_reasons)

# This workflow needs the full allowed request. Redaction is a separate,
# explicit application choice; it is never substituted silently by the guard.
text_for_model = request_text

# Log a reviewed structural whitelist, not the complete decision object.
audit_payload = {
    "should_block": decision.should_block,
    "compliance_allowed": decision.compliance_allowed,
    "block_reasons": decision.block_reasons,
    "warning_codes": decision.warnings,
    "finding_count": decision.audit["finding_count"],
    "service_matched": decision.audit["service_matched"],
    "service_id": decision.service_id,
}
```

## What It Checks

By default, these checks run when the detector finds a PHI candidate. When
`enforce_declared_phi=True`, they also run when
`ComplianceContext.phi_status == "real_phi"`, even if the detector found no
candidate:

- service profile exists for the vendor, service, and model
- `covered_service` is true when the PHI status requires BAA coverage
- `baa_executed` is true when the PHI status requires BAA coverage
- PHI status is explicitly allowed by the service profile
- model does not match denied patterns such as preview, beta, or experimental
- feature is allowed and not explicitly denied
- logging mode is allowed for PHI workflows
- storage mode is allowed for PHI workflows
- environment requirements such as production redacted logging are satisfied

If no PHI is detected and declared enforcement is not active, an unknown
service profile is reported as a warning instead of a block. This is the
backward-compatible default. Declared enforcement applies only to `real_phi`;
it does not promote `synthetic`, `deidentified`, or `non_phi` to real PHI.

`text_decision.has_phi` and its findings always describe detector output. The
declared-PHI option does not fabricate a finding or change redaction output.

Service profiles currently match `vendor`, `service`, and `model_patterns`.
`feature`, logging, storage, PHI status, BAA flags, and the production raw-log
rule are then evaluated for the matched profile. `endpoint`, `region`, and
`purpose` are recorded context only; they are not policy-match dimensions in
policy version 1. `require_audit` is also recorded in decision metadata for the
caller and is not itself a blocking rule.

## Audit Safety

`ComplianceDecision.to_dict()` is not an unconditional ordinary-log payload.
With the default `include_phi=False`, it omits the original `GuardDecision.text`
and raw finding values. However, it still includes `redacted_text`, and
detector-driven redaction leaves that field equal to the original input when no
candidate is found. It also includes caller-controlled context strings. Missed
or unknown sensitive content can therefore remain present.

Prefer an explicit whitelist such as the structural `audit_payload` above.
Only log `redacted_text` after the application has separately established that
the detector coverage and destination are appropriate. Keep free-form context
values free of PHI and secrets.

Use `decision.to_dict(include_phi=True)` only in controlled debugging contexts where raw PHI handling is approved.

## Boundary

This guard is a policy enforcement tool, not a legal opinion. It cannot know contract status unless your organization supplies it through policy. Keep the compliance policy reviewed by security, legal, or platform owners, and update it when vendor contracts, covered services, models, or logging behavior changes.
