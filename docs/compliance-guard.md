# Compliance Guard

The compliance guard adds a deterministic eligibility check on top of PHI scanning. It is designed for projects that need to prevent PHI from being sent to a model, endpoint, feature, logging path, or storage mode that is not approved by the organization's BAA and service policy.

It does not discover whether your company signed a BAA. That is an organizational fact. The guard enforces the facts supplied in a private compliance policy file.

The consuming project must provide both policy files. The sample policies in this
repository are fixtures and schema examples, not installed package data.

## Basic Use

```python
from pathlib import Path

from phi_boundary_report import (
    ComplianceContext,
    guard_compliance,
    load_compliance_policy,
    load_policy,
)

phi_policy = load_policy(Path("config/phi-policy.yml"))
compliance_policy = load_compliance_policy(Path("config/phi-compliance-policy.yml"))

decision = guard_compliance(
    "member_id=MBR-SYN-8842",
    layer="model_input",
    phi_policy=phi_policy,
    compliance_policy=compliance_policy,
    context=ComplianceContext(
        phi_status="real_phi",
        vendor="google",
        service="vertex_ai",
        endpoint="generate_content",
        model="gemini-2.5-pro",
        feature="online_prediction",
        environment="production",
        logging="redacted_only",
        storage="none",
    ),
)

if decision.should_block:
    raise RuntimeError(decision.block_reasons)

text_for_model = decision.redacted_text
audit_payload = decision.to_dict()
```

## What It Checks

When the text contains PHI candidates, the guard checks:

- service profile exists for the vendor, service, and model
- `covered_service` is true when the PHI status requires BAA coverage
- `baa_executed` is true when the PHI status requires BAA coverage
- PHI status is explicitly allowed by the service profile
- model does not match denied patterns such as preview, beta, or experimental
- feature is allowed and not explicitly denied
- logging mode is allowed for PHI workflows
- storage mode is allowed for PHI workflows
- environment requirements such as production redacted logging are satisfied

If no PHI is detected, an unknown service profile is reported as a warning instead of a block. This lets general non-PHI traffic proceed while still surfacing missing routing metadata.

## Audit Safety

`ComplianceDecision.to_dict()` is safe for ordinary audit logs by default. It includes counts, categories, decision reasons, and redacted text, but not the raw input text or raw finding values.

Use `decision.to_dict(include_phi=True)` only in controlled debugging contexts where raw PHI handling is approved.

## Boundary

This guard is a policy enforcement tool, not a legal opinion. It cannot know contract status unless your organization supplies it through policy. Keep the compliance policy reviewed by security, legal, or platform owners, and update it when vendor contracts, covered services, models, or logging behavior changes.
